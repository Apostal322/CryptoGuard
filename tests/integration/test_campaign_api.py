"""Campaign analysis through the API: off by default, read-only, never changes findings."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cryptoguard.core.address import to_checksum_address
from tests.fakenode import FakeNode
from tests.integration.test_api import rpc_client_for

TOKEN = to_checksum_address("0x" + "f" * 39 + "1")
SIGNER = to_checksum_address("0x" + "5" * 40)
OTHER_SIGNER = to_checksum_address("0x" + "6" * 40)
W1 = to_checksum_address("0x" + "a1" * 20)
W2 = to_checksum_address("0x" + "a2" * 20)
W3 = to_checksum_address("0x" + "a3" * 20)
R1, L1 = (to_checksum_address("0xabcd" + c * 32 + "ef12") for c in "19")
R2, L2 = (to_checksum_address("0xbcde" + c * 32 + "fa21") for c in "28")
R3, L3 = (to_checksum_address("0xcdef" + c * 32 + "ab34") for c in "37")
SHADOW = {"campaign_analysis": "shadow"}


def make_node() -> FakeNode:
    node = FakeNode(head=1_100)
    node.add_token(TOKEN)
    for wallet, real in ((W1, R1), (W2, R2), (W3, R3)):
        node.set_account(wallet)
        node.send_native(wallet, real, 10**16, block=900)  # the real payment (reference)
    # The same key plants lookalikes on W1 and W2; W3 is targeted by an unrelated signer.
    node.add_transfer_log(TOKEN, W1, L1, 0, block=1_000, signer=SIGNER, log_index=1)
    node.add_transfer_log(TOKEN, W2, L2, 0, block=1_010, signer=SIGNER, log_index=2)
    node.add_transfer_log(TOKEN, W3, L3, 0, block=1_020, signer=OTHER_SIGNER, log_index=3)
    return node


def snapshots(client: TestClient) -> list[list[tuple[str, str]]]:
    out = []
    for wallet in (W1, W2, W3):
        r = client.post(f"/api/v1/wallets/{wallet}/snapshots", json={"lookback_blocks": 1_000})
        assert r.status_code == 200, r.text
        out.append(sorted((e["rule_id"], e["to_status"]) for e in r.json()["finding_events"]))
    return out


def test_disabled_by_default() -> None:
    with rpc_client_for(make_node()) as client:
        snapshots(client)
        for method, path in (
            ("post", "/api/v1/campaigns/runs"),
            ("get", "/api/v1/campaigns"),
            ("get", f"/api/v1/wallets/{W1}/related-activity"),
        ):
            r = getattr(client, method)(path)
            assert r.status_code == 409
            assert r.json()["error"]["code"] == "feature_disabled"


def test_shadow_run_links_wallets_through_a_shared_signer_only() -> None:
    with rpc_client_for(make_node(), **SHADOW) as client:
        snapshots(client)
        assert client.get("/api/v1/campaigns").json()["error"]["code"] == "no_campaign_run"
        run = client.post("/api/v1/campaigns/runs").json()
        assert run["attempts"] == 3
        assert run["clusters"] == 1
        assert run["unclustered"] == 1
        assert run["experimental"] is True
        again = client.post("/api/v1/campaigns/runs").json()
        assert again["created"] is False
        assert again["input_sha256"] == run["input_sha256"]

        page = client.get("/api/v1/campaigns").json()
        [summary] = page["items"]
        assert summary["targeted_wallets"] == 2
        assert summary["confidence"] == "strongly_supported"

        detail = client.get(f"/api/v1/campaigns/{summary['campaign_id']}").json()
        signer_ev = next(e for e in detail["evidence"] if e["kind"] == "signer")
        assert signer_ev["key"] == SIGNER
        assert signer_ev["merges"] is True
        assert signer_ev["statement"] == "These attempts share a verified planting signer."
        assert {m["victim"] for m in detail["members"]} == {W1, W2}

        graph = client.get(f"/api/v1/campaigns/{summary['campaign_id']}/graph").json()
        kinds = {e["kind"] for e in graph["edges"]}
        assert {"TARGETED_WALLET", "PLANTED_BY", "USED_LOOKALIKE"} <= kinds

        related = client.get(f"/api/v1/wallets/{W1}/related-activity").json()
        assert related["status"] == "related_activity"
        assert "1 other wallet" in related["statement"]
        alone = client.get(f"/api/v1/wallets/{W3}/related-activity").json()
        assert alone["status"] == "attempts_without_links"

        assert client.get("/api/v1/campaigns/cmp-" + "0" * 24).status_code == 404
        assert client.get("/api/v1/campaigns/not-an-id").status_code == 404


def test_shadow_mode_does_not_change_findings() -> None:
    with rpc_client_for(make_node()) as off:
        off_findings = snapshots(off)
    with rpc_client_for(make_node(), **SHADOW) as shadow:
        shadow_findings = snapshots(shadow)
        shadow.post("/api/v1/campaigns/runs")
        after = shadow.get(f"/api/v1/wallets/{W1}/findings").json()
    assert off_findings == shadow_findings
    assert any(rule == "CG-POI-001" for events in off_findings for rule, _ in events)
    assert all(f["rule_id"] != "campaign" for f in after["items"])


def test_purging_a_wallet_removes_runs_that_mention_it() -> None:
    with rpc_client_for(make_node(), **SHADOW) as client:
        snapshots(client)
        client.post("/api/v1/campaigns/runs")
        app_state = client.app.state.cryptoguard  # type: ignore[attr-defined]
        app_state.repository.purge(W1)
        assert client.get("/api/v1/campaigns").json()["error"]["code"] == "no_campaign_run"


def test_concurrent_runs_are_refused_not_stacked() -> None:
    from cryptoguard.api.campaign_routes import RUN_LOCK

    with rpc_client_for(make_node(), **SHADOW) as client:
        snapshots(client)
        assert RUN_LOCK.acquire(blocking=False)  # a run is in progress
        try:
            r = client.post("/api/v1/campaigns/runs")
        finally:
            RUN_LOCK.release()
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "campaign_run_in_progress"
        assert client.post("/api/v1/campaigns/runs").status_code == 200
