"""Replay recorders under a hard request cap: every attempt is reserved first, a window that
hits the cap writes nothing, and the cap is required on every live replay command.

Mock transports only (no RPC).
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path

import httpx
import pytest

from cryptoguard import cli
from cryptoguard.blockchain import budget as budget_mod
from cryptoguard.blockchain.budget import (
    BudgetExhaustedError,
    RequestLedger,
    budgeted_transport,
    run_ledger,
)
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.replay.models import case_directory
from cryptoguard.replay.record import locate_transaction, record_fixture
from tests.fakenode import FakeNode
from tests.integration.test_replay import HARM, manifest
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, TOKEN, WALLET


class Counting(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.attempts = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        return await self.inner.handle_async_request(request)


async def _no_sleep(_: float) -> None:
    return None


def _provider(node: FakeNode, ledger: RequestLedger) -> tuple[RpcEthereumProvider, Counting]:
    counting = Counting(node.transport())
    client = JsonRpcClient(
        "https://rpc.example.invalid",
        retry=RetryPolicy(max_retries=3, base_delay=0.0, max_delay=0.0),
        transport=budgeted_transport(ledger, counting),
        sleep=_no_sleep,
        rng=random.Random(0),
    )
    provider = RpcEthereumProvider(
        client, expected_chain_id=1, endpoint_display="test", max_log_block_range=1000
    )
    return provider, counting


def _incident(node: FakeNode) -> str:
    node.add_token(TOKEN)
    node.head = 200
    node.send_native(WALLET, REAL, 10**16, block=100)
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=110, signer=ATTACKER_SIGNER)
    theft = node.add_transfer_log(TOKEN, WALLET, FAKE, 1000, block=HARM, signer=WALLET)
    node.send_native(WALLET, TOKEN, 0, block=HARM)
    return str(theft["transactionHash"])


async def test_recording_within_the_cap_counts_every_attempt(tmp_path: Path) -> None:
    node = FakeNode()
    _incident(node)
    ledger = RequestLedger(tmp_path / "ledger.json", cap=10_000)
    provider, counting = _provider(node, ledger)
    try:
        fixture = await record_fixture(provider, manifest(), chunk_blocks=50)
    finally:
        await provider.aclose()
    assert fixture.transfer_scan_complete
    assert counting.attempts > 0
    assert ledger.used() == counting.attempts == fixture.rpc_requests


async def test_recording_stops_at_the_cap_and_never_exceeds_it(tmp_path: Path) -> None:
    node = FakeNode()
    _incident(node)
    ledger = RequestLedger(tmp_path / "ledger.json", cap=5)
    provider, counting = _provider(node, ledger)
    try:
        with pytest.raises(BudgetExhaustedError):
            await record_fixture(provider, manifest(), chunk_blocks=50)
    finally:
        await provider.aclose()
    assert counting.attempts <= 5
    assert ledger.used() == counting.attempts == 5


def test_run_ledger_applies_the_per_run_and_total_caps(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    RequestLedger(path, cap=10).reserve(4)
    assert run_ledger(path, 10).cap == 10
    assert run_ledger(path, 10, per_run=3).cap == 7  # 4 used + 3 for this run
    assert run_ledger(path, 10, per_run=100).cap == 10  # never past the approval
    for bad in ({"cap": 0}, {"cap": 10, "per_run": 0}):
        with pytest.raises(ValueError, match="positive"):
            run_ledger(path, **bad)  # type: ignore[arg-type]


async def test_locate_reads_block_parties_and_transfers(tmp_path: Path) -> None:
    node = FakeNode()
    theft = _incident(node)
    ledger = RequestLedger(tmp_path / "ledger.json", cap=20)
    provider, counting = _provider(node, ledger)
    try:
        found = await locate_transaction(provider, theft)
        missing = await locate_transaction(provider, "0x" + "cd" * 32)
    finally:
        await provider.aclose()
    assert found["found"]
    assert found["block_number"] == HARM
    assert found["succeeded"]
    assert [(t["from"], t["to"], t["value_base_units"]) for t in found["transfers"]] == [
        (WALLET, FAKE, "1000")
    ]
    assert missing == {"transaction_hash": "0x" + "cd" * 32, "found": False}
    assert ledger.used() == counting.attempts


@pytest.mark.parametrize(
    "argv",
    [
        ["replay", "record", "usdt-50m-poisoning-2025-12-19", "--rpc-url", "https://x.invalid"],
        ["replay", "locate", "0x" + "ab" * 32, "--rpc-url", "https://x.invalid"],
        [
            "replay",
            "find-transfers",
            "--sender",
            "0x" + "ab" * 20,
            "--since",
            "2025-01-01",
            "--until",
            "2025-01-02",
            "--rpc-url",
            "https://x.invalid",
        ],
        ["replay", "record-background", "--rpc-url", "https://x.invalid"],
        [
            "replay",
            "sample-background",
            "--rpc-url",
            "https://x.invalid",
            "--seed",
            "1",
            "--from-block",
            "1",
            "--to-block",
            "2",
        ],
    ],
)
def test_live_replay_commands_require_a_ledger_and_cap(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_record_cli_fails_closed_at_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    case = "usdt-50m-poisoning-2025-12-19"
    fixture_path = case_directory(case) / "fixture.json"
    before = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
    node = FakeNode()
    monkeypatch.setattr(budget_mod.httpx, "AsyncHTTPTransport", node.transport)
    ledger = tmp_path / "ledger.json"
    argv = ["replay", "record", case, "--rpc-url", "https://rpc.example.invalid"]
    code = cli.main([*argv, "--ledger", str(ledger), "--cap", "1"])
    assert code == 2
    assert "not evaluable: budget" in capsys.readouterr().err
    assert hashlib.sha256(fixture_path.read_bytes()).hexdigest() == before  # nothing written
    assert RequestLedger(ledger, cap=1).used() == 1


def test_stage_1_dry_run_prepare_record_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pilot's whole chain on a mock node: prepare the manifest from a located receipt,
    record the window into a separate case folder under a cap, then verify it as Level I."""
    import json

    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.replay.models import load_cases

    harm_block, plant_block = 30_000, 29_000
    node = FakeNode()
    node.add_token(TOKEN)
    node.head = 31_000
    node.send_native(WALLET, REAL, 10**16, block=25_000)
    plant = node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=plant_block, signer=ATTACKER_SIGNER)
    theft = node.add_transfer_log(TOKEN, WALLET, FAKE, 1000, block=harm_block, signer=WALLET)
    monkeypatch.setattr(budget_mod.httpx, "AsyncHTTPTransport", node.transport)

    ledger = tmp_path / "ledger.json"
    url = ["--rpc-url", "https://rpc.example.invalid", "--ledger", str(ledger), "--cap", "3000"]
    hashes = [str(theft["transactionHash"]), str(plant["transactionHash"])]
    out = tmp_path / "located.json"
    assert cli.main(["replay", "locate", *hashes, "--out", str(out), *url]) == 0
    cand = ib.Candidate.model_validate(
        {
            "case_id": "dry-run",
            "source": {"publisher": "p", "url": "https://example.org", "date": "2026-08-09"},
            "chain_id": 1,
            "mechanism": "zero_value_transfer",
            "identifiers": {
                "victim": WALLET.lower(),
                "lookalike": FAKE.lower(),
                "intended": REAL.lower(),
                "planting_tx": hashes[1],
                "harm_tx": hashes[0],
            },
            "identifier_status": "verbatim",
            "fixture_case_id": None,
            "synthetic": True,
        }
    )
    m = ib.prepare(
        cand.model_copy(update={"synthetic": False}),
        json.loads(out.read_text(encoding="utf-8")),
        title="t",
        first_report="2026-11-03",
    )
    cases_dir = tmp_path / "cases"
    (cases_dir / "dry-run").mkdir(parents=True)
    (cases_dir / "dry-run" / "manifest.json").write_text(m.model_dump_json(indent=2))
    record = ["replay", "record", "dry-run", "--cases-dir", str(cases_dir), *url]
    assert cli.main([*record, "--max-requests", "2000"]) == 0
    [case] = load_cases(cases_dir)
    assert case.fixture is not None
    assert case.fixture.transfer_scan_complete
    assert (case.fixture.from_block, case.fixture.to_block) == (harm_block - 21_600, harm_block)
    assert RequestLedger(ledger, cap=3000).used() <= 3000
    monkeypatch.setattr(ib, "reference_sets", lambda _d: {})
    manifest_ = ib.CandidateManifest.model_validate(
        {
            "schema_version": "incident-candidates/1",
            "protocol": "p",
            "discovery": {},
            "candidates": [cand.model_copy(update={"synthetic": False}).model_dump()],
        }
    )
    [row] = ib.verify(manifest_, Path("unused"), cases=[], new_cases=[case])
    assert (row["level"], row["tier"], row["verified"]) == ("I", "A", True)
    assert row["onchain"]["planting"] == "confirmed in the window"


async def test_block_at_time_bisects_header_timestamps(tmp_path: Path) -> None:
    from cryptoguard.replay.record import block_at_time

    node = FakeNode()
    node.head = 5_000  # FakeNode: timestamp = 1_700_000_000 + 12 * block
    provider, counting = _provider(node, RequestLedger(tmp_path / "l.json", cap=100))
    try:
        ts = 1_700_000_000 + 12 * 1_234
        assert await block_at_time(provider, ts, after=True) == 1_234
        assert await block_at_time(provider, ts + 5, after=True) == 1_235
        assert await block_at_time(provider, ts + 5, after=False) == 1_234
    finally:
        await provider.aclose()
    assert counting.attempts <= 3 * (13 + 2)  # about log2(head) reads per call


def test_stage_2a_dry_run_find_resolve_prepare_record_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A near-miss case on a mock node: the frozen rule finds the harmful transfer from the
    two reported addresses, skips a counterfeit transfer the attacker signed "from" the
    victim, and the case then records and verifies as Level I like any other."""
    import json

    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.replay.models import load_cases

    node = FakeNode()
    node.add_token(TOKEN)
    node.head = 31_000
    node.send_native(WALLET, REAL, 10**16, block=25_000)
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=28_900, signer=ATTACKER_SIGNER)
    fake_from_victim = node.add_transfer_log(
        TOKEN, WALLET, FAKE, 115, block=29_000, signer=ATTACKER_SIGNER
    )
    theft = node.add_transfer_log(TOKEN, WALLET, FAKE, 1000, block=30_000, signer=WALLET)
    monkeypatch.setattr(budget_mod.httpx, "AsyncHTTPTransport", node.transport)
    rule = {
        "sender": "etherscan_filter_fadd",
        "recipient": "etherscan_filter_tadd",
        "prefixes": [],
        "token": None,
        "since": "2023-11-18",  # blocks 22,134.. (FakeNode clock)
        "until": "2023-11-19",
    }
    monkeypatch.setitem(ib.RESOLUTION_RULES, "dry-2a", rule)
    cand = ib.Candidate.model_validate(
        {
            "case_id": "dry-2a",
            "source": {"publisher": "p", "url": "https://example.org", "date": "2023-11-19"},
            "chain_id": 1,
            "mechanism": "unknown",
            "identifiers": {
                "etherscan_filter_fadd": WALLET.lower(),
                "etherscan_filter_tadd": FAKE.lower(),
            },
            "identifier_status": "partial: roles not stated",
            "fixture_case_id": None,
            "synthetic": False,
        }
    )
    ledger = tmp_path / "ledger.json"
    url = ["--rpc-url", "https://rpc.example.invalid", "--ledger", str(ledger), "--cap", "3000"]
    out = tmp_path / "found.json"
    find = ["replay", "find-transfers", "--sender", WALLET, "--recipient", FAKE]
    dates = ["--since", rule["since"], "--until", rule["until"], "--out", str(out)]
    assert cli.main([*find, *dates, *url, "--max-requests", "300"]) == 0
    found = json.loads(out.read_text(encoding="utf-8"))
    assert found["scan_complete"]
    assert [t["transaction_hash"] for t in found["transfers"]] == [
        str(fake_from_victim["transactionHash"]),  # nonzero, but signed by the attacker
        str(theft["transactionHash"]),
    ]
    done = ib.resolve(cand, found)
    assert done.identifiers["harm_tx"] == str(theft["transactionHash"])
    assert (done.identifiers["victim"], done.identifiers["lookalike"]) == (
        WALLET.lower(),
        FAKE.lower(),
    )
    m = ib.prepare(done, found, title="t", first_report="2026-11-03")
    assert m.harm.block_number == 30_000
    cases_dir = tmp_path / "cases"
    (cases_dir / "dry-2a").mkdir(parents=True)
    (cases_dir / "dry-2a" / "manifest.json").write_text(m.model_dump_json(indent=2))
    assert cli.main(["replay", "record", "dry-2a", "--cases-dir", str(cases_dir), *url]) == 0
    [case] = load_cases(cases_dir)
    monkeypatch.setattr(ib, "reference_sets", lambda _d: {})
    manifest_ = ib.CandidateManifest(
        schema_version="incident-candidates/1", protocol="p", discovery={}, candidates=[done]
    )
    [row] = ib.verify(manifest_, Path("unused"), cases=[], new_cases=[case])
    assert (row["level"], row["tier"], row["verified"]) == ("I", "A", True)
    assert row["onchain"]["planting"] == "not reported"
    assert RequestLedger(ledger, cap=3000).used() <= 3000
