from __future__ import annotations

from cryptoguard.blockchain.abi import UINT256_MAX
from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.detectors.poisoning import detect_poisoning
from cryptoguard.graph.build import OpenFinding, build_wallet_graph
from cryptoguard.history.state import WalletState
from tests.unit.test_history_logic import DELEGATED, NO_CODE, TARGET, approval
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, WALLET, addr, transfer

BLOCK = 200


def state(*approvals, account=NO_CODE) -> WalletState:  # type: ignore[no-untyped-def]
    return WalletState(
        approvals={a.key: a for a in approvals}, account=account, native_balance_wei="0"
    )


def graph(s: WalletState, transfers=(), findings=(), **kwargs):  # type: ignore[no-untyped-def]
    cases = detect_poisoning(WALLET, list(transfers), chain_id=1, wallet_is_plain_eoa=True)
    return build_wallet_graph(
        wallet=WALLET,
        chain_id=1,
        simulated=False,
        snapshot_id=1,
        snapshot_block=BLOCK,
        state=s,
        transfers=list(transfers),
        cases=cases,
        open_findings=list(findings),
        coverage="test",
        **kwargs,
    )


def edge_types(g) -> set[str]:  # type: ignore[no-untyped-def]
    return {e.type for e in g.edges}


def test_every_edge_has_a_source_and_evidence() -> None:
    poisoned = [
        transfer(WALLET, REAL, 100, 100, signer=WALLET),
        transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
    ]
    g = graph(state(approval(UINT256_MAX, balance=5), account=DELEGATED), poisoned)
    assert edge_types(g) == {
        "APPROVED_SPENDER",
        "HOLDS_TOKEN",
        "DELEGATES_TO",
        "TRANSFERRED_TO",
        "RESEMBLES",
    }
    ids = {n.id for n in g.nodes}
    for e in g.edges:
        assert e.source in ids
        assert e.target in ids
        assert e.evidence, e.type
        assert e.explanation
    assert g.nodes[0].id == WALLET  # the wallet is first


def test_only_similarity_is_heuristic() -> None:
    g = graph(
        state(),
        [
            transfer(WALLET, REAL, 100, 100, signer=WALLET),
            transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
        ],
    )
    classes = {e.type: e.evidence_class for e in g.edges}
    assert classes["RESEMBLES"] == "heuristic_signal"
    assert classes["TRANSFERRED_TO"] == "observed_fact"
    resembles = next(e for e in g.edges if e.type == "RESEMBLES")
    assert (resembles.source, resembles.target) == (FAKE, REAL)
    assert resembles.explanation.startswith("Inferred, not an observed interaction")


def test_transfer_edges_record_who_signed() -> None:
    g = graph(
        state(),
        [
            transfer(WALLET, REAL, 100, 100, signer=WALLET),
            transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
            transfer(FAKE, WALLET, 1, 111, signer=FAKE),
        ],
    )
    out_fake = next(e for e in g.edges if e.type == "TRANSFERRED_TO" and e.target == FAKE)
    assert out_fake.attributes["wallet_signed"] == 0
    assert out_fake.attributes["other_signed"] == 1
    assert out_fake.attributes["zero_value"] == 1
    assert out_fake.evidence[0].transaction_hash is not None
    incoming = next(e for e in g.edges if e.type == "RECEIVED_FROM")
    assert (incoming.source, incoming.target) == (FAKE, WALLET)


def test_inactive_and_stale_approvals_are_not_drawn_by_default() -> None:
    revoked = approval(0)
    stale = approval(UINT256_MAX, verified_at=150).model_copy(update={"spender": TARGET})
    assert edge_types(graph(state(revoked, stale))) == set()
    with_inactive = graph(state(revoked, stale), include_inactive=True)
    approvals = [e for e in with_inactive.edges if e.type == "APPROVED_SPENDER"]
    assert [e.target for e in approvals] == [revoked.spender]  # stale still excluded


def test_findings_annotate_nodes_not_edges() -> None:
    finding = OpenFinding(
        "0x01", "CG-POI-001", "elevated_risk", "high", "new", "Poisoning", f"poisoning:{FAKE}"
    )
    g = graph(
        state(),
        [
            transfer(WALLET, REAL, 100, 100, signer=WALLET),
            transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
        ],
        findings=[finding],
    )
    fake = next(n for n in g.nodes if n.id == FAKE)
    assert [f.rule_id for f in fake.findings] == ["CG-POI-001"]
    assert fake.kinds == ["counterparty"]


def test_size_limit_summarizes_low_priority_counterparties() -> None:
    noise = [
        transfer(addr(f"{i + 1:040x}"), WALLET, 1, 120 + i, signer=None, index=i)
        for i in range(100)
    ]
    poisoned = [
        transfer(WALLET, REAL, 100, 100, signer=WALLET),
        transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
    ]
    g = graph(state(), [*poisoned, *noise], max_nodes=20)
    assert len(g.nodes) <= 20
    ids = {n.id for n in g.nodes}
    assert {FAKE, REAL} <= ids  # poisoning participants always kept
    summary = next(n for n in g.nodes if n.kinds == ["summary"])
    assert summary.hidden_count == g.limits.hidden_counterparties
    assert g.limits.nodes_before_limit == 1 + 2 + 100
    assert any("summarized" in item for item in g.limitations)


def test_approval_budget_keeps_riskiest() -> None:
    many = [approval(5).model_copy(update={"spender": addr(f"{i + 1:040x}")}) for i in range(30)]
    risky = approval(UINT256_MAX).model_copy(update={"spender": addr("e" * 40)})
    g = graph(state(*many, risky), max_nodes=20)
    spenders = {e.target for e in g.edges if e.type == "APPROVED_SPENDER"}
    assert addr("e" * 40) in spenders
    assert len(spenders) == 10
    assert g.limits.hidden_approvals == 21


def test_graph_is_deterministic() -> None:
    transfers = [
        transfer(WALLET, REAL, 100, 100, signer=WALLET),
        transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
    ]
    s = state(approval(UINT256_MAX), account=DELEGATED)
    assert graph(s, transfers) == graph(s, list(reversed(transfers)))


def test_known_contracts_are_labelled() -> None:
    router = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    g = graph(state(approval(UINT256_MAX).model_copy(update={"spender": router})))
    node = next(n for n in g.nodes if n.id == router)
    assert (node.label, node.label_source) == ("Uniswap V2: Router 02", "known_contract")
    token = next(n for n in g.nodes if "token" in n.kinds)
    assert token.label_source == "token_symbol_untrusted"
    assert node.code_kind == CodeKind.CONTRACT
