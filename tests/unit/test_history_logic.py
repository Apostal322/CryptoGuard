from __future__ import annotations

from cryptoguard.blockchain.abi import UINT256_MAX
from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.core.chains import get_chain
from cryptoguard.core.hashing import EMPTY_CODE_HASH
from cryptoguard.history.delta import ChangeKind, compute_delta
from cryptoguard.history.state import (
    ApprovalState,
    DelegationState,
    EventRef,
    WalletState,
    pair_key,
    state_hash,
)
from cryptoguard.risk.lifecycle import (
    FindingStatus,
    KnownFinding,
    acknowledge,
    reconcile,
)
from cryptoguard.risk.rules import (
    RULESET_VERSION,
    Confidence,
    RuleEvaluation,
    Severity,
    evaluate,
    fingerprint,
)
from cryptoguard.services.approvals import AllowanceLevel

MAINNET = get_chain(1)
WALLET = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
SPENDER = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
TARGET = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
TX = "0x" + "ab" * 32

NO_CODE = DelegationState(
    code_kind=CodeKind.NO_CODE, code_hash=EMPTY_CODE_HASH, target=None, target_code_kind=None
)
DELEGATED = DelegationState(
    code_kind=CodeKind.EIP7702_DELEGATION,
    code_hash="0x" + "11" * 32,
    target=TARGET,
    target_code_kind=CodeKind.CONTRACT,
)


def level(value: int | None) -> AllowanceLevel:
    if value is None:
        return AllowanceLevel.UNKNOWN
    if value == 0:
        return AllowanceLevel.NONE
    return AllowanceLevel.UNLIMITED if value == UINT256_MAX else AllowanceLevel.LIMITED


def approval(
    allowance: int | None,
    *,
    event_value: int | None = None,
    event_block: int = 100,
    verified_at: int = 200,
    balance: int | None = 10,
    spender_kind: CodeKind = CodeKind.CONTRACT,
) -> ApprovalState:
    return ApprovalState(
        token=TOKEN,
        spender=SPENDER,
        token_symbol="TKN",
        token_decimals=18,
        allowance=None if allowance is None else str(allowance),
        allowance_status="unknown" if allowance is None else "known",
        unknown_reason="call_reverted" if allowance is None else None,
        level=level(allowance),
        balance=None if balance is None else str(balance),
        exposure=None,
        spender_code_kind=spender_kind,
        spender_label=None,
        latest_event=EventRef(
            value=str(event_value if event_value is not None else (allowance or 0)),
            block_number=event_block,
            block_hash="0x" + "cd" * 32,
            transaction_hash=TX,
            transaction_index=0,
            log_index=1,
        ),
        verified_at_block=verified_at,
    )


def state(*approvals: ApprovalState, account: DelegationState = NO_CODE) -> WalletState:
    return WalletState(
        approvals={a.key: a for a in approvals}, account=account, native_balance_wei="0"
    )


def delta(before: WalletState, after: WalletState, frm: int = 100, to: int = 200):  # type: ignore[no-untyped-def]
    return compute_delta(before, after, from_block=frm, to_block=to, chain=MAINNET, simulated=False)


# -- delta -----------------------------------------------------------------------------------


def test_granted_with_matching_event_has_transaction_cause() -> None:
    [change] = delta(state(), state(approval(500, event_block=150)))
    assert change.kind is ChangeKind.ALLOWANCE_GRANTED
    assert (change.before, change.after) == (None, "500")
    assert change.cause.kind == "approval_event"
    assert change.cause.transaction_hash == TX
    assert change.cause.explorer_url == f"https://etherscan.io/tx/{TX}"
    assert (change.from_block_exclusive, change.to_block) == (100, 200)


def test_reduction_without_event_never_invents_a_transaction() -> None:
    before = state(approval(500, event_block=50, verified_at=100))
    after = state(approval(300, event_value=500, event_block=50))
    [change] = delta(before, after)
    assert change.kind is ChangeKind.ALLOWANCE_REDUCED
    assert change.cause.kind == "state_comparison"
    assert change.cause.transaction_hash is None
    assert "transferFrom" in change.cause.note


def test_event_in_interval_that_does_not_explain_value_is_not_the_cause() -> None:
    before = state(approval(0, verified_at=100))
    after = state(approval(40, event_value=100, event_block=150))  # approved 100, 60 spent
    [change] = delta(before, after)
    assert change.kind is ChangeKind.ALLOWANCE_GRANTED
    assert change.cause.kind == "state_comparison"
    assert "differs" in change.cause.note


def test_allowance_transitions() -> None:
    assert [c.kind for c in delta(state(approval(5, verified_at=100)), state(approval(9)))] == [
        ChangeKind.ALLOWANCE_INCREASED
    ]
    assert [c.kind for c in delta(state(approval(5, verified_at=100)), state(approval(0)))] == [
        ChangeKind.ALLOWANCE_REVOKED
    ]
    assert [c.kind for c in delta(state(approval(5, verified_at=100)), state(approval(None)))] == [
        ChangeKind.ALLOWANCE_BECAME_UNKNOWN
    ]
    assert [c.kind for c in delta(state(approval(None, verified_at=100)), state(approval(5)))] == [
        ChangeKind.ALLOWANCE_BECAME_KNOWN
    ]
    assert delta(state(approval(5, verified_at=100)), state(approval(5))) == []
    assert delta(state(), state(approval(0))) == []  # granted and fully used in between


def test_carried_forward_pair_claims_no_change() -> None:
    before = state(approval(5, verified_at=100))
    after = state(approval(5, verified_at=100))  # not re-verified at block 200
    assert delta(before, after) == []


def test_delegation_transitions_have_state_comparison_cause() -> None:
    [set_] = delta(state(), state(account=DELEGATED))
    assert set_.kind is ChangeKind.DELEGATION_SET
    assert set_.cause.transaction_hash is None
    other = DELEGATED.model_copy(update={"target": SPENDER, "code_hash": "0x" + "22" * 32})
    assert [c.kind for c in delta(state(account=DELEGATED), state(account=other))] == [
        ChangeKind.DELEGATION_CHANGED
    ]
    assert [c.kind for c in delta(state(account=DELEGATED), state())] == [
        ChangeKind.DELEGATION_CLEARED
    ]


def test_delta_order_is_deterministic() -> None:
    other = approval(7).model_copy(update={"spender": TARGET})
    after = state(other, approval(9), account=DELEGATED)
    first = delta(state(), after)
    second = delta(state(), state(approval(9), other, account=DELEGATED))
    assert first == second
    assert [c.subject for c in first] == sorted(c.subject for c in first)


def test_state_hash_ignores_insertion_order() -> None:
    a, b = approval(1), approval(2).model_copy(update={"spender": TARGET})
    assert state_hash(state(a, b)) == state_hash(state(b, a))
    assert state_hash(state(a)) != state_hash(state(b))


# -- rules -----------------------------------------------------------------------------------


def evaluated(s: WalletState):  # type: ignore[no-untyped-def]
    return evaluate(s, chain_id=1, wallet=WALLET, block=200)


def test_unlimited_severity_depends_on_balance() -> None:
    [with_balance] = evaluated(state(approval(UINT256_MAX, balance=5))).candidates
    assert (with_balance.rule_id, with_balance.severity) == (
        "CG-APR-001",
        Severity.REVIEW_RECOMMENDED,
    )
    assert with_balance.confidence is Confidence.HIGH
    [empty] = evaluated(state(approval(UINT256_MAX, balance=0))).candidates
    assert empty.severity is Severity.INFORMATIONAL
    assert empty.fingerprint == with_balance.fingerprint  # same condition, same finding


def test_codeless_spender_is_a_medium_confidence_heuristic() -> None:
    [finding] = evaluated(state(approval(5, spender_kind=CodeKind.NO_CODE))).candidates
    assert (finding.rule_id, finding.severity) == ("CG-APR-002", Severity.ELEVATED_RISK)
    assert finding.confidence is Confidence.MEDIUM
    assert "not proof" in finding.explanation


def test_unknown_allowance_is_unknown_severity_and_unverifiable() -> None:
    result = evaluated(state(approval(None, event_value=5)))
    [finding] = result.candidates
    assert (finding.rule_id, finding.severity) == ("CG-APR-003", Severity.UNKNOWN)
    assert result.unverifiable_subjects == {pair_key(TOKEN, SPENDER)}


def test_stale_pair_is_unverifiable_and_raises_nothing() -> None:
    result = evaluated(state(approval(UINT256_MAX, verified_at=100)))
    assert result.candidates == []
    assert result.unverifiable_subjects == {pair_key(TOKEN, SPENDER)}


def test_delegation_rules() -> None:
    ids = {c.rule_id for c in evaluated(state(account=DELEGATED)).candidates}
    assert ids == {"CG-DEL-001"}
    codeless = DELEGATED.model_copy(update={"target_code_kind": CodeKind.NO_CODE})
    assert {c.rule_id for c in evaluated(state(account=codeless)).candidates} == {
        "CG-DEL-001",
        "CG-DEL-002",
    }
    malformed = NO_CODE.model_copy(update={"code_kind": CodeKind.MALFORMED_DELEGATION_PREFIX})
    assert [c.rule_id for c in evaluated(state(account=malformed)).candidates] == ["CG-COD-001"]


def test_limited_contract_approval_raises_nothing_and_nothing_is_critical() -> None:
    assert evaluated(state(approval(5))).candidates == []
    every = evaluated(
        state(approval(UINT256_MAX, spender_kind=CodeKind.NO_CODE), account=DELEGATED)
    )
    assert all(c.severity is not Severity.CRITICAL_EVIDENCE for c in every.candidates)


def test_fingerprints_are_stable_and_subject_specific() -> None:
    a = fingerprint("CG-APR-001", 1, WALLET, "x")
    assert a == fingerprint("CG-APR-001", 1, WALLET, "x")
    assert a != fingerprint("CG-APR-001", 1, WALLET, "y")
    assert a != fingerprint("CG-APR-001", 11155111, WALLET, "x")


# -- lifecycle -------------------------------------------------------------------------------


def known(
    fp: str, status: FindingStatus, subject: str, version: str = RULESET_VERSION
) -> dict[str, KnownFinding]:
    return {fp: KnownFinding(fp, status, version, subject)}


def test_new_then_active_then_resolved() -> None:
    present = evaluated(state(approval(UINT256_MAX)))
    fp = present.candidates[0].fingerprint
    subject = present.candidates[0].subject
    [first] = reconcile({}, present).transitions
    assert (first.from_status, first.to_status) == (None, FindingStatus.NEW)
    [second] = reconcile(known(fp, FindingStatus.NEW, subject), present).transitions
    assert second.to_status is FindingStatus.ACTIVE
    assert reconcile(known(fp, FindingStatus.ACTIVE, subject), present).transitions == []
    gone = evaluated(state(approval(0)))
    [third] = reconcile(known(fp, FindingStatus.ACTIVE, subject), gone).transitions
    assert third.to_status is FindingStatus.RESOLVED


def test_reopen_acknowledged_and_unverifiable() -> None:
    present = evaluated(state(approval(UINT256_MAX)))
    fp, subject = present.candidates[0].fingerprint, present.candidates[0].subject
    [reopen] = reconcile(known(fp, FindingStatus.RESOLVED, subject), present).transitions
    assert (reopen.from_status, reopen.to_status) == (FindingStatus.RESOLVED, FindingStatus.NEW)
    assert reconcile(known(fp, FindingStatus.ACKNOWLEDGED, subject), present).transitions == []

    unknown_now = evaluated(state(approval(None, event_value=0)))
    result = reconcile(known(fp, FindingStatus.ACTIVE, subject), unknown_now)
    assert result.transitions == []  # not resolved on missing evidence
    assert result.not_reverified == [fp]


def test_escalation_within_a_rule_group_supersedes_instead_of_resolving() -> None:
    # Regression (found in the live WBTC check): CG-POI-001 escalating to CG-POI-003 for the
    # same lookalike must not read as "resolved".
    from cryptoguard.risk.rules import EvidenceRef, make_candidate

    subject = "poisoning:0x" + "ab" * 20
    escalated = make_candidate(
        "CG-POI-003",
        chain_id=1,
        wallet=WALLET,
        subject=subject,
        severity=Severity.CRITICAL_EVIDENCE,
        confidence=Confidence.MEDIUM,
        title="t",
        explanation="e",
        evidence=[EvidenceRef(kind="transfer_event", description="d", block_number=1)],
    )
    evaluation = RuleEvaluation(candidates=[escalated])
    old = KnownFinding("0x01", FindingStatus.ACTIVE, RULESET_VERSION, subject, "CG-POI-001")
    [new, superseded] = sorted(
        reconcile({"0x01": old}, evaluation).transitions,
        key=lambda t: t.fingerprint != escalated.fingerprint,
    )
    assert new.to_status is FindingStatus.NEW
    assert superseded.to_status is FindingStatus.SUPERSEDED
    assert "CG-POI-003" in superseded.reason


def test_coexisting_rules_on_one_subject_still_resolve() -> None:
    # CG-APR-001 and CG-APR-002 can both hold for one pair; one ending is a real resolution.
    present = evaluated(state(approval(UINT256_MAX, spender_kind=CodeKind.NO_CODE)))
    by_rule = {c.rule_id: c for c in present.candidates}
    only_unlimited = evaluated(state(approval(UINT256_MAX)))
    codeless = by_rule["CG-APR-002"]
    known_002 = {
        codeless.fingerprint: KnownFinding(
            codeless.fingerprint,
            FindingStatus.ACTIVE,
            RULESET_VERSION,
            codeless.subject,
            "CG-APR-002",
        )
    }
    [transition] = reconcile(known_002, only_unlimited).transitions[-1:]
    assert transition.to_status is FindingStatus.RESOLVED


def test_old_ruleset_major_is_superseded() -> None:
    result = reconcile(
        known("0x01", FindingStatus.ACTIVE, "s", version="0.9.0"), evaluated(state())
    )
    [transition] = result.transitions
    assert transition.to_status is FindingStatus.SUPERSEDED


def test_acknowledge_rules() -> None:
    assert acknowledge(FindingStatus.NEW) is FindingStatus.ACKNOWLEDGED
    assert acknowledge(FindingStatus.ACTIVE) is FindingStatus.ACKNOWLEDGED
    for status in (FindingStatus.RESOLVED, FindingStatus.ACKNOWLEDGED, FindingStatus.SUPERSEDED):
        try:
            acknowledge(status)
        except ValueError:
            continue
        raise AssertionError(f"{status} should not be acknowledgeable")
