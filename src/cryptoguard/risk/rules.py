"""Rule-based assessment of a wallet's security state (ruleset ``cg-rules``).

Severity and confidence are separate axes. Severity describes how much the condition matters
if the evidence is right; confidence describes how strong the evidence is. No current rule
emits ``critical_evidence``: that is reserved for conditions backed by independent, verifiable
evidence of harm (e.g. a published incident), which CryptoGuard does not ingest yet.

A finding's fingerprint is ``keccak(rule_id | ruleset major | chain | wallet | subject)``, so
the same condition on the same subject is always the same finding, across runs and restarts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.core.hashing import keccak256
from cryptoguard.history.state import ApprovalState, WalletState
from cryptoguard.services.approvals import AllowanceLevel

RULESET_ID = "cg-rules"
RULESET_VERSION = "1.1.0"
RULESET_MAJOR = RULESET_VERSION.split(".")[0]


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    REVIEW_RECOMMENDED = "review_recommended"
    ELEVATED_RISK = "elevated_risk"
    CRITICAL_EVIDENCE = "critical_evidence"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    description: str


RULES: tuple[Rule, ...] = (
    Rule(
        "CG-APR-001",
        "permission_exposure",
        "Active unlimited or effectively unlimited ERC-20 allowance. Review recommended when the "
        "owner holds a balance of the token; informational when the balance is zero.",
    ),
    Rule(
        "CG-APR-002",
        "permission_exposure",
        "Active ERC-20 allowance to a spender with no contract code (heuristic: a pattern seen "
        "in approval phishing; medium confidence).",
    ),
    Rule(
        "CG-APR-003",
        "data_coverage",
        "An approval exists but its current allowance could not be verified (severity unknown).",
    ),
    Rule(
        "CG-DEL-001",
        "delegation",
        "The account has an active EIP-7702 delegation; the delegate's code governs it.",
    ),
    Rule(
        "CG-DEL-002",
        "delegation",
        "The EIP-7702 delegation target has no code, so code deployed there later would "
        "control the account.",
    ),
    Rule(
        "CG-COD-001",
        "data_integrity",
        "Account code starts with 0xef0100 but is not a valid 23-byte delegation indicator.",
    ),
    Rule(
        "CG-POI-001",
        "address_poisoning",
        "A lookalike of an address the wallet sent to appears in its transfer history together "
        "with poisoning context (zero-value transfer, spoofed outgoing transfer, or unsolicited "
        "incoming transfer).",
    ),
    Rule(
        "CG-POI-002",
        "address_poisoning",
        "A lookalike of an address the wallet sent to appears in its transfer history without "
        "other poisoning context (informational; low confidence).",
    ),
    Rule(
        "CG-POI-003",
        "address_poisoning",
        "The wallet itself sent tokens to a lookalike of an address it had used before "
        "(possible loss to address poisoning).",
    ),
)
_RULES = {rule.rule_id: rule for rule in RULES}


class EvidenceRef(BaseModel):
    kind: Literal["approval_state", "approval_event", "account_code", "transfer_event"]
    description: str
    block_number: int
    transaction_hash: str | None = None


class FindingCandidate(BaseModel):
    fingerprint: str
    rule_id: str
    ruleset_version: str
    category: str
    severity: Severity
    confidence: Confidence
    subject: str
    title: str
    explanation: str
    evidence: list[EvidenceRef]


@dataclass
class RuleEvaluation:
    candidates: list[FindingCandidate]
    # Subjects whose inputs were not verified at this block. Open findings about them must not
    # be resolved: absence of evidence is not evidence of absence.
    unverifiable_subjects: set[str] = field(default_factory=set)


def fingerprint(rule_id: str, chain_id: int, wallet: str, subject: str) -> str:
    material = f"{rule_id}|{RULESET_MAJOR}|{chain_id}|{wallet}|{subject}"
    return "0x" + keccak256(material.encode()).hex()


def make_candidate(
    rule_id: str,
    *,
    chain_id: int,
    wallet: str,
    subject: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    explanation: str,
    evidence: list[EvidenceRef],
) -> FindingCandidate:
    return FindingCandidate(
        fingerprint=fingerprint(rule_id, chain_id, wallet, subject),
        rule_id=rule_id,
        ruleset_version=RULESET_VERSION,
        category=_RULES[rule_id].category,
        severity=severity,
        confidence=confidence,
        subject=subject,
        title=title,
        explanation=explanation,
        evidence=evidence,
    )


def _approval_evidence(approval: ApprovalState, block: int) -> list[EvidenceRef]:
    event = approval.latest_event
    return [
        EvidenceRef(
            kind="approval_state",
            description=f"allowance({approval.token}, owner, {approval.spender}) = "
            f"{approval.allowance if approval.allowance is not None else 'unknown'}",
            block_number=block,
        ),
        EvidenceRef(
            kind="approval_event",
            description=f"Latest observed Approval event set {event.value}.",
            block_number=event.block_number,
            transaction_hash=event.transaction_hash,
        ),
    ]


def _evaluate_approval(
    approval: ApprovalState, chain_id: int, wallet: str, block: int, out: RuleEvaluation
) -> None:
    subject = approval.key
    symbol = approval.token_symbol or "token"
    label = f" ({approval.spender_label})" if approval.spender_label else ""
    if approval.verified_at_block != block:
        out.unverifiable_subjects.add(subject)
        return
    if approval.active is None:
        out.unverifiable_subjects.add(subject)
        if int(approval.latest_event.value) > 0:
            out.candidates.append(
                make_candidate(
                    "CG-APR-003",
                    chain_id=chain_id,
                    wallet=wallet,
                    subject=subject,
                    severity=Severity.UNKNOWN,
                    confidence=Confidence.LOW,
                    title=f"Unverifiable {symbol} allowance for {approval.spender}",
                    explanation="An Approval event granted "
                    f"{approval.latest_event.value} base units, "
                    f"but allowance() could not be read ({approval.unknown_reason}). The current "
                    "permission is unknown.",
                    evidence=_approval_evidence(approval, block),
                )
            )
        return
    if not approval.active:
        return
    if approval.level in (AllowanceLevel.UNLIMITED, AllowanceLevel.EFFECTIVELY_UNLIMITED):
        has_balance = approval.balance is not None and int(approval.balance) > 0
        out.candidates.append(
            make_candidate(
                "CG-APR-001",
                chain_id=chain_id,
                wallet=wallet,
                subject=subject,
                severity=Severity.REVIEW_RECOMMENDED if has_balance else Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                title=f"Unlimited {symbol} allowance for {approval.spender}{label}",
                explanation="The spender may transfer any amount of this token the wallet "
                "holds, now "
                "or in future. "
                + (
                    f"Visible exposure is the full balance ({approval.balance} base units)."
                    if has_balance
                    else "The wallet currently holds none, so nothing is exposed yet."
                )
                + " Unlimited approvals are common for DEXes; revoke ones you no longer use.",
                evidence=_approval_evidence(approval, block),
            )
        )
    if approval.spender_code_kind is CodeKind.NO_CODE:
        out.candidates.append(
            make_candidate(
                "CG-APR-002",
                chain_id=chain_id,
                wallet=wallet,
                subject=subject,
                severity=Severity.ELEVATED_RISK,
                confidence=Confidence.MEDIUM,
                title=f"Active {symbol} allowance to an address without code",
                explanation=f"{approval.spender} has no contract code but may move up to "
                f"{approval.allowance} base units. Dapps normally approve contracts; "
                "verify that you "
                "intended this approval. This is a heuristic, not proof of wrongdoing.",
                evidence=_approval_evidence(approval, block),
            )
        )


def evaluate(state: WalletState, *, chain_id: int, wallet: str, block: int) -> RuleEvaluation:
    out = RuleEvaluation(candidates=[])
    account = state.account
    code_evidence = [
        EvidenceRef(
            kind="account_code",
            description=f"eth_getCode(wallet) at block {block}: {account.code_kind.value}, "
            f"hash {account.code_hash}",
            block_number=block,
        )
    ]
    if account.code_kind is CodeKind.EIP7702_DELEGATION and account.target:
        subject = f"delegation:{account.target}"
        out.candidates.append(
            make_candidate(
                "CG-DEL-001",
                chain_id=chain_id,
                wallet=wallet,
                subject=subject,
                severity=Severity.REVIEW_RECOMMENDED,
                confidence=Confidence.HIGH,
                title=f"Account delegates to {account.target}",
                explanation="Calls to this account run the delegate contract's code with the "
                "account's assets and permissions. Confirm the delegate is a contract you chose.",
                evidence=code_evidence,
            )
        )
        if account.target_code_kind is CodeKind.NO_CODE:
            out.candidates.append(
                make_candidate(
                    "CG-DEL-002",
                    chain_id=chain_id,
                    wallet=wallet,
                    subject=subject,
                    severity=Severity.ELEVATED_RISK,
                    confidence=Confidence.MEDIUM,
                    title="Delegation target has no code",
                    explanation=f"{account.target} has no code at this block. Whoever can deploy "
                    "code there (for example via CREATE2) would control this account.",
                    evidence=code_evidence,
                )
            )
    elif account.code_kind is CodeKind.MALFORMED_DELEGATION_PREFIX:
        out.candidates.append(
            make_candidate(
                "CG-COD-001",
                chain_id=chain_id,
                wallet=wallet,
                subject="account",
                severity=Severity.UNKNOWN,
                confidence=Confidence.LOW,
                title="Malformed EIP-7702 indicator",
                explanation="Account code starts with 0xef0100 but has the wrong length. "
                "This should "
                "not occur on a correct chain; the provider's data deserves scrutiny.",
                evidence=code_evidence,
            )
        )
    for key in sorted(state.approvals):
        _evaluate_approval(state.approvals[key], chain_id, wallet, block, out)
    out.candidates.sort(key=lambda c: c.fingerprint)
    return out
