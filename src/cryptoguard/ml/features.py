"""Point-in-time transaction features (pure Python: shared by training and shadow scoring).

Inputs are one collected record (``collect.py``): the transaction, its receipt, the sender's
nonce and the target's code at the block *before* the transaction. Nothing later is used.

Deliberately excluded:

- ``block_number`` and timestamps: used to split data in time, never as features, so a model
  cannot learn when the dataset authors happened to collect each class;
- raw addresses, hashes and selectors as identifiers: only coarse, generalizable properties
  (code size, vanity zero runs, known function families, log structure) are encoded.
"""

from __future__ import annotations

import math
from itertools import combinations
from typing import Any

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
UNLIMITED = 2**255  # allowance at or above this is "effectively unlimited"

# Function families by 4-byte selector (public, well-known signatures).
SELECTORS = {
    "approve": {"0x095ea7b3", "0x39509351"},  # approve, increaseAllowance
    "permit": {"0xd505accf", "0x8fcbaf0c", "0x2b67b570", "0x2a2d80d1"},  # EIP-2612, DAI, Permit2
    "set_approval_for_all": {"0xa22cb465"},
    "transfer": {"0xa9059cbb"},
    "transfer_from": {"0x23b872dd", "0x42842e0e", "0xb88d4fde", "0xf242432a"},
    "multicall": {"0xac9650d8", "0x5ae401dc", "0x1f0464d1", "0x252dba42", "0x82ad56cb"},
    "seaport": {"0xfb0f3ee1", "0x87201b41", "0xe7acab24", "0xb3a34c4c", "0xed98a574"},
    "upgrade": {"0x3659cfe6", "0x4f1ef286"},  # upgradeTo, upgradeToAndCall
}

FEATURES: tuple[str, ...] = (
    "value_eth_log",
    "is_zero_value",
    "gas_limit_log",
    "gas_price_gwei_log",
    "is_typed_fee",
    "input_bytes_log",
    "input_is_bare_selector",
    *(f"fn_{name}" for name in SELECTORS),
    "fn_other",
    "is_contract_creation",
    "to_is_contract",
    "to_code_size_log",
    "to_is_delegated_eoa",
    "to_vanity_zero_nibbles",
    "from_vanity_zero_nibbles",
    "sender_prior_txs_log",
    "status_success",
    "gas_used_ratio",
    "n_logs",
    "n_log_emitters",
    "n_transfers",
    "n_zero_value_transfers",
    "n_transfers_not_from_sender",
    "n_transfers_from_sender",
    "n_transfers_to_sender",
    "n_transfer_recipients",
    "n_approvals",
    "n_unlimited_approvals",
    "n_approval_for_all_granted",
    "max_party_affix_match",
)


def _int(value: str | None) -> int:
    return int(value, 16) if value else 0


def _log1p(x: float) -> float:
    return math.log1p(max(x, 0.0))


def _topic_address(topic: str) -> str:
    return "0x" + topic[-40:].lower()


def _vanity_zeros(address: str | None) -> int:
    """Leading plus trailing zero nibbles, e.g. 0x0000553f…0000 -> 8 (vanity-mined)."""
    if not address:
        return 0
    body = address.lower()[2:]
    return (len(body) - len(body.lstrip("0"))) + (len(body) - len(body.rstrip("0")))


def affix_match(a: str, b: str) -> int:
    """Common leading plus trailing hex characters of two distinct addresses."""
    x, y = a.lower()[2:], b.lower()[2:]
    if x == y:
        return 0
    prefix = next((i for i, (p, q) in enumerate(zip(x, y, strict=True)) if p != q), len(x))
    suffix = next(
        (i for i, (p, q) in enumerate(zip(reversed(x), reversed(y), strict=True)) if p != q),
        len(x),
    )
    return prefix + suffix


def extract(record: dict[str, Any]) -> dict[str, float]:
    """Feature vector for one collected record (status "ok")."""
    tx = record["tx"]
    receipt = record.get("receipt") or {}
    sender = (tx.get("from") or "").lower()
    target = (tx.get("to") or "").lower() or None
    data = tx.get("input") or "0x"
    selector = data[:10].lower() if len(data) >= 10 else None
    value = _int(tx.get("value"))
    gas = _int(tx.get("gas"))
    fee = _int(tx.get("maxFeePerGas")) or _int(tx.get("gasPrice"))
    code = record.get("to_code_before") or {"size": 0, "prefix": "0x"}

    f: dict[str, float] = {
        "value_eth_log": _log1p(value / 1e18),
        "is_zero_value": float(value == 0),
        "gas_limit_log": _log1p(gas),
        "gas_price_gwei_log": _log1p(fee / 1e9),
        "is_typed_fee": float(tx.get("maxFeePerGas") is not None),
        "input_bytes_log": _log1p((len(data) - 2) / 2),
        "input_is_bare_selector": float(len(data) == 10),
    }
    family = next((name for name, sels in SELECTORS.items() if selector in sels), None)
    for name in SELECTORS:
        f[f"fn_{name}"] = float(family == name)
    f["fn_other"] = float(family is None and selector is not None)

    f["is_contract_creation"] = float(target is None)
    f["to_is_contract"] = float(code["size"] > 0 and not code["prefix"].startswith("0xef0100"))
    f["to_code_size_log"] = _log1p(code["size"])
    f["to_is_delegated_eoa"] = float(code["prefix"].startswith("0xef0100"))
    f["to_vanity_zero_nibbles"] = float(_vanity_zeros(target))
    f["from_vanity_zero_nibbles"] = float(_vanity_zeros(sender))
    f["sender_prior_txs_log"] = _log1p(_int(record.get("from_nonce_before")))

    f["status_success"] = float(_int(receipt.get("status")) == 1)
    f["gas_used_ratio"] = _int(receipt.get("gasUsed")) / gas if gas else 0.0
    logs = receipt.get("logs") or []
    f["n_logs"] = float(len(logs))
    f["n_log_emitters"] = float(len({log["address"].lower() for log in logs}))

    transfers = [lg for lg in logs if lg["topics"] and lg["topics"][0].lower() == TRANSFER]
    parties: set[str] = {sender} | ({target} if target else set())
    recipients: set[str] = set()
    zero = not_sender = from_sender = to_sender = 0
    for log in transfers:
        if len(log["topics"]) < 3:
            continue
        src, dst = _topic_address(log["topics"][1]), _topic_address(log["topics"][2])
        parties |= {src, dst}
        recipients.add(dst)
        amount = _int(log["data"]) if len(log["topics"]) == 3 and log["data"] != "0x" else None
        zero += amount == 0
        not_sender += src != sender
        from_sender += src == sender
        to_sender += dst == sender
    f["n_transfers"] = float(len(transfers))
    f["n_zero_value_transfers"] = float(zero)
    f["n_transfers_not_from_sender"] = float(not_sender)
    f["n_transfers_from_sender"] = float(from_sender)
    f["n_transfers_to_sender"] = float(to_sender)
    f["n_transfer_recipients"] = float(len(recipients))

    approvals = unlimited = for_all = 0
    for log in logs:
        topic0 = log["topics"][0].lower() if log["topics"] else ""
        if topic0 == APPROVAL:
            approvals += 1
            if len(log["topics"]) == 3 and log["data"] != "0x" and _int(log["data"]) >= UNLIMITED:
                unlimited += 1
            if len(log["topics"]) >= 3:
                parties.add(_topic_address(log["topics"][2]))
        elif topic0 == APPROVAL_FOR_ALL:
            for_all += _int(log["data"]) == 1
            if len(log["topics"]) >= 3:
                parties.add(_topic_address(log["topics"][2]))
    f["n_approvals"] = float(approvals)
    f["n_unlimited_approvals"] = float(unlimited)
    f["n_approval_for_all_granted"] = float(for_all)
    # Lookalike pairs among the parties of one transaction (bounded: logs can be long).
    pool = sorted(p for p in parties if p and p != "0x" + "0" * 40)[:40]
    f["max_party_affix_match"] = float(
        max((affix_match(a, b) for a, b in combinations(pool, 2)), default=0)
    )
    assert tuple(f) == FEATURES, "feature order drifted"
    return f


def parties(record: dict[str, Any]) -> set[str]:
    """Accounts a transaction ties together: sender, target, approved spenders and
    operators, transfer recipients. Used only to group rows for leakage-safe splits (an
    attacker's or a user's repeated addresses must not straddle train and test)."""
    tx = record["tx"]
    sender = (tx.get("from") or "").lower()
    out = {sender, (tx.get("to") or "").lower()}
    for log in (record.get("receipt") or {}).get("logs") or []:
        topics = log["topics"]
        if not topics or len(topics) < 3:
            continue
        if topics[0].lower() in (APPROVAL, APPROVAL_FOR_ALL) or topics[0].lower() == TRANSFER:
            out.add(_topic_address(topics[2]))
    return {a for a in out if a and a != "0x" + "0" * 40}
