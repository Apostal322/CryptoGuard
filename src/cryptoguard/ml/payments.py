"""Offline verification of a suspected victim payment from recorded transaction data.

A Transfer log alone proves nothing: any contract can emit one (fake tokens), and the
genuine token emits one for a spoofed ``transferFrom(victim, x, 0)``. A victim-signed
transaction alone proves nothing about a specific log either. The verifier therefore combines
the transaction, its receipt and its logs, and returns ``unresolved`` whenever the recorded
evidence does not support a confirmed asset movement. It makes no RPC calls.

Attribution is kept apart from movement: the result records where value went and whether
that address imitates another one, but never claims who controls it.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from cryptoguard.blockchain.abi import TRANSFER_TOPIC

TRANSFER_SELECTOR = "0xa9059cbb"
TRANSFER_FROM_SELECTOR = "0x23b872dd"

# Reviewed token contracts whose Transfer logs reflect real balance changes (mainnet).
TRUSTED_TOKENS: dict[str, str] = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
}

Status = Literal["confirmed_direct_payment", "not_a_payment", "reverted", "unresolved"]
Evidence = Literal[
    "native_transfer",
    "trusted_token_transfer_call",
    "matching_trusted_log",
    "receipt_success",
    "receipt_reverted",
    "receipt_missing",
    "untrusted_token",
    "signer_is_not_victim",
    "spender_mediated_transfer_from",
    "log_without_matching_call",
    "calldata_not_a_direct_transfer",
    "zero_amount",
    "destination_mismatch",
]


class PaymentVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Status
    evidence: tuple[Evidence, ...]
    tx_hash: str | None
    observed_destination: str | None
    asset: str | None  # "ETH", a trusted symbol, or a token address
    amount: int | None
    # Attribution, kept separate from movement:
    destination_is_candidate: bool
    ownership_claim: None = None  # never asserted from on-chain data alone


def _addr_topic(topic: str) -> str:
    return "0x" + topic.lower()[-40:]


def _receipt_status(receipt: dict[str, Any] | None) -> bool | None:
    if not receipt:
        return None
    status = receipt.get("status")
    return True if status == "0x1" else False if status == "0x0" else None


def _result(
    status: Status,
    evidence: list[Evidence],
    tx: dict[str, Any] | None,
    destination: str | None,
    asset: str | None,
    amount: int | None,
    candidate: str,
) -> PaymentVerification:
    return PaymentVerification(
        status=status,
        evidence=tuple(evidence),
        tx_hash=(tx or {}).get("hash"),
        observed_destination=destination,
        asset=asset,
        amount=amount,
        destination_is_candidate=destination is not None and destination == candidate,
    )


def verify_payment(
    *,
    victim: str,
    candidate: str,
    tx: dict[str, Any],
    receipt: dict[str, Any] | None,
    trusted_tokens: dict[str, str] | None = None,
) -> PaymentVerification:
    """Did ``victim`` move value to ``candidate`` in ``tx``? Evidence-based, fail-safe."""
    trusted = {k.lower(): v for k, v in (trusted_tokens or TRUSTED_TOKENS).items()}
    victim, candidate = victim.lower(), candidate.lower()
    signer = str(tx.get("from", "")).lower()
    to = str(tx.get("to") or "").lower() or None
    raw_value = str(tx.get("value") or "0")
    value = int(raw_value, 16) if raw_value.startswith("0x") else int(raw_value)
    data = str(tx.get("input", "0x")).lower()
    ok = _receipt_status(receipt)
    ev: list[Evidence] = []

    if signer != victim:
        # A genuine movement out of the victim can still happen through an approved spender
        # (transferFrom); proving it needs approval history, which this record lacks.
        logs = [
            lg
            for lg in (receipt or {}).get("logs", [])
            if lg.get("topics")
            and lg["topics"][0].lower() == TRANSFER_TOPIC
            and len(lg["topics"]) == 3
            and _addr_topic(lg["topics"][1]) == victim
            and _addr_topic(lg["topics"][2]) == candidate
        ]
        ev.append("signer_is_not_victim")
        if logs and any(lg.get("address", "").lower() in trusted for lg in logs):
            ev.append("spender_mediated_transfer_from")
        return _result(
            "unresolved" if logs else "not_a_payment", ev, tx, None, None, None, candidate
        )

    if ok is None:
        ev.append("receipt_missing")
        return _result("unresolved", ev, tx, to, None, None, candidate)
    if ok is False:
        ev.append("receipt_reverted")
        return _result("reverted", ev, tx, to, None, None, candidate)
    ev.append("receipt_success")

    if value > 0 and data in ("0x", ""):
        ev.append("native_transfer")
        if to != candidate:
            ev.append("destination_mismatch")
            return _result("not_a_payment", ev, tx, to, "ETH", value, candidate)
        return _result("confirmed_direct_payment", ev, tx, to, "ETH", value, candidate)

    if data.startswith(TRANSFER_SELECTOR) and len(data) >= 138:
        recipient = "0x" + data[34:74]
        amount = int(data[74:138], 16)
        if to not in trusted:
            ev.append("untrusted_token")
            return _result("unresolved", ev, tx, recipient, to, amount, candidate)
        ev.append("trusted_token_transfer_call")
        if amount == 0:
            ev.append("zero_amount")
            return _result("not_a_payment", ev, tx, recipient, trusted[to or ""], 0, candidate)
        matching = [
            lg
            for lg in (receipt or {}).get("logs", [])
            if str(lg.get("address", "")).lower() == to
            and lg.get("topics")
            and lg["topics"][0].lower() == TRANSFER_TOPIC
            and len(lg["topics"]) == 3
            and _addr_topic(lg["topics"][1]) == victim
            and _addr_topic(lg["topics"][2]) == recipient
            and int(str(lg.get("data", "0x0")), 16) == amount
        ]
        if not matching:
            ev.append("log_without_matching_call")
            return _result("unresolved", ev, tx, recipient, trusted[to or ""], amount, candidate)
        ev.append("matching_trusted_log")
        if recipient != candidate:
            ev.append("destination_mismatch")
            return _result("not_a_payment", ev, tx, recipient, trusted[to or ""], amount, candidate)
        return _result(
            "confirmed_direct_payment", ev, tx, recipient, trusted[to or ""], amount, candidate
        )

    # Router, multicall, contract-wallet or other calls: value may move, but not provably here.
    ev.append("calldata_not_a_direct_transfer")
    return _result("unresolved", ev, tx, to, None, None, candidate)
