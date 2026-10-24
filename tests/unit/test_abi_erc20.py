from __future__ import annotations

import pytest

from cryptoguard.blockchain.abi import (
    APPROVAL_TOPIC,
    SEL_ALLOWANCE,
    SEL_BALANCE_OF,
    SEL_DECIMALS,
    SEL_SYMBOL,
    address_topic,
    decode_address_word,
    decode_decimals,
    decode_symbol,
    decode_uint256,
    encode_call,
)
from cryptoguard.blockchain.erc20 import ApprovalLogShape, classify_approval_log
from cryptoguard.blockchain.rpc import classify_rpc_error
from cryptoguard.core.errors import (
    ContractCallFailedError,
    LogQueryTooLargeError,
    RpcRateLimitedError,
)
from tests.fakenode import FakeNode, abi_string

OWNER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
SPENDER = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"


def test_well_known_selectors_and_topic() -> None:
    assert SEL_ALLOWANCE.hex() == "dd62ed3e"
    assert SEL_BALANCE_OF.hex() == "70a08231"
    assert SEL_DECIMALS.hex() == "313ce567"
    assert SEL_SYMBOL.hex() == "95d89b41"
    assert APPROVAL_TOPIC == "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"


def test_call_encoding() -> None:
    data = encode_call(SEL_ALLOWANCE, OWNER, SPENDER)
    assert len(data) == 4 + 64
    assert decode_address_word(data[4:36]) == OWNER
    assert decode_address_word(data[36:68]) == SPENDER
    assert address_topic(OWNER) == "0x" + "00" * 12 + OWNER[2:].lower()


def test_address_word_with_dirty_high_bytes_rejected() -> None:
    with pytest.raises(ValueError, match="address"):
        decode_address_word(b"\x01" + bytes(11) + bytes(20))


def test_uint_and_decimals_decoding_is_strict() -> None:
    assert decode_uint256((5).to_bytes(32, "big")) == 5
    for bad in (b"", bytes(31), bytes(64)):
        with pytest.raises(ValueError, match="32 bytes"):
            decode_uint256(bad)
    assert decode_decimals((6).to_bytes(32, "big")) == 6
    with pytest.raises(ValueError, match="implausible"):
        decode_decimals((200).to_bytes(32, "big"))


def test_symbol_decoding() -> None:
    assert decode_symbol(abi_string(b"USDC")) == "USDC"
    assert decode_symbol(b"MKR".ljust(32, b"\0")) == "MKR"  # legacy bytes32
    assert decode_symbol(abi_string(b"<script>alert(1)</script>")) == "scriptalert(1)/script"
    assert decode_symbol(abi_string(b"A" * 100)) == "A" * 32
    with pytest.raises(ValueError, match="symbol"):
        decode_symbol((32).to_bytes(32, "big") + (10**6).to_bytes(32, "big"))
    with pytest.raises(ValueError, match="symbol"):
        decode_symbol(b"\x01\x02")


def _log(node: FakeNode, **kwargs: object) -> dict[str, object]:
    return node.add_approval_log(TOKEN, OWNER, SPENDER, 100, block=10, **kwargs)  # type: ignore[arg-type]


def test_erc20_log_decoded() -> None:
    shape, event = classify_approval_log(_log(FakeNode(), log_index=7))
    assert shape is ApprovalLogShape.ERC20
    assert event is not None
    assert (event.token, event.owner, event.spender, event.value) == (TOKEN, OWNER, SPENDER, 100)
    assert (event.block_number, event.log_index) == (10, 7)


def test_erc721_shaped_log_is_not_an_allowance() -> None:
    shape, event = classify_approval_log(_log(FakeNode(), nft_token_id=42))
    assert shape is ApprovalLogShape.ERC721_SHAPED
    assert event is None


def test_removed_log_skipped() -> None:
    assert classify_approval_log(_log(FakeNode(), removed=True))[0] is ApprovalLogShape.REMOVED


@pytest.mark.parametrize(
    "mutate",
    [
        lambda log: log["topics"].pop(),  # 2 topics
        lambda log: log.update(data="0x" + "00" * 64),  # 64-byte data with 3 topics
        lambda log: log["topics"].__setitem__(1, "0x" + "ff" * 32),  # not an address
        lambda log: log["topics"].__setitem__(0, "0x" + "11" * 32),  # different event
        lambda log: log.pop("blockHash"),
        lambda log: log.update(address="0x1234"),
        lambda log: log.update(topics="nope"),
    ],
)
def test_malformed_logs_are_rejected(mutate) -> None:  # type: ignore[no-untyped-def]
    log = _log(FakeNode())
    mutate(log)
    assert classify_approval_log(log) == (ApprovalLogShape.MALFORMED, None)


def test_free_plan_range_limit_is_a_split_signal_not_unsupported() -> None:
    # Regression: drpc's wording contains "not supported" but means "range too large".
    err = {"code": 35, "message": "ranges over 10000 blocks are not supported on free plan"}
    assert isinstance(classify_rpc_error("eth_getLogs", err), LogQueryTooLargeError)


def test_log_query_errors_are_distinguished_from_rate_limits() -> None:
    too_many = {"code": -32005, "message": "query returned more than 10000 results"}
    assert isinstance(classify_rpc_error("eth_getLogs", too_many), LogQueryTooLargeError)
    assert isinstance(classify_rpc_error("eth_call", too_many), RpcRateLimitedError)
    assert isinstance(
        classify_rpc_error(
            "eth_getLogs", {"code": -32000, "message": "exceed maximum block range"}
        ),
        LogQueryTooLargeError,
    )
    assert isinstance(
        classify_rpc_error("eth_call", {"code": 3, "message": "execution reverted"}),
        ContractCallFailedError,
    )
