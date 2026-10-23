from __future__ import annotations

import pytest

from cryptoguard.blockchain.abi import (
    APPROVAL_TOPIC,
    SEL_ALLOWANCE,
    SEL_DECIMALS,
    UINT256_MAX,
    address_topic,
)
from cryptoguard.blockchain.eip7702 import DELEGATION_PREFIX, CodeKind
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.chains import get_chain
from cryptoguard.core.errors import (
    BlockRangeTooLargeError,
    InvalidScanRequestError,
    LogFilterRestrictedError,
    ReorgDetectedError,
    ScanBudgetExceededError,
)
from cryptoguard.services.approvals import (
    AllowanceLevel,
    ApprovalEntry,
    ScanLimits,
    scan_approvals,
)
from cryptoguard.services.demo import DEMO_ACCOUNTS, DemoProvider
from tests.fakenode import FakeNode, FakeToken

MAINNET = get_chain(1)
OWNER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
OTHER_OWNER = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
TOKEN2 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
EOA_SPENDER = "0x1111111111111111111111111111111111111111"
UNIT = 10**18

LIMITS = ScanLimits(
    lookback_blocks=10_000,
    max_scan_blocks=100_000,
    chunk_blocks=1000,
    max_log_requests=100,
    max_pairs=50,
)


def limits(**overrides: int) -> ScanLimits:
    values = {**LIMITS.__dict__, **overrides}
    return ScanLimits(**values)


def entry(entries: list[ApprovalEntry], token: str, spender: str) -> ApprovalEntry:
    return next(e for e in entries if e.token.address == token and e.spender.address == spender)


@pytest.fixture
def token(node: FakeNode) -> FakeToken:
    fake = node.add_token(TOKEN)
    fake.balances[OWNER] = 1_000 * UNIT
    node.set_account(PERMIT2, code=b"\x60\x80")
    node.set_account(ROUTER, code=b"\x60\x80")
    return fake


async def test_discovery_and_current_state(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    head = node.head
    node.add_approval_log(TOKEN, OWNER, PERMIT2, UINT256_MAX, block=head - 50, log_index=1)
    node.add_approval_log(TOKEN, OWNER, ROUTER, 300 * UNIT, block=head - 40)
    node.add_approval_log(TOKEN, OTHER_OWNER, ROUTER, 5, block=head - 30)  # other owner
    token.allowances[(OWNER, PERMIT2)] = UINT256_MAX
    token.allowances[(OWNER, ROUTER)] = 300 * UNIT

    scan = await scan_approvals(provider, OWNER.lower(), chain=MAINNET, limits=LIMITS)
    report = scan.report
    assert report.owner == OWNER
    assert report.block_number == head
    assert report.coverage.complete_for_requested_range is True
    assert report.coverage.scanned_from_block == head - 9_999
    assert report.pairs_discovered == 2
    assert len(scan.events) == 2

    permit2 = entry(report.approvals, TOKEN, PERMIT2)
    assert permit2.allowance_level is AllowanceLevel.UNLIMITED
    assert permit2.active is True
    assert permit2.spender.label == "Uniswap Permit2"
    assert permit2.spender.code_kind is CodeKind.CONTRACT
    assert permit2.owner_balance.raw == str(1_000 * UNIT)
    assert permit2.exposure_upper_bound.raw == str(1_000 * UNIT)  # min(balance, allowance)
    assert permit2.exposure_upper_bound.formatted == "1000"
    assert permit2.token.symbol == "TKN"
    assert permit2.token.decimals == 18
    codes = {s.code for s in permit2.signals}
    assert codes == {"unlimited_allowance", "allowance_exceeds_balance"}
    assert permit2.latest_event.explorer_url is not None

    router = entry(report.approvals, TOKEN, ROUTER)
    assert router.allowance_level is AllowanceLevel.LIMITED
    assert router.exposure_upper_bound.raw == str(300 * UNIT)
    assert router.signals == []


async def test_logs_are_requested_for_the_owner_topic_only(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)
    queries = [params[0] for method, params in node.requests if method == "eth_getLogs"]
    assert queries
    for query in queries:
        assert query["topics"] == [APPROVAL_TOPIC, address_topic(OWNER)]
        assert "address" not in query  # all tokens
        assert int(query["toBlock"], 16) - int(query["fromBlock"], 16) + 1 <= 1000


async def test_state_reads_are_pinned_to_the_scan_block(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 1, block=node.head - 1)
    await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)
    tags = {params[1] for method, params in node.requests if method in ("eth_call", "eth_getCode")}
    assert tags == {hex(node.head)}


async def test_current_allowance_wins_over_event_value(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 100 * UNIT, block=node.head - 10)
    token.allowances[(OWNER, ROUTER)] = 40 * UNIT  # partly spent via transferFrom
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    router = entry(report.approvals, TOKEN, ROUTER)
    assert router.latest_event.value == str(100 * UNIT)
    assert router.current_allowance.raw == str(40 * UNIT)
    assert "allowance_differs_from_latest_event" in {s.code for s in router.signals}


async def test_revoked_approval_is_inactive(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, UINT256_MAX, block=node.head - 20)
    node.add_approval_log(TOKEN, OWNER, ROUTER, 0, block=node.head - 10)
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    router = entry(report.approvals, TOKEN, ROUTER)
    assert router.events_in_range == 2
    assert router.latest_event.value == "0"
    assert router.allowance_level is AllowanceLevel.NONE
    assert router.active is False
    assert router.exposure_upper_bound.raw == "0"
    assert router.signals == []


async def test_latest_event_ordering_uses_block_then_log_index(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    block = node.head - 5
    node.add_approval_log(TOKEN, OWNER, ROUTER, 7, block=block, log_index=9)
    node.add_approval_log(TOKEN, OWNER, ROUTER, 3, block=block, log_index=2)
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    assert entry(report.approvals, TOKEN, ROUTER).latest_event.value == "7"


async def test_failed_allowance_call_is_unknown_not_zero(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 5, block=node.head - 1)
    token.reverts.add(SEL_ALLOWANCE)
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    router = entry(report.approvals, TOKEN, ROUTER)
    assert router.current_allowance.status == "unknown"
    assert router.current_allowance.unknown_reason == "call_reverted"
    assert router.allowance_level is AllowanceLevel.UNKNOWN
    assert router.active is None
    assert router.exposure_upper_bound.status == "unknown"
    assert router.owner_balance.status == "known"  # balance stays a separate concept


async def test_nonstandard_return_is_unknown(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 5, block=node.head - 1)
    token.returns[SEL_ALLOWANCE] = b""  # e.g. a contract without the function but no revert
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    assert entry(report.approvals, TOKEN, ROUTER).current_allowance.unknown_reason == (
        "nonstandard_return"
    )


async def test_token_without_code_is_not_called(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.add_approval_log(TOKEN2, OWNER, ROUTER, 5, block=node.head - 1)
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    item = entry(report.approvals, TOKEN2, ROUTER)
    assert item.token.code_kind is CodeKind.NO_CODE
    assert item.current_allowance.unknown_reason == "token_has_no_code"
    assert item.owner_balance.unknown_reason == "token_has_no_code"
    assert "eth_call" not in node.calls


async def test_missing_decimals_shows_base_units(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 5, block=node.head - 1)
    token.reverts.add(SEL_DECIMALS)
    token.allowances[(OWNER, ROUTER)] = 5
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    router = entry(report.approvals, TOKEN, ROUTER)
    assert router.token.decimals is None
    assert router.current_allowance.raw == "5"
    assert router.current_allowance.formatted is None
    assert "token_metadata_unavailable" in {s.code for s in router.signals}


async def test_spender_signals(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    delegated = OTHER_OWNER
    node.set_account(delegated, code=DELEGATION_PREFIX + bytes.fromhex(ROUTER[2:]))
    node.add_approval_log(TOKEN, OWNER, EOA_SPENDER, 5, block=node.head - 2)
    node.add_approval_log(TOKEN, OWNER, delegated, 5, block=node.head - 1)
    token.allowances[(OWNER, EOA_SPENDER)] = 5
    token.allowances[(OWNER, delegated)] = 5
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    eoa = entry(report.approvals, TOKEN, EOA_SPENDER)
    signal = next(s for s in eoa.signals if s.code == "spender_has_no_code")
    assert signal.evidence_class == "heuristic_signal"
    assert "not proof" in signal.explanation
    assert "spender_is_delegated_eoa" in {
        s.code for s in entry(report.approvals, TOKEN, delegated).signals
    }


async def test_revoked_eoa_approval_raises_no_signal(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, EOA_SPENDER, 0, block=node.head - 1)
    report = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    assert entry(report.approvals, TOKEN, EOA_SPENDER).signals == []


async def test_nft_removed_and_duplicate_logs(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN2, OWNER, ROUTER, 0, block=node.head - 3, nft_token_id=42)
    node.add_approval_log(TOKEN, OWNER, ROUTER, 9, block=node.head - 2, removed=True)
    duplicate = node.add_approval_log(TOKEN, OWNER, ROUTER, 5, block=node.head - 1)
    node.logs.append(dict(duplicate))
    scan = await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)
    counts = scan.report.log_counts
    assert (counts.erc721_shaped_approvals, counts.removed, counts.erc20_approvals) == (1, 1, 2)
    assert scan.report.pairs_discovered == 1
    assert entry(scan.report.approvals, TOKEN, ROUTER).events_in_range == 1
    assert len(scan.events) == 1


async def test_oversized_log_queries_are_split(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.max_log_range = 300
    blocks = [node.head - 10, node.head - 450, node.head - 999, node.head - 1500]
    for i, block in enumerate(blocks):
        node.add_approval_log(TOKEN, OWNER, f"0x{i + 1:040x}", 1, block=block)
    report = (
        await scan_approvals(provider, OWNER, chain=MAINNET, limits=limits(), lookback_blocks=2000)
    ).report
    assert report.pairs_discovered == 4
    assert report.coverage.complete_for_requested_range is True
    assert report.coverage.log_query_splits > 0
    assert report.coverage.scanned_from_block == node.head - 1999


async def test_budget_exhaustion_reports_partial_coverage(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 1, block=node.head - 50)
    node.add_approval_log(TOKEN, OWNER, PERMIT2, 1, block=node.head - 900)  # beyond the budget
    report = (
        await scan_approvals(
            provider,
            OWNER,
            chain=MAINNET,
            limits=limits(chunk_blocks=100, max_log_requests=2),
            lookback_blocks=1000,
        )
    ).report
    coverage = report.coverage
    assert coverage.complete_for_requested_range is False
    assert coverage.scanned_from_block == node.head - 199
    assert coverage.requested_from_block == node.head - 999
    assert "NOT scanned" in coverage.description
    assert [e.spender.address for e in report.approvals] == [ROUTER]


async def test_budget_exhausted_before_any_range(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.max_log_range = 1
    with pytest.raises(ScanBudgetExceededError):
        await scan_approvals(
            provider, OWNER, chain=MAINNET, limits=limits(chunk_blocks=8, max_log_requests=1)
        )


async def test_scan_window_is_bounded(node: FakeNode, provider: RpcEthereumProvider) -> None:
    with pytest.raises(BlockRangeTooLargeError):
        await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS, lookback_blocks=100_001)
    with pytest.raises(BlockRangeTooLargeError):
        await scan_approvals(
            provider, OWNER, chain=MAINNET, limits=LIMITS, from_block=node.head + 1
        )
    assert "eth_getLogs" not in node.calls


async def test_pair_limit_keeps_most_recent(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    for i in range(5):
        node.add_approval_log(TOKEN, OWNER, f"0x{i + 1:040x}", 1, block=node.head - 100 + i)
    report = (
        await scan_approvals(provider, OWNER, chain=MAINNET, limits=limits(max_pairs=2))
    ).report
    assert report.pairs_discovered == 5
    assert report.pairs_truncated == 3
    assert {e.latest_event.block_number for e in report.approvals} == {
        node.head - 96,
        node.head - 97,
    }
    assert any("not verified" in item for item in report.limitations)


async def test_reorg_during_scan_raises(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    def on_call(method: str) -> None:
        if method == "eth_getLogs":
            node.fork = "reorged"

    node.on_call = on_call
    with pytest.raises(ReorgDetectedError):
        await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)


async def test_scan_is_deterministic(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.add_approval_log(TOKEN, OWNER, ROUTER, 1, block=node.head - 3)
    node.add_approval_log(TOKEN, OWNER, PERMIT2, 2, block=node.head - 2)
    first = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    second = (await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)).report
    assert first.model_dump(exclude={"observed_at"}) == second.model_dump(exclude={"observed_at"})
    assert [e.spender.address for e in first.approvals] == sorted([ROUTER, PERMIT2])


async def test_provider_requiring_address_filter_gives_actionable_error(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    # Regression: publicnode.com rejects address-less eth_getLogs (found in a live check).
    node.require_log_address = True
    with pytest.raises(LogFilterRestrictedError) as excinfo:
        await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS)
    assert "--token" in excinfo.value.message
    assert node.calls.count("eth_getLogs") == 1  # not retried, not split


async def test_token_scope_filters_discovery(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    node.require_log_address = True
    node.add_token(TOKEN2)
    node.add_approval_log(TOKEN, OWNER, ROUTER, 1, block=node.head - 2)
    node.add_approval_log(TOKEN2, OWNER, ROUTER, 1, block=node.head - 1)
    report = (
        await scan_approvals(
            provider, OWNER, chain=MAINNET, limits=LIMITS, tokens=[TOKEN.lower(), TOKEN]
        )
    ).report
    assert report.token_scope == [TOKEN]
    assert [e.token.address for e in report.approvals] == [TOKEN]
    assert "Only these 1 token contract(s)" in report.coverage.description
    queries = [params[0] for method, params in node.requests if method == "eth_getLogs"]
    assert all(q["address"] == [TOKEN] for q in queries)


async def test_token_scope_is_bounded(provider: RpcEthereumProvider) -> None:
    many = [f"0x{i + 1:040x}" for i in range(26)]
    with pytest.raises(InvalidScanRequestError):
        await scan_approvals(provider, OWNER, chain=MAINNET, limits=LIMITS, tokens=many)


async def test_demo_scan_is_labelled() -> None:
    wallet = next(a.address for a in DEMO_ACCOUNTS if a.label == "plain-wallet")
    report = (await scan_approvals(DemoProvider(1), wallet, chain=MAINNET, limits=LIMITS)).report
    assert report.simulated is True
    assert report.limitations[0].startswith("SIMULATED DATA")
    assert report.pairs_discovered == 3
    assert all(e.latest_event.explorer_url is None for e in report.approvals)
    levels = sorted(e.allowance_level.value for e in report.approvals)
    assert levels == ["limited", "none", "unlimited"]
