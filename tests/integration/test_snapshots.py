from __future__ import annotations

import pytest

from cryptoguard.blockchain.abi import UINT256_MAX
from cryptoguard.blockchain.eip7702 import DELEGATION_PREFIX
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.chains import get_chain
from cryptoguard.core.errors import InvalidScanRequestError
from cryptoguard.database.history import HistoryRepository
from cryptoguard.database.repository import create_db_engine, init_schema
from cryptoguard.history.delta import ChangeKind
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.snapshots import SnapshotOutcome, take_snapshot
from tests.fakenode import FakeNode, FakeToken

MAINNET = get_chain(1)
OWNER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
DELEGATE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
LIMITS = ScanLimits(
    lookback_blocks=1_000,
    max_scan_blocks=5_000,
    chunk_blocks=1_000,
    max_log_requests=100,
    max_pairs=50,
)


def repository() -> HistoryRepository:
    engine = create_db_engine("sqlite://")
    init_schema(engine)
    return HistoryRepository(engine)


@pytest.fixture
def repo() -> HistoryRepository:
    return repository()


@pytest.fixture
def token(node: FakeNode) -> FakeToken:
    fake = node.add_token(TOKEN)
    fake.balances[OWNER] = 100
    node.set_account(ROUTER, code=b"\x60\x80")
    node.set_account(PERMIT2, code=b"\x60\x80")
    node.set_account(DELEGATE, code=b"\x60\x80")
    return fake


async def snap(
    provider: RpcEthereumProvider, repo: HistoryRepository, **kwargs: object
) -> SnapshotOutcome:
    return await take_snapshot(
        provider,
        repo,
        OWNER,
        chain=MAINNET,
        limits=LIMITS,
        confirmations=0,
        **kwargs,  # type: ignore[arg-type]
    )


def approve(node: FakeNode, token: FakeToken, spender: str, value: int, block: int) -> None:
    node.add_approval_log(TOKEN, OWNER, spender, value, block=block)
    token.allowances[(OWNER, spender)] = value


async def test_baseline_then_genuine_changes(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    approve(node, token, ROUTER, UINT256_MAX, node.head - 100)
    base = await snap(provider, repo)
    assert base.is_baseline
    assert base.created
    assert base.changes == []
    assert base.coverage.scanned[0].from_block == node.head - 999
    [new] = base.finding_events
    assert (new.rule_id, new.to_status, new.severity) == ("CG-APR-001", "new", "review_recommended")

    first_block = node.head
    node.head += 50
    approve(node, token, PERMIT2, 40, node.head - 10)  # new approval with an event
    approve(node, token, ROUTER, 0, node.head - 5)  # revocation with an event

    second = await snap(provider, repo)
    assert not second.is_baseline
    assert second.previous_block == first_block
    kinds = {(c.spender, c.kind) for c in second.changes}
    assert kinds == {
        (PERMIT2, ChangeKind.ALLOWANCE_GRANTED),
        (ROUTER, ChangeKind.ALLOWANCE_REVOKED),
    }
    for change in second.changes:
        assert change.cause.kind == "approval_event"
        assert change.cause.transaction_hash is not None
        assert (change.from_block_exclusive, change.to_block) == (first_block, node.head)
    [resolved] = second.finding_events
    assert (resolved.from_status, resolved.to_status) == ("new", "resolved")

    rows, total = repo.timeline(1, OWNER, limit=10, offset=0)
    assert total == 2
    assert [r.snapshot.block_number for r in rows] == [node.head, first_block]
    assert rows[0].previous_block == first_block


async def test_discovery_is_incremental(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    await snap(provider, repo)
    previous = node.head
    node.head += 30
    node.requests.clear()
    second = await snap(provider, repo)
    ranges = [
        (int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16))
        for m, p in node.requests
        if m == "eth_getLogs"
    ]
    # Approvals, outgoing transfers and incoming transfers: each only over the new blocks.
    assert ranges == [(previous + 1, node.head)] * 3
    assert [(r.from_block, r.to_block) for r in second.coverage.scanned] == [
        (previous - 999, node.head)
    ]
    assert second.coverage.gaps == []


async def test_spending_without_event_is_a_state_comparison_change(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    approve(node, token, ROUTER, 500, node.head - 10)
    await snap(provider, repo)
    node.head += 20
    token.allowances[(OWNER, ROUTER)] = 120  # transferFrom spent 380; no Approval event
    [change] = (await snap(provider, repo)).changes
    assert change.kind is ChangeKind.ALLOWANCE_REDUCED
    assert (change.before, change.after) == ("500", "120")
    assert change.cause.kind == "state_comparison"
    assert change.cause.transaction_hash is None


async def test_delegation_set_between_snapshots(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    await snap(provider, repo)
    node.head += 5
    node.set_account(OWNER, code=DELEGATION_PREFIX + bytes.fromhex(DELEGATE[2:]))
    second = await snap(provider, repo)
    [change] = second.changes
    assert change.kind is ChangeKind.DELEGATION_SET
    assert change.after == DELEGATE
    assert change.cause.transaction_hash is None
    assert [(e.rule_id, e.to_status) for e in second.finding_events] == [("CG-DEL-001", "new")]


async def test_finding_lifecycle_across_snapshots(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    approve(node, token, ROUTER, UINT256_MAX, node.head - 1)
    await snap(provider, repo)
    node.head += 1
    second = await snap(provider, repo)
    assert [(e.from_status, e.to_status) for e in second.finding_events] == [("new", "active")]
    [finding] = repo.list_findings(1, OWNER, ["active"])
    assert repo.acknowledge_finding(finding.fingerprint) is not None

    node.head += 1
    assert (await snap(provider, repo)).finding_events == []  # acknowledged stays acknowledged

    node.head += 1
    token.reverts.add(bytes.fromhex("dd62ed3e"))  # allowance() now reverts
    unverified = await snap(provider, repo)
    assert unverified.findings_not_reverified == 1
    assert repo.list_findings(1, OWNER, ["acknowledged"])  # not resolved on missing evidence
    # The unreadable allowance is itself a finding (severity unknown).
    assert [(e.rule_id, e.to_status, e.severity) for e in unverified.finding_events] == [
        ("CG-APR-003", "new", "unknown")
    ]

    node.head += 1
    token.reverts.clear()
    approve(node, token, ROUTER, 0, node.head)
    resolved = await snap(provider, repo)
    assert {(e.rule_id, e.from_status, e.to_status) for e in resolved.finding_events} == {
        ("CG-APR-001", "acknowledged", "resolved"),
        ("CG-APR-003", "new", "resolved"),
    }
    detail = repo.get_finding(finding.fingerprint)
    assert detail is not None
    statuses = [(t.from_status, t.to_status) for t in detail[1]]
    assert statuses == [
        (None, "new"),
        ("new", "active"),
        ("active", "acknowledged"),
        ("acknowledged", "resolved"),
    ]
    assert detail[0].resolved_block == node.head

    node.head += 1
    approve(node, token, ROUTER, UINT256_MAX, node.head)
    reopened = await snap(provider, repo)
    assert [(e.from_status, e.to_status) for e in reopened.finding_events] == [("resolved", "new")]
    assert repo.get_finding(finding.fingerprint)[0].reopen_count == 1  # type: ignore[index]


async def test_same_block_is_idempotent_and_backwards_is_rejected(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    first = await snap(provider, repo)
    again = await snap(provider, repo)
    assert again.created is False
    assert again.snapshot_id == first.snapshot_id
    with pytest.raises(InvalidScanRequestError, match="forward"):
        await snap(provider, repo, block=node.head - 1)
    with pytest.raises(InvalidScanRequestError):
        await snap(provider, repo, block=node.head + 1)


async def test_default_block_respects_confirmations(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    outcome = await take_snapshot(
        provider, repo, OWNER, chain=MAINNET, limits=LIMITS, confirmations=12
    )
    assert outcome.block_number == node.head - 12
    assert outcome.lag_blocks == 12


async def test_reorged_previous_snapshot_is_orphaned(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    approve(node, token, ROUTER, 5, node.head - 3)
    await snap(provider, repo)
    assert repo.count_approval_events(1, OWNER) == 1
    node.fork = "other"  # every block hash changes: the old snapshot is no longer canonical
    node.logs.clear()
    node.head += 2
    outcome = await snap(provider, repo)
    assert outcome.orphaned_snapshots == 1
    assert outcome.is_baseline  # no canonical base left within the lookback
    _, total = repo.timeline(1, OWNER, limit=10, offset=0)
    assert total == 1
    _, with_orphans = repo.timeline(1, OWNER, limit=10, offset=0, include_orphaned=True)
    assert with_orphans == 2
    assert repo.count_approval_events(1, OWNER) == 0  # stale fork events were dropped


async def test_token_scope_is_fixed_after_baseline(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    await snap(provider, repo, tokens=[TOKEN])
    node.head += 1
    inherited = await snap(provider, repo)
    assert TOKEN in inherited.coverage.description
    node.head += 1
    with pytest.raises(InvalidScanRequestError, match="scope"):
        await snap(provider, repo, tokens=[ROUTER])


async def test_long_gap_is_reported(
    node: FakeNode, provider: RpcEthereumProvider, repo: HistoryRepository, token: FakeToken
) -> None:
    await snap(provider, repo)
    first = node.head
    node.head += 8_000  # beyond max_scan_blocks (5,000)
    outcome = await snap(provider, repo)
    [gap] = outcome.coverage.gaps
    assert (gap.from_block, gap.to_block) == (first + 1, node.head - 5_000)
    assert "NOT scanned" in outcome.coverage.description


async def test_snapshots_are_reproducible(
    node: FakeNode, provider: RpcEthereumProvider, token: FakeToken
) -> None:
    approve(node, token, ROUTER, UINT256_MAX, node.head - 4)
    approve(node, token, PERMIT2, 3, node.head - 2)
    a = await snap(provider, repository())
    b = await snap(provider, repository())
    assert a.state_hash == b.state_hash
    assert a.model_dump(exclude={"snapshot_id"}) == b.model_dump(exclude={"snapshot_id"})
