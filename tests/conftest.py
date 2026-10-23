from __future__ import annotations

import random
from collections.abc import AsyncIterator

import pytest

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from tests.fakenode import FakeNode


class SleepRecorder:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


@pytest.fixture
def node() -> FakeNode:
    return FakeNode()


@pytest.fixture
def sleeps() -> SleepRecorder:
    return SleepRecorder()


def make_client(node: FakeNode, sleeps: SleepRecorder, *, max_retries: int = 3) -> JsonRpcClient:
    return JsonRpcClient(
        "https://rpc.example.invalid/v2/SECRETKEY123",
        retry=RetryPolicy(max_retries=max_retries, base_delay=0.5, max_delay=4.0),
        transport=node.transport(),
        sleep=sleeps,
        rng=random.Random(0),
    )


@pytest.fixture
async def provider(node: FakeNode, sleeps: SleepRecorder) -> AsyncIterator[RpcEthereumProvider]:
    rpc = RpcEthereumProvider(
        make_client(node, sleeps),
        expected_chain_id=1,
        endpoint_display="https://rpc.example.invalid/…",
        max_log_block_range=1000,
    )
    yield rpc
    await rpc.aclose()
