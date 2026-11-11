"""Build the validated modelling table and its manifest from labels plus collected chain data.

Rows are grouped by the accounts they tie together (``features.parties``), joined by
union-find. Only a curated registry of public infrastructure (major tokens, DEX routers,
marketplaces, Permit2) does not join rows. Degree-based rules ("used by many senders") were
tried and rejected: a scam contract called by many victims looks exactly like a popular
router, and exempting it lets its later victims leak into the test split. Over-linking only
costs evaluation rows; under-linking leaks. ``group_report`` states the effect.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptoguard.ml import FEATURE_SET_VERSION
from cryptoguard.ml.features import FEATURES, extract, parties

if TYPE_CHECKING:
    import pandas as pd

# Public infrastructure on Ethereum mainnet, identified by name from the projects' own
# published deployments (independent of any label source). Lower-case.
PUBLIC_INFRASTRUCTURE: dict[str, str] = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "Tether USD (USDT)",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USD Coin (USDC)",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "Dai (DAI)",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "Wrapped Ether (WETH)",
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "Lido staked ETH (stETH)",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router 02",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 SwapRouter02",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Aggregation Router v5",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x00000000006c3852cbef3e08e8df289169ede581": "OpenSea Seaport 1.1",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "OpenSea Seaport 1.5",
    "0x1e0049783f008a0085193e00003d00cd54003c71": "OpenSea Conduit",
    "0x000000000000ad05ccc4f10045630fb830b95127": "Blur Marketplace",
}


def table_schema() -> Any:
    import pandera.pandas as pa

    finite = pa.Check(lambda s: s.notna() & (s.abs() < 1e12), element_wise=False)
    return pa.DataFrameSchema(
        {
            "tx_hash": pa.Column(str, pa.Check.str_matches(r"^0x[0-9a-f]{64}$"), unique=True),
            "block_number": pa.Column(int, pa.Check.gt(0)),
            "label": pa.Column(int, pa.Check.isin([0, 1])),
            "family": pa.Column(str),
            "subtype": pa.Column(str),
            "group": pa.Column(str),
            **{name: pa.Column(float, finite) for name in FEATURES},
        },
        strict=True,
        ordered=True,
    )


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)  # deterministic representative


def hubs(records: dict[str, dict[str, Any]]) -> set[str]:
    """Registry accounts that occur in ``records`` (the rest always link rows)."""
    seen: set[str] = set()
    for rec in records.values():
        seen |= parties(rec)
    return seen & set(PUBLIC_INFRASTRUCTURE)


def assign_groups(records: dict[str, dict[str, Any]], hub_set: set[str]) -> dict[str, str]:
    uf = _UnionFind()
    for tx_hash in sorted(records):
        uf.find(tx_hash)
        for account in sorted(parties(records[tx_hash]) - hub_set):
            uf.union(tx_hash, "acct:" + account)
    return {h: "g" + hashlib.sha256(uf.find(h).encode()).hexdigest()[:12] for h in records}


def build_table(
    labels: pd.DataFrame, records: dict[str, dict[str, Any]]
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Validated table (one row per collected, labelled transaction) and build facts."""
    import pandas as pd

    ok = {h: r for h, r in records.items() if r["status"] == "ok"}
    hub_set = hubs(ok)
    groups = assign_groups(ok, hub_set)
    by_hash: dict[str, dict[str, Any]] = {
        str(r["tx_hash"]): {str(k): v for k, v in r.items()} for r in labels.to_dict("records")
    }
    rows = []
    for tx_hash in sorted(ok):
        if tx_hash not in by_hash:
            continue
        lab = by_hash[tx_hash]
        rows.append(
            {
                "tx_hash": tx_hash,
                "block_number": int(ok[tx_hash]["tx"]["blockNumber"], 16),
                "label": int(lab["label"]),
                "family": str(lab["family"]),
                "subtype": str(lab["subtype"]),
                "group": groups[tx_hash],
                **extract(ok[tx_hash]),
            }
        )
    table = table_schema().validate(pd.DataFrame(rows))
    facts = {
        "feature_set": FEATURE_SET_VERSION,
        "rows": len(table),
        "not_found": sum(r["status"] == "not_found" for r in records.values()),
        "hub_accounts": len(hub_set),
        "hub_rule": "curated public-infrastructure registry only",
    }
    return table, facts


def group_report(table: pd.DataFrame) -> dict[str, Any]:
    """Diagnostics only (labels are read here, never when grouping)."""
    g = table.groupby("group")["label"].agg(["size", "mean"])
    mixed = g[(g["mean"] > 0) & (g["mean"] < 1)]
    return {
        "groups": len(g),
        "largest_group_rows": int(g["size"].max()),
        "singleton_groups": int((g["size"] == 1).sum()),
        "mixed_label_groups": len(mixed),
        "rows_in_mixed_groups": int(mixed["size"].sum()),
        "phishing_rows_sharing_a_group": int(
            table[table["label"] == 1].groupby("group").size().loc[lambda s: s > 1].sum()
        ),
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_table(
    table: pd.DataFrame, facts: dict[str, Any], out: Path, inputs: dict[str, Path]
) -> dict[str, Any]:
    """Write the table as CSV (stable formatting) plus a manifest of every input's hash."""
    out.parent.mkdir(parents=True, exist_ok=True)
    data = table.to_csv(index=False, lineterminator="\n", float_format="%.10g").encode()
    out.write_bytes(data)
    manifest = {
        **facts,
        "table": {"path": out.as_posix(), "sha256": sha256_bytes(data)},
        "inputs": {
            k: {"path": p.as_posix(), "sha256": sha256_bytes(p.read_bytes())}
            for k, p in inputs.items()
        },
        "label_counts": {
            f"{r['family']}/{r['subtype']}": int(r["n"])
            for r in table.groupby(["family", "subtype"])
            .size()
            .reset_index(name="n")
            .to_dict("records")
        },
        "block_range": [int(table["block_number"].min()), int(table["block_number"].max())],
        "groups": group_report(table),
    }
    out.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest
