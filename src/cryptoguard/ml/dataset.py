"""Build the validated modelling table and its manifest from labels plus collected chain data.

Rows are grouped by the accounts they tie together (``features.parties``), joined by
union-find. Accounts used by many distinct senders (tokens, routers, marketplaces) are
public infrastructure: they do not join rows, or every row would collapse into one group.
The rule is label-free; ``group_report`` states how much it cuts.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptoguard.ml import FEATURE_SET_VERSION
from cryptoguard.ml.features import FEATURES, extract, parties

if TYPE_CHECKING:
    import pandas as pd

# Public infrastructure (label-free): an account used by at least HUB_MIN_SENDERS distinct
# senders (routers, Permit2), or a log-emitting contract (token, marketplace) touched by
# at least EMITTER_MIN_SENDERS distinct senders. Phishing contracts that victims call
# directly emit no logs and stay linking accounts unless they reach HUB_MIN_SENDERS.
HUB_MIN_SENDERS = 10
EMITTER_MIN_SENDERS = 2


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
    senders: dict[str, set[str]] = defaultdict(set)
    emitter_senders: dict[str, set[str]] = defaultdict(set)
    for rec in records.values():
        sender = (rec["tx"].get("from") or "").lower()
        for account in parties(rec):
            senders[account].add(sender)
        for log in (rec.get("receipt") or {}).get("logs") or []:
            emitter_senders[log["address"].lower()].add(sender)
    return {a for a, s in senders.items() if len(s) >= HUB_MIN_SENDERS} | {
        a for a, s in emitter_senders.items() if len(s) >= EMITTER_MIN_SENDERS
    }


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
        "hub_rule": {"min_senders": HUB_MIN_SENDERS, "emitter_min_senders": EMITTER_MIN_SENDERS},
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
