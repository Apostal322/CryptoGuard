"""Leakage-safe train / validation / test splits.

1. **Study window.** Only blocks where both classes occur are kept. PTXPhish's benign
   transactions span 2017-2024 but its phishing ones 2022-2023; outside the overlap, the
   era alone (gas-fee format, token mix) would separate the classes.
2. **Time.** Rows are ordered by block; train is the earliest part, then validation, then
   test. No block is shared by two splits.
3. **Account purge.** A validation row sharing any non-hub account (sender, target,
   spender, recipient: ``features.parties``) with a training row is dropped, and a test row
   sharing one with a kept training or validation row is dropped. This stops repeated
   users and reused attacker infrastructure from appearing on both sides.
4. **Point in time.** Hubs (public infrastructure, ``dataset.hubs``) are determined from the
   training rows only, so later data never shapes the split.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptoguard.ml.dataset import hubs
from cryptoguard.ml.features import parties

if TYPE_CHECKING:
    import pandas as pd


@dataclass(frozen=True)
class SplitPlan:
    train: float = 0.6
    validation: float = 0.2  # test gets the rest


DEFAULT_SPLIT = SplitPlan()


def study_window(table: pd.DataFrame) -> tuple[int, int]:
    """Block range in which both classes occur (a dataset definition, stated in reports)."""
    by = table.groupby("label")["block_number"]
    return int(by.min().max()), int(by.max().min())


def _cut(blocks: list[int], fraction: float) -> int:
    """First block of the part after ``fraction`` of rows (never splits a block)."""
    index = min(int(len(blocks) * fraction), len(blocks) - 1)
    return blocks[index]


def make_splits(
    table: pd.DataFrame,
    records: dict[str, dict[str, Any]],
    plan: SplitPlan = DEFAULT_SPLIT,
) -> tuple[pd.Series, dict[str, Any]]:
    """A split name per row ("train", "validation", "test", or "excluded:<reason>")."""
    import pandas as pd

    lo, hi = study_window(table)
    split = pd.Series("excluded:outside_window", index=table.index, dtype=object)
    inside = table[(table["block_number"] >= lo) & (table["block_number"] <= hi)]
    blocks = sorted(inside["block_number"])
    val_start = _cut(blocks, plan.train)
    test_start = _cut(blocks, plan.train + plan.validation)
    split[inside.index[inside["block_number"] < val_start]] = "train"
    split[
        inside.index[(inside["block_number"] >= val_start) & (inside["block_number"] < test_start)]
    ] = "validation"
    split[inside.index[inside["block_number"] >= test_start]] = "test"

    train_records = {h: records[h] for h in table.loc[split == "train", "tx_hash"]}
    hub_set = hubs(train_records)

    def accounts(tx_hash: str) -> set[str]:
        return parties(records[tx_hash]) - hub_set

    seen: set[str] = set()
    for tx_hash in table.loc[split == "train", "tx_hash"]:
        seen |= accounts(tx_hash)
    for name in ("validation", "test"):
        keep: set[str] = set()
        for index in table.index[split == name]:
            acc = accounts(str(table.at[index, "tx_hash"]))
            if acc & seen:
                split[index] = f"excluded:shares_account_with_earlier_split({name})"
            else:
                keep |= acc
        seen |= keep

    summary: dict[str, Any] = {
        "window": [lo, hi],
        "boundaries": {"validation_from_block": val_start, "test_from_block": test_start},
        "hub_accounts_from_train": len(hub_set),
        "counts": {
            str(name): {str(k): int(v) for k, v in grp["label"].value_counts().sort_index().items()}
            for name, grp in table.groupby(split)
        },
    }
    return split, summary
