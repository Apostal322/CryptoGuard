"""Parse the external label sources into validated long-format tables.

PTXPhish (the training labels) is a wide spreadsheet: one column of transaction hashes per
attack subtype plus two benign columns ("KOL" and "Developer" transactions), with a
"Source" column next to some subtypes. It contains no addresses, values or timestamps:
every feature must come from the chain (``collect.py``).

Poison-Hunter and Forta give address-level labels only. They are parsed for the data card
(overlaps, duplicates) and never used as training labels: Poison-Hunter's benign class is
1,154 *popular* addresses (separable from phishing addresses by popularity alone), and both
draw on Etherscan's labels, which are not independent of each other.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptoguard.ml.sources import SOURCES, local_path, verify

if TYPE_CHECKING:
    import pandas as pd

TX_HASH = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")

# PTXPhish sheet layout (row 3 holds the subtype headers; data starts at row 4).
_PTX_HEADER_ROW = 3
_PTX_FAMILIES = {
    "Approve": "ice_phishing",
    "Permit": "ice_phishing",
    "SetApproveForAll": "ice_phishing",
    "Bulk transfer": "nft_order",
    "Proxy upgrade": "nft_order",
    "Free buy order": "nft_order",
    "Zero value transfer": "address_poisoning",
    "Fake token transfer": "address_poisoning",
    "Dust value transfer": "address_poisoning",
    "Airdrop function": "payable_function",
    "Wallet function": "payable_function",
    "Benign KOL": "benign",
    "Benign Developer": "benign",
}
FAMILIES = (
    "ice_phishing",
    "nft_order",
    "address_poisoning",
    "payable_function",
    "benign",
)


def _snake(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def ptx_schema() -> Any:
    import pandera.pandas as pa

    return pa.DataFrameSchema(
        {
            "tx_hash": pa.Column(str, pa.Check.str_matches(TX_HASH.pattern), unique=True),
            "family": pa.Column(str, pa.Check.isin(FAMILIES)),
            "subtype": pa.Column(str, pa.Check.isin([_snake(k) for k in _PTX_FAMILIES])),
            "label": pa.Column(int, pa.Check.isin([0, 1])),
        },
        checks=pa.Check(
            lambda df: (df["label"] == (df["family"] != "benign").astype(int)).all(),
            error="label must be 1 exactly for the attack families",
        ),
        strict=True,
        coerce=False,
    )


def load_ptxphish(data_dir: Path) -> pd.DataFrame:
    """One validated row per labelled transaction (lower-case hash)."""
    import pandas as pd

    source = SOURCES["ptxphish"]
    verify(data_dir, source)
    path = local_path(data_dir, source, source.files[0])
    sheet = pd.read_excel(path, header=None, dtype=str)
    headers = sheet.iloc[_PTX_HEADER_ROW].tolist()
    seen = {h for h in headers if isinstance(h, str)} - {"Source"}
    if seen != set(_PTX_FAMILIES):
        raise ValueError(f"unexpected PTXPhish layout: subtypes {sorted(seen)}")
    rows = []
    for column, header in enumerate(headers):
        if header not in _PTX_FAMILIES:
            continue
        for value in sheet.iloc[_PTX_HEADER_ROW + 1 :, column].dropna():
            tx_hash = str(value).strip().lower()
            if not TX_HASH.match(tx_hash):
                raise ValueError(f"PTXPhish column {header!r}: not a tx hash: {value!r}")
            family = _PTX_FAMILIES[header]
            rows.append((tx_hash, family, _snake(header), int(family != "benign")))
    frame = pd.DataFrame(rows, columns=["tx_hash", "family", "subtype", "label"])
    frame = frame.astype({"tx_hash": str, "family": str, "subtype": str, "label": int})
    return ptx_schema().validate(frame)  # type: ignore[no-any-return]


def load_address_labels(data_dir: Path) -> pd.DataFrame:
    """Address-level labels from Poison-Hunter and Forta (data card only, not training)."""
    import pandas as pd

    rows: list[tuple[str, str, str]] = []
    ph = SOURCES["poison-hunter"]
    verify(data_dir, ph)
    for file, label in (
        ("phishing_address_groundtruth.txt", "phishing"),
        ("benign_addresses_on_etherscan.txt", "benign_popular"),
    ):
        text = (data_dir / ph.name / file).read_text(encoding="utf-8")
        rows += [(a.strip().lower(), label, f"poison-hunter:{file}") for a in text.split()]
    forta = SOURCES["forta"]
    verify(data_dir, forta)
    for file, column in (
        ("labels/1/phishing_scams.csv", "address"),
        ("labels/1/etherscan_malicious_labels.csv", "banned_address"),
    ):
        table = pd.read_csv(data_dir / forta.name / file, usecols=[column], dtype=str)
        rows += [(a.lower(), "phishing", f"forta:{file}") for a in table[column].dropna()]
    frame = pd.DataFrame(rows, columns=["address", "label", "source"])
    bad = frame[~frame["address"].str.match(ADDRESS.pattern)]
    if len(bad):
        raise ValueError(f"{len(bad)} malformed addresses, e.g. {bad.iloc[0].to_dict()}")
    return frame


def poison_hunter_sample_is_shifted(data_dir: Path) -> bool:
    """The 150-row transfer sample has two more fields per row than header names, so a
    plain CSV read assigns values to the wrong columns. Detected, reported, never used."""
    import csv

    path = data_dir / "poison-hunter" / "phishing_transfers_sample.csv"
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        widths = {len(row) for row in reader if row}
    return widths != {len(header)}
