"""Generic review cohorts (Phase 11.5): deterministic stratified draw, freeze-once, and the
existing review workflow running a second, separately frozen cohort without revealing its
purpose.

Synthetic items and synthetic reviewer decisions only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import cohort as ch
from cryptoguard.ml import review_sample as rs
from cryptoguard.ml import unblind as ub
from cryptoguard.ml.review_server import ReviewApp
from tests.review_fixtures import ATTEMPT_FIELDS, addr, fields

COHORT = "hard-negative-candidates/1"
LEGIT = {
    **ATTEMPT_FIELDS,
    "decision": "confirmed_legitimate_interaction",
    "prior_counterparty": "not_observed",
    "prior_counterparty_address": None,
    "matched_leading": None,
    "matched_trailing": None,
    "legitimate_explanation": "observed",
    "rationale": "The address is the wallet owner's own exchange deposit address.",
}


def items(n_arc: int = 40, wallets: int = 3, per_wallet: int = 5) -> list[ch.FrameItem]:
    out = []
    k = 0
    for i in range(n_arc):
        k += 1
        out.append(
            _item(
                k,
                f"archive_uncategorized|{2023 if i % 2 else 2022}|{'yes' if i % 7 == 0 else 'no'}",
                group=f"a/{i // 2}",
            )
        )
    for w in range(wallets):
        for _ in range(per_wallet):
            k += 1
            out.append(_item(k, f"fixture_background:w{w}|2024|no", group=f"f/{k}"))
    return out


def _item(k: int, stratum: str, *, group: str) -> ch.FrameItem:
    return ch.FrameItem(
        event_id=f"{k:016x}",
        stratum=stratum,
        group=group,
        sheet={
            "chain_id": 1,
            "wallet": addr(1000 + k),
            "address_under_review": addr(2000 + k),
            "transaction": "0x" + f"{k:064x}",
            "block": 17_000_000 + k,
            "coverage_note": "No wallet history is included.",
            "context": [
                {"block": 1, "direction": "out", "counterparty": addr(3000 + k), "value": "5"}
            ],
        },
        key={
            "frame": stratum.split("|")[0],
            "categories": ["A_similarity_ordinary_value"],
            "screen_status": "no_known_overlap",
            "label_status": "unlabeled_candidate",
            "imitated": addr(4000 + k),
        },
    )


def design(quota: dict[str, int] | None = None) -> ch.CohortDesign:
    q = quota or {"archive_uncategorized": 6} | {f"fixture_background:w{w}": 2 for w in range(3)}
    return ch.CohortDesign(COHORT, "seed", q, ("frame", "year", "potential_positive_overlap"), "t")


def test_draw_is_deterministic_stratified_and_one_per_group() -> None:
    a = ch.draw(items(), design())
    b = ch.draw(list(reversed(items())), design())
    assert a == b
    m = a["manifest"]
    assert len(m["selected"]) == 12
    by_item = {i.event_id: i for i in items()}
    groups = [by_item[r["victim_event_id"]].group for r in m["selected"]]
    assert len(set(groups)) == len(groups)
    table = {r["stratum"]: r for r in m["strata_table"]}
    assert sum(r["groups"] for r in table.values()) == m["groups"]["count"]  # every rep counted
    for r in table.values():
        if r["selected"]:
            got = sum(x["weight"] for x in m["selected"] if x["stratum"] == r["stratum"])
            assert got == pytest.approx(r["groups"])  # weights are N/n


def test_sheet_is_neutral_and_key_holds_the_rest() -> None:
    s = ch.draw(items(), design())
    for line in s["sheet"]:
        assert line["description"] == ch.NEUTRAL
        text = json.dumps(line)
        for word in (
            "archive",
            "fixture",
            "uncategorized",
            "negative",
            "categor",
            "screen",
            "label",
            "imitated",
        ):
            assert word not in text
    assert all("candidate" in k and "sheet" in k for k in s["key"])


def test_empty_or_duplicate_frames_are_refused() -> None:
    with pytest.raises(rs.ReviewSampleError, match="empty"):
        ch.draw([], design())
    dup = items()[:2]
    with pytest.raises(rs.ReviewSampleError, match="repeats"):
        ch.draw([dup[0], dup[0]], design())


def test_small_strata_take_everything_they_have() -> None:
    m = ch.draw(items(per_wallet=1), design())["manifest"]
    fixture_rows = [r for r in m["strata_table"] if r["stratum"].startswith("fixture")]
    assert all(r["selected"] == r["groups"] == 1 for r in fixture_rows)  # census


def test_freeze_once_and_refuse_a_changed_frame(tmp_path: Path) -> None:
    out = tmp_path / "cohort"
    m, written = ch.freeze(items(), design(), out)
    assert written
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    again, written = ch.freeze(items(), design(), out)
    assert not written
    assert again["selection_sha256"] == m["selection_sha256"]
    with pytest.raises(rs.SampleFrozenError, match="frame changed"):
        ch.freeze(items()[:-1], design(), out)
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


# --- the review workflow on a second cohort ----------------------------------------------------


@pytest.fixture
def frozen_cohort(tmp_path: Path, monkeypatch) -> dict[str, Any]:
    out = tmp_path / "cohort"
    m, _ = ch.freeze(items(), design(), out)
    hashes = {name: rs.file_sha256(out / name) for name in (rs.SHEET, rs.KEY, rs.MANIFEST)}
    monkeypatch.setitem(
        rs.COHORTS,
        COHORT,
        hashes | {"selection": m["selection_sha256"], "queue": m["queue_sha256"]},
    )
    return {"dir": out, "manifest": m, "tmp": tmp_path}


def test_package_names_no_cohort_and_server_hides_the_key(frozen_cohort: dict[str, Any]) -> None:
    t = frozen_cohort["tmp"]
    pkg = ub.make_package(frozen_cohort["dir"], t / "work", "A", t / "pkg", cohort=COHORT)
    info = (pkg / "reviewer.json").read_text(encoding="utf-8")
    assert "negative" not in info
    assert COHORT not in info
    state = ReviewApp(pkg).state()
    text = json.dumps(state)
    for word in ("negative", "archive_uncategorized", "fixture", "screen", "unlabeled", "categor"):
        assert word not in text
    hidden = {i.key["imitated"] for i in items()}
    assert not any(h in text for h in hidden)  # key-only addresses are never sent
    first = state["items"][0]
    assert first["description"] == ch.NEUTRAL
    assert first["context"][0]["direction"] == "out"


def test_verification_of_one_cohort_does_not_accept_another(frozen_cohort: dict[str, Any]) -> None:
    with pytest.raises(rs.FrozenIntegrityError):
        rs.verify_frozen(frozen_cohort["dir"])  # checked against the Phase 11.4 hashes
    assert rs.verify_frozen(frozen_cohort["dir"], cohort=COHORT)["sample_version"] == COHORT


def _review(pkg: Path, decide) -> Path:
    app = ReviewApp(pkg)
    with app.store:
        for it in app.state()["items"]:
            app.store.save(fields(it["item"], it["victim_event_id"], decide(it["item"])))
        app.finalize()
    return pkg / "annotations" / "submission.json"


def test_unblinding_a_candidate_cohort_reports_the_legitimate_share(
    frozen_cohort: dict[str, Any],
) -> None:
    t, d = frozen_cohort["tmp"], frozen_cohort["dir"]
    pkgs = {r: ub.make_package(d, t / "work", r, t / f"pkg-{r}", cohort=COHORT) for r in "AB"}
    a = _review(pkgs["A"], lambda i: LEGIT)
    b = _review(pkgs["B"], lambda i: ATTEMPT_FIELDS if i == 1 else LEGIT)
    with pytest.raises(ub.UnblindingRefused):
        ub.unblind(d, t / "work", [a, b])  # the default cohort's hashes do not match
    report = ub.unblind(d, t / "work", [a, b], cohort=COHORT)
    n = len(frozen_cohort["manifest"]["selected"])
    legit = report["all_reviewers_legitimate"]["overall"]
    assert legit["positives"] == n - 1  # one item disputed
    assert report["agreement"]["binary"]["disagreements"] == 1
    assert any(k.startswith("frame=") for k in report["agreement"]["by_subgroup"])
    assert "no source label" in report["source_comparison"]["note"]
