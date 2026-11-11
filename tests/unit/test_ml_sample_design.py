"""Frozen-sample verification and the design-based estimator (Phase 11.4).

Synthetic samples only. Estimator tests use populations small enough to check by hand or
by enumerating every possible sample.
"""

from __future__ import annotations

import itertools
import json
import shutil
from fractions import Fraction
from pathlib import Path

import pytest

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml import sample_design as sd
from tests.review_fixtures import frozen, pkt, queue

# --- frozen-sample verification -----------------------------------------------------------


def test_verification_passes_on_untouched_files(tmp_path: Path, monkeypatch) -> None:
    q, sample, manifest = frozen(tmp_path, monkeypatch)
    assert rs.verify_frozen(sample, queue=q)["selection_sha256"] == manifest["selection_sha256"]


@pytest.mark.parametrize("name", [rs.SHEET, rs.KEY, rs.MANIFEST])
def test_any_changed_byte_is_refused_and_left_in_place(
    tmp_path: Path, monkeypatch, name: str
) -> None:
    """A modified file is reported, never regenerated: its bytes stay as found."""
    _, sample, _ = frozen(tmp_path, monkeypatch)
    path = sample / name
    tampered = path.read_bytes().replace(b"\n", b"\r\n", 1)
    path.write_bytes(tampered)
    with pytest.raises(rs.FrozenIntegrityError, match=name):
        rs.verify_frozen(sample)
    assert path.read_bytes() == tampered


def test_missing_manifest_and_wrong_queue_are_refused(tmp_path: Path, monkeypatch) -> None:
    q, sample, _ = frozen(tmp_path, monkeypatch)
    q.write_text(q.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(rs.FrozenIntegrityError, match="review queue"):
        rs.verify_frozen(sample, queue=q)
    (sample / rs.MANIFEST).unlink()
    with pytest.raises(rs.FrozenIntegrityError, match="missing"):
        rs.verify_frozen(sample)


def test_selection_hash_is_recomputed_not_trusted(tmp_path: Path, monkeypatch) -> None:
    """A manifest edited consistently (new selection, matching file hash) still fails,
    because the selection hash committed in the docs no longer matches."""
    _, sample, manifest = frozen(tmp_path, monkeypatch)
    manifest["selected"][0]["victim_event_id"] = manifest["selected"][1]["victim_event_id"]
    (sample / rs.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setitem(rs.FROZEN_V1, rs.MANIFEST, rs.file_sha256(sample / rs.MANIFEST))
    with pytest.raises(rs.FrozenIntegrityError, match="selection hash"):
        rs.verify_frozen(sample)


def test_reviewer_package_verification_needs_no_key(tmp_path: Path, monkeypatch) -> None:
    _, sample, _ = frozen(tmp_path, monkeypatch)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    for name in (rs.SHEET, rs.MANIFEST):
        shutil.copyfile(sample / name, pkg / name)
    rs.verify_frozen(pkg, with_key=False)
    with pytest.raises(rs.FrozenIntegrityError, match="missing"):
        rs.verify_frozen(pkg)


# --- audit ---------------------------------------------------------------------------------


def test_audit_reproduces_the_design_and_reports_units(tmp_path: Path, monkeypatch) -> None:
    _, _, manifest = frozen(tmp_path, monkeypatch)
    a = sd.audit(queue(), manifest)
    assert a["all_checks_pass"], a["checks"]
    u = a["units"]
    assert u["attempts"] == len(queue())
    assert u["campaign_groups"] == u["representatives"] == u["attempts"] - 1
    assert u["non_representative_attempts"] == 1
    assert u["multi_attempt_groups"] == 1


def test_audit_catches_tampered_weights_and_reserve_order(tmp_path: Path, monkeypatch) -> None:
    _, _, manifest = frozen(tmp_path, monkeypatch)
    manifest["selected"][0]["weight"] += 0.5
    name = next(k for k, v in manifest["reserves"].items() if len(v) > 1)
    manifest["reserves"][name] = list(reversed(manifest["reserves"][name]))
    checks = sd.audit(queue(), manifest)["checks"]
    assert not checks["recorded_weights_match_exact"]
    assert not checks["reserves_in_rank_order"]


def test_design_rejects_duplicate_or_misallocated_items(tmp_path: Path, monkeypatch) -> None:
    _, _, manifest = frozen(tmp_path, monkeypatch)
    dup = json.loads(json.dumps(manifest))
    dup["selected"].append(dup["selected"][0])
    with pytest.raises(rs.ReviewSampleError):
        sd.design(dup)
    bad = json.loads(json.dumps(manifest))
    bad["strata_table"][0]["selected"] += 1
    with pytest.raises(rs.ReviewSampleError, match="inconsistent"):
        sd.design(bad)


def test_grouping_links_campaigns_that_span_strata() -> None:
    """Attempts of one campaign in different strata form one group; only one can be
    sampled, and the audit counts the group as multi-stratum."""
    packets = [*queue(), pkt(600, subtype="dust", victim=10_001, rival=True)]
    root = rs.groups(packets)
    assert root["0000000000000258"] == root["0000000000000001"]  # 600 and 1 share a victim
    m = rs.draw(packets, "q")["manifest"]
    a = sd.audit(packets, m)
    assert a["all_checks_pass"]
    assert a["units"]["multi_stratum_groups"] == 1


# --- allocation edge cases -------------------------------------------------------------------


def test_allocation_edge_cases() -> None:
    assert rs.allocate({("a",): 1, ("b",): 50}, 5) == {("a",): 1, ("b",): 4}  # single item
    assert rs.allocate({("a",): 2, ("b",): 3}, 9) == {("a",): 2, ("b",): 3}  # census
    assert rs.allocate({("a",): 0, ("b",): 10}, 3) == {("a",): 0, ("b",): 3}  # empty
    # Ties in the remainder are broken by the cell key, deterministically.
    assert rs.allocate({("a",): 10, ("b",): 10}, 3) == {("a",): 1, ("b",): 2}


# --- estimator -------------------------------------------------------------------------------


def two_strata(n_a: int = 4, n_b: int = 2) -> sd.Design:
    cells = {
        "x|2023|rival": sd.Cell("x|2023|rival", "x", 2023, True, 8, n_a, 8),
        "x|2024|rival": sd.Cell("x|2024|rival", "x", 2024, True, 2, n_b, 2),
    }
    items = {f"a{i}": "x|2023|rival" for i in range(n_a)} | {
        f"b{i}": "x|2024|rival" for i in range(n_b)
    }
    return sd.Design(cells, items, dict.fromkeys(items, 1), 10)


def test_stratified_estimate_weights_strata_by_population() -> None:
    d = two_strata()
    y = {"a0": True, "a1": True, "a2": False, "a3": False, "b0": True, "b1": True}
    est = sd.estimate(d, y)
    assert est["estimate"] == pytest.approx(0.8 * 0.5 + 0.2 * 1.0)
    assert est["unweighted"]["proportion"] == pytest.approx(4 / 6)  # differs: unequal weights
    # Only stratum A has sampling variance (B is a census): (N_a/N)^2 (1-n/N) s^2 / n.
    assert est["variance"] == pytest.approx(0.8**2 * (1 - 4 / 8) * (1 / 3) / 4)
    assert d.inclusion("a0") == Fraction(1, 2)
    assert d.weight("b0") == 1


def test_estimator_is_design_unbiased_by_enumeration() -> None:
    """Average the estimate over every possible stratified sample: it equals the true
    population proportion exactly."""
    pop_a = [True, True, True, False, False, True, False, False]  # 4/8
    pop_b = [True, False]  # census of 2
    truth = (sum(pop_a) + sum(pop_b)) / 10
    total, count = 0.0, 0
    d = two_strata()
    for pick in itertools.combinations(range(8), 4):
        y = {f"a{i}": pop_a[j] for i, j in enumerate(pick)} | {"b0": pop_b[0], "b1": pop_b[1]}
        total += sd.estimate(d, y)["estimate"]
        count += 1
    assert total / count == pytest.approx(truth)


def test_all_and_none_confirmed() -> None:
    d = two_strata()
    ids = list(d.item_cell)
    one = sd.estimate(d, dict.fromkeys(ids, True))
    zero = sd.estimate(d, dict.fromkeys(ids, False))
    assert one["estimate"] == 1.0 and zero["estimate"] == 0.0  # noqa: PT018
    lo, hi = one["wilson95_design"]
    assert hi == 1.0 and 0.5 < lo < 1.0  # noqa: PT018
    assert "Kish" in one["interval_basis"]  # zero variance: weighting effect only
    assert zero["wilson95_design"][0] == 0.0


def test_census_scope_has_no_sampling_error() -> None:
    d = two_strata()
    est = sd.estimate(d, {"b0": True, "b1": False}, scope=lambda c: c.year == 2024)
    assert est["census"] is True
    assert est["wilson95_design"] == (0.5, 0.5)


def test_nonresponse_gives_bounds_and_an_empty_stratum_gives_no_estimate() -> None:
    d = two_strata()
    y = {"a0": True, "a1": None, "a2": False, "a3": True, "b0": True, "b1": True}
    est = sd.estimate(d, y)
    assert est["missing"] == 1
    lo, hi = est["bounds_missing_as_false_true"]
    assert lo == pytest.approx(0.8 * 0.5 + 0.2) and hi == pytest.approx(0.8 * 0.75 + 0.2)  # noqa: PT018
    assert lo <= est["estimate"] <= hi
    none_b = sd.estimate(d, {"a0": True, "a1": True, "a2": False, "a3": True})
    assert none_b["estimate"] is None
    assert "no responses" in none_b["reason"]


def test_single_item_strata_are_collapsed_by_the_fixed_rule() -> None:
    cells = [
        sd.Cell("x|2023|rival", "x", 2023, True, 30, 5, 30),
        sd.Cell("x|2024|rival", "x", 2024, True, 10, 1, 10),
        sd.Cell("x|2022|no_rival", "x", 2022, False, 10, 1, 10),
        sd.Cell("y|2023|rival", "y", 2023, True, 5, 1, 5),
    ]
    responded = {c.name: c.selected for c in cells}
    g = sd.collapse_partners(cells, responded)
    assert g["x|2024|rival"] == g["x|2023|rival"]  # same rival status, nearest year
    assert g["x|2022|no_rival"] == g["x|2023|rival"]  # no same-rival partner: largest
    assert g["y|2023|rival"] == "y|2023|rival"  # no partner in its subtype
    d = sd.Design({c.name: c for c in cells}, {"y1": "y|2023|rival"}, {"y1": 1}, 55)
    est = sd.estimate(d, {"y1": True}, scope=lambda c: c.subtype == "y")
    assert est["variance"] is None
    assert "no stratum to pool" in est["variance_note"]


def test_reported_numbers_match_known_values() -> None:
    lo, _ = sd.wilson(1.0, 60)
    assert lo == pytest.approx(0.93983, abs=1e-5)  # protocol's unweighted 0.94
    lo24, _ = sd.wilson(1.0, 24)
    assert lo24 == pytest.approx(0.86202, abs=1e-5)
    assert sd.wilson(0.5, 0) is None
    assert sd.kish_deff([1, 1, 1]) == 1.0
    assert sd.attempt_bounds((0.9, 1.0), 1395, 1469) == pytest.approx((0.9 * 1395 / 1469, 1.0))
