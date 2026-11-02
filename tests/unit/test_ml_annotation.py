"""Annotation schema, durable reviewer store and submission finalization (Phase 11.4).

Decisions here are synthetic test inputs, not labels.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptoguard.ml import annotation as an
from cryptoguard.ml.review import import_reviews
from tests.review_fixtures import ATTEMPT_FIELDS, INSUFFICIENT_FIELDS, fields

ITEMS = {1: "00000000000000a1", 2: "00000000000000a2", 3: "00000000000000a3"}
SAMPLE = {"selection_sha256": "s" * 64, "sheet_sha256": "h" * 64}


def store(tmp: Path, reviewer: str = "A") -> an.ReviewerStore:
    return an.ReviewerStore(tmp / reviewer, reviewer, ITEMS)


def complete(s: an.ReviewerStore) -> None:
    for item, e in ITEMS.items():
        s.save(fields(item, e))


# --- schema --------------------------------------------------------------------------------


def make(**over: object) -> an.Annotation:
    return an.Annotation.model_validate(
        {**fields(1, ITEMS[1]), "reviewer": "A", "revision": 1, "saved_at": "t", **over}
    )


def test_confirmed_needs_evidence_but_insufficient_does_not() -> None:
    make()
    make(**{k: v for k, v in INSUFFICIENT_FIELDS.items() if k != "rationale"}, rationale="x")
    for bad, match in (
        ({"prior_counterparty": "not_loaded", "prior_counterparty_address": None}, "imitated"),
        ({"matched_leading": None}, "matched"),
        ({"legitimate_explanation": "not_loaded"}, "legitimate explanation"),
        ({"planting_transfer": "not_available"}, "planting"),
        ({"rationale": "looks bad"}, "5 words"),
    ):
        with pytest.raises(ValueError, match=match):
            make(**bad)


def test_other_decisions_have_their_own_rules() -> None:
    with pytest.raises(ValueError, match="legitimate"):
        make(decision="confirmed_legitimate_interaction")
    with pytest.raises(ValueError, match="contradictory"):
        make(decision="conflicting_evidence")
    make(decision="conflicting_evidence", prior_counterparty="contradictory")
    with pytest.raises(ValueError, match="pseudonym"):
        make(reviewer="Dr. Real Name")
    with pytest.raises(ValueError, match="decision"):
        make(decision="probably_fine")


def test_missing_evidence_is_not_negative_evidence() -> None:
    """'likely' with unavailable counterparty data is allowed; it does not become
    'not observed' or a legitimate label."""
    a = make(
        decision="likely_poisoning_attempt",
        prior_counterparty="not_available",
        prior_counterparty_address=None,
        matched_leading=None,
        matched_trailing=None,
        legitimate_explanation="not_available",
    )
    assert a.prior_counterparty == "not_available"


def test_annotations_convert_to_the_existing_review_import(tmp_path: Path) -> None:
    a = make()
    path = tmp_path / "decisions.jsonl"
    path.write_text(a.to_review_decision().model_dump_json() + "\n", encoding="utf-8")
    history = import_reviews(path, {ITEMS[1]}, [])
    assert history[0].tier == "verified_attempt"
    assert history[0].source == "review:A"


# --- store ---------------------------------------------------------------------------------


def test_save_revise_and_resume(tmp_path: Path) -> None:
    with store(tmp_path) as s:
        first = s.save(fields(1, ITEMS[1]))
        second = s.save(fields(1, ITEMS[1], INSUFFICIENT_FIELDS), expected_revision=1)
    assert (first.revision, second.revision) == (1, 2)
    again = store(tmp_path)  # a new process
    assert again.latest()[1].decision == "insufficient_evidence"
    assert [a.revision for a in again.history(1)] == [1, 2]  # the original is kept


def test_duplicate_submit_is_idempotent_and_stale_edits_are_refused(tmp_path: Path) -> None:
    with store(tmp_path) as s:
        a = s.save(fields(1, ITEMS[1]))
        assert s.save(fields(1, ITEMS[1])) == a
        assert len(s.entries) == 1
        with pytest.raises(an.AnnotationError, match="reload"):
            s.save(fields(1, ITEMS[1], INSUFFICIENT_FIELDS), expected_revision=0)


def test_unknown_item_wrong_event_and_invalid_fields_are_rejected(tmp_path: Path) -> None:
    with store(tmp_path) as s:
        with pytest.raises(an.AnnotationError, match="unknown item"):
            s.save(fields(9, "0" * 16))
        with pytest.raises(an.AnnotationError, match="does not match"):
            s.save(fields(1, ITEMS[2]))
        with pytest.raises(an.AnnotationError, match="planting"):
            s.save({**fields(1, ITEMS[1]), "planting_transfer": "not_loaded"})
        assert s.entries == []


def test_the_store_must_be_locked_to_write_and_only_once(tmp_path: Path) -> None:
    s = store(tmp_path)
    with pytest.raises(an.AnnotationError, match="with"):
        s.save(fields(1, ITEMS[1]))
    with s, pytest.raises(an.AnnotationError, match="another review session"), store(tmp_path):
        pass


def test_a_failed_disk_write_changes_nothing(tmp_path: Path, monkeypatch) -> None:
    with store(tmp_path) as s:
        s.save(fields(1, ITEMS[1]))
        before = (tmp_path / "A" / an.LOG).read_bytes()

        def full_disk(*_: object) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(an.os, "replace", full_disk)
        with pytest.raises(OSError, match="No space"):
            s.save(fields(2, ITEMS[2]))
        assert len(s.entries) == 1
    assert (tmp_path / "A" / an.LOG).read_bytes() == before


def test_an_interrupted_save_leaves_the_log_intact(tmp_path: Path) -> None:
    with store(tmp_path) as s:
        s.save(fields(1, ITEMS[1]))
    (tmp_path / "A" / (an.LOG + ".tmp")).write_bytes(b'{"half a reco')
    s2 = store(tmp_path)
    assert len(s2.entries) == 1
    assert not (tmp_path / "A" / (an.LOG + ".tmp")).exists()


@pytest.mark.parametrize("edit", ["flip", "truncate", "drop_first", "other_reviewer"])
def test_tampering_breaks_the_hash_chain(tmp_path: Path, edit: str) -> None:
    with store(tmp_path) as s:
        s.save(fields(1, ITEMS[1]))
        s.save(fields(2, ITEMS[2]))
    log = tmp_path / "A" / an.LOG
    lines = log.read_text(encoding="utf-8").splitlines()
    if edit == "flip":
        lines[0] = lines[0].replace("confirmed_poisoning_attempt", "likely_poisoning_attempt")
    elif edit == "truncate":
        lines[1] = lines[1][:40]
    elif edit == "drop_first":
        lines = lines[1:]
    else:
        lines[0] = lines[0].replace('"reviewer":"A"', '"reviewer":"B"')
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(an.StoreCorruptError):
        store(tmp_path)


# --- finalization ----------------------------------------------------------------------------


def test_finalize_needs_every_item_then_freezes(tmp_path: Path) -> None:
    with store(tmp_path) as s:
        s.save(fields(1, ITEMS[1]))
        with pytest.raises(an.AnnotationError, match="2 item"):
            s.finalize(SAMPLE)
        s.save(fields(2, ITEMS[2]))
        s.save(fields(3, ITEMS[3], INSUFFICIENT_FIELDS))
        sub = s.finalize(SAMPLE)
        with pytest.raises(an.FinalizedError):
            s.save(fields(1, ITEMS[1], INSUFFICIENT_FIELDS))
        with pytest.raises(an.FinalizedError):
            s.finalize(SAMPLE)
    loaded = an.load_submission(tmp_path / "A" / an.SUBMISSION)
    assert loaded == sub
    assert [a.item for a in loaded.decisions] == [1, 2, 3]
    assert store(tmp_path).finalized  # survives a restart


def test_edited_submissions_are_detected(tmp_path: Path) -> None:
    with store(tmp_path) as s:
        complete(s)
        s.finalize(SAMPLE)
    path = tmp_path / "A" / an.SUBMISSION
    body = json.loads(path.read_text(encoding="utf-8"))
    body["decisions"][0]["decision"] = "likely_poisoning_attempt"
    path.write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(an.StoreCorruptError, match="edited"):
        an.load_submission(path)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(an.StoreCorruptError):
        an.load_submission(path)


def test_reviewers_have_separate_stores(tmp_path: Path) -> None:
    with store(tmp_path, "A") as a, store(tmp_path, "B") as b:
        a.save(fields(1, ITEMS[1]))
        b.save(fields(1, ITEMS[1], INSUFFICIENT_FIELDS))
    assert store(tmp_path, "A").latest()[1].reviewer == "A"
    assert store(tmp_path, "B").latest()[1].decision == "insufficient_evidence"
    with pytest.raises(an.StoreCorruptError, match="reviewer"):
        an.ReviewerStore(tmp_path / "A", "B", ITEMS)  # B cannot open A's log as its own


def test_attempt_fields_fixture_is_valid() -> None:
    assert ATTEMPT_FIELDS["decision"] in an.ATTEMPT
