"""The reviewer-kit check refuses anything that would unblind a reviewer or leak data."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "make_reviewer_kit.py"


@pytest.fixture(scope="module")
def kit_mod() -> ModuleType:
    spec = importlib.util.spec_from_file_location("make_reviewer_kit", SCRIPT)
    assert spec
    assert spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _kit(root: Path) -> tuple[Path, dict[str, dict[str, str]]]:
    kit = root / "reviewer-A"
    expected: dict[str, dict[str, str]] = {}
    for folder in ("training", "set-1", "set-2"):
        d = kit / folder
        d.mkdir(parents=True)
        sheet, packets = f"sheet {folder}\n".encode(), f"packets {folder}\n".encode()
        (d / "reviewer_sheet.jsonl").write_bytes(sheet)
        (d / "evidence_packets.jsonl").write_bytes(packets)
        (d / "reviewer.json").write_text(json.dumps({"reviewer": "A", "protocol": "p"}))
        expected[folder] = {"sheet": hashlib.sha256(sheet).hexdigest(),
                            "evidence": hashlib.sha256(packets).hexdigest()}  # fmt: skip
    (kit / "training" / "training_notes.md").write_text("# notes; payoff is fine here\n")
    code = kit / "cryptoguard"
    (code / "src" / "cryptoguard").mkdir(parents=True)
    (code / "src" / "cryptoguard" / "submissions.py").write_text("")
    for name in ("pyproject.toml", "uv.lock", ".python-version", "LICENSE", "README.md"):
        (code / name).write_text("")
    (kit / "README.md").write_text("")
    (kit / "reviewer-guide.md").write_text("")
    return kit, expected


def test_clean_kit_passes(kit_mod: ModuleType, tmp_path: Path) -> None:
    kit, expected = _kit(tmp_path)
    assert kit_mod.check(kit, "A", expected) == []


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda k: (k / "set-1" / "unblinding_key.jsonl").write_text("{}"), "unblinding_key"),
        (lambda k: (k / "set-2" / "sample_manifest.json").write_text("{}"), "sample_manifest"),
        (lambda k: (k / "cryptoguard" / "ML_REPORT.md").write_text(""), "ML_REPORT.md"),
        (lambda k: (k / "cryptoguard" / "tests").mkdir(), "tests"),
        (lambda k: (k / "set-1" / "annotations").mkdir(), "annotations"),
        (lambda k: (k / "set-2" / "reviewer_sheet.jsonl").write_text("x"), "registered bytes"),
        (lambda k: (k / "set-1" / "reviewer.json").write_text('{"reviewer": "B"}'), "reviewer A"),
        (
            lambda k: (k / "set-1" / "reviewer.json").write_text('{"reviewer": "A", "cohort": 1}'),
            "extra keys",
        ),
        (
            lambda k: (k / "set-2" / "replacement_sheet.jsonl").write_text("Tsuchiya row"),
            "tsuchiya",
        ),
        (lambda k: (k / "notes.txt").write_text(""), "top level"),
    ],
)
def test_check_refuses(kit_mod: ModuleType, tmp_path: Path, mutate: object, needle: str) -> None:
    kit, expected = _kit(tmp_path)
    mutate(kit)  # type: ignore[operator]
    problems = kit_mod.check(kit, "A", expected)
    assert any(needle in p for p in problems), problems


def test_expected_hashes_are_the_registered_ones(kit_mod: ModuleType) -> None:
    from cryptoguard.ml import review_sample as rs
    from cryptoguard.ml import training

    want = kit_mod.expected_hashes()
    assert want["training"] == {
        "sheet": training.sheet_sha256(),
        "evidence": training.packets_sha256(),
    }
    for folder, cohort in kit_mod.FOLDERS.items():
        reg = rs.COHORTS[cohort]
        assert want[folder] == {"sheet": reg[rs.SHEET], "evidence": reg["evidence"]}
    assert kit_mod.FOLDERS == {"set-1": rs.SAMPLE_VERSION, "set-2": "hard-negative-candidates/1"}
