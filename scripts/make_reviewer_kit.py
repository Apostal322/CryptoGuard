"""Build one reviewer's kit: three blinded folders, the guide and a reviewer-only copy of the tool.

Usage: uv run python scripts/make_reviewer_kit.py --reviewer A [--out data/ml/poisoning/outbox]

Writes <out>/reviewer-<R>/, <out>/reviewer-<R>.zip and a maintainer-only record
<out>/reviewer-<R>.record.json (folder -> cohort mapping, hashes), then checks the kit
(exit code 1 on any problem). Nothing is sent: the maintainer sends the zip. 0 RPC requests.

Folder names are neutral (set-1, set-2) and the code copy leaves out the reports, tests and
research docs, which describe how the items were chosen.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = {"set-1": "review-sample/1", "set-2": "hard-negative-candidates/1"}
TOP_LEVEL = {"README.md", "reviewer-guide.md", "cryptoguard", "training", *FOLDERS}
CODE_PATHS = ("src", "pyproject.toml", "uv.lock", ".python-version", "LICENSE")
CODE_TOP_LEVEL = {*CODE_PATHS, "README.md"}
SET_FILES = {"reviewer_sheet.jsonl", "evidence_packets.jsonl", "reviewer.json",
             "replacement_sheet.jsonl"}  # fmt: skip
TRAINING_FILES = {"reviewer_sheet.jsonl", "evidence_packets.jsonl", "reviewer.json",
                  "training_notes.md"}  # fmt: skip
INFO_KEYS = {"reviewer", "protocol", "selection_sha256", "sheet_sha256", "training"}
FORBIDDEN_NAMES = ("unblinding_key", "sample_manifest", ".sqlite", ".db", ".env", "submission.json")
DOC_PATHS = ("docs/ml/reviewer-guide.md", "docs/ml/reviewer-kit-readme.md")
# Words that would tell a reviewer where an item came from. Checked in the real folders only.
FORBIDDEN_WORDS = (b"tsuchiya", b"ptxphish", b"poison-hunter", b"payoff", b"hard-negative",
                   b"hard_negative", b"unblind", b"review-sample")  # fmt: skip
CODE_README = (
    "# CryptoGuard review tool\n\nThe local review tool only. See ../README.md for how to use it.\n"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_hashes() -> dict[str, dict[str, str]]:
    from cryptoguard.ml import review_sample as rs
    from cryptoguard.ml import training

    out = {"training": {"sheet": training.sheet_sha256(), "evidence": training.packets_sha256()}}
    for folder, cohort in FOLDERS.items():
        reg = rs.COHORTS[cohort]
        out[folder] = {"sheet": reg[rs.SHEET], "evidence": reg["evidence"]}
    return out


def check(kit: Path, reviewer: str, expected: Mapping[str, Mapping[str, str]]) -> list[str]:
    """Every problem that would make the kit unsafe or unusable; empty means it may be sent."""
    problems: list[str] = []
    top = {p.name for p in kit.iterdir()}
    if top != TOP_LEVEL:
        problems.append(f"top level is {sorted(top)}, expected {sorted(TOP_LEVEL)}")
    for path in kit.rglob("*"):
        rel = path.relative_to(kit).as_posix()
        if any(bad in path.name.lower() for bad in FORBIDDEN_NAMES):
            problems.append(f"forbidden file {rel}")
        if path.is_dir() and path.name in {"annotations", "data", "tests", ".venv"}:
            problems.append(f"forbidden folder {rel}")
    code = kit / "cryptoguard"
    if code.is_dir():
        extra = {p.name for p in code.iterdir()} - CODE_TOP_LEVEL
        if extra:
            problems.append(f"code copy has extra entries {sorted(extra)}")
        reports = [p.name for p in code.rglob("*.md") if p.name.startswith("ML")]
        if reports:
            problems.append(f"code copy has research reports {reports}")
    for folder, want in expected.items():
        d = kit / folder
        if not d.is_dir():
            problems.append(f"{folder}: missing")
            continue
        allowed = TRAINING_FILES if folder == "training" else SET_FILES
        names = {p.name for p in d.iterdir()}
        if names - allowed:
            problems.append(f"{folder}: unexpected files {sorted(names - allowed)}")
        for kind, name in (
            ("sheet", "reviewer_sheet.jsonl"),
            ("evidence", "evidence_packets.jsonl"),
        ):
            f = d / name
            if not f.is_file() or sha256(f) != want[kind]:
                problems.append(f"{folder}: {name} missing or not the registered bytes")
        info_path = d / "reviewer.json"
        info = json.loads(info_path.read_text(encoding="utf-8")) if info_path.is_file() else {}
        if info.get("reviewer") != reviewer:
            problems.append(f"{folder}: reviewer.json is not for reviewer {reviewer}")
        if set(info) - INFO_KEYS:
            problems.append(
                f"{folder}: reviewer.json has extra keys {sorted(set(info) - INFO_KEYS)}"
            )
        if folder != "training":
            for f in (p for p in d.iterdir() if p.is_file()):
                text = f.read_bytes().lower()
                hits = [w.decode() for w in FORBIDDEN_WORDS if w in text]
                if hits:
                    problems.append(f"{folder}/{f.name}: contains {hits}")
    return problems


def zip_problems(kit: Path, archive: Path) -> list[str]:
    with zipfile.ZipFile(archive) as z:
        zipped = {n.split("/", 1)[1] for n in z.namelist() if "/" in n and not n.endswith("/")}
    on_disk = {p.relative_to(kit).as_posix() for p in kit.rglob("*") if p.is_file()}
    return [] if zipped == on_disk else ["zip contents differ from the kit folder"]


def git(*args: str) -> bytes:
    return subprocess.run(  # noqa: S603 (our own fixed commands)
        ["git", *args],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout


def head_commit() -> str:
    """HEAD, refusing uncommitted changes in anything the kit copies."""
    dirty = git("status", "--porcelain", "--", *CODE_PATHS, *DOC_PATHS).decode()
    if dirty.strip():
        raise SystemExit(f"uncommitted changes in the kit's code or docs:\n{dirty}")
    return git("rev-parse", "HEAD").decode().strip()


def copy_code(dest: Path, commit: str) -> None:
    """Extract the committed code (never the working tree)."""
    tar = git("archive", "--format=tar", commit, "--", *CODE_PATHS)
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        t.extractall(dest, filter="data")
    (dest / "README.md").write_text(CODE_README, encoding="utf-8", newline="\n")


def build(reviewer: str, out: Path) -> Path:
    from cryptoguard.ml import training
    from cryptoguard.ml.cli import COHORT_DIRS, COHORT_WORK
    from cryptoguard.ml.unblind import make_package

    kit = out / f"reviewer-{reviewer}"
    if kit.exists():
        raise SystemExit(f"{kit} exists; a kit is built once per reviewer")
    commit = head_commit()
    kit.mkdir(parents=True)
    training.make_package(reviewer, kit / "training")
    for folder, cohort in FOLDERS.items():
        make_package(
            COHORT_DIRS[cohort], COHORT_WORK[cohort], reviewer, kit / folder, cohort=cohort
        )
    shutil.copyfile(ROOT / "docs/ml/reviewer-guide.md", kit / "reviewer-guide.md")
    shutil.copyfile(ROOT / "docs/ml/reviewer-kit-readme.md", kit / "README.md")
    copy_code(kit / "cryptoguard", commit)

    problems = check(kit, reviewer, expected_hashes())
    archive = out / f"reviewer-{reviewer}.zip"
    if not problems:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(kit.rglob("*")):
                if p.is_file():
                    z.write(p, f"{kit.name}/{p.relative_to(kit).as_posix()}")
        problems = zip_problems(kit, archive)
    if problems:
        print("\n".join(f"PROBLEM: {p}" for p in problems), file=sys.stderr)
        raise SystemExit(1)
    record = {
        "reviewer": reviewer,
        "commit": commit,
        "folders": {"training": "training/1", **FOLDERS},
        "zip_sha256": sha256(archive),
        "hashes": expected_hashes(),
        "sent": None,  # the maintainer fills this in by hand when the kit is sent
    }
    (out / f"reviewer-{reviewer}.record.json").write_text(
        json.dumps(record, indent=1) + "\n", encoding="utf-8"
    )
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reviewer", required=True, help="pseudonym, e.g. A")
    parser.add_argument("--out", type=Path, default=Path("data/ml/poisoning/outbox"))
    args = parser.parse_args()
    archive = build(args.reviewer, args.out)
    print(f"Kit for reviewer {args.reviewer}: {archive} (sha256 {sha256(archive)}); checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
