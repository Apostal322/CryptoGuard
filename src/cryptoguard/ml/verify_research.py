"""Offline reproducibility check of the poisoning research inputs (``cryptoguard ml
verify-research``, Phase 11.7).

It fetches nothing and regenerates nothing. Every check is reported as:
- ``PASS``;
- ``FAIL``: a file is present but wrong;
- ``MISSING``: a file is absent;
- ``BLOCKED``: waiting on an external dependency, such as human reviews.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

VERIFY_VERSION = "verify-research/1"


def _check(name: str, fn: Callable[[], tuple[str, str]]) -> dict[str, str]:
    try:
        status, detail = fn()
    except FileNotFoundError as exc:
        status, detail = "MISSING", str(exc)
    except Exception as exc:  # a check must report, never abort the whole verification
        status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
    return {"check": name, "status": status, "detail": detail}


def verify(data_dir: Path, ml_dir: Path, *, hash_archive: bool = True) -> dict[str, Any]:
    from cryptoguard.ml import review_sample as rs
    from cryptoguard.ml.annotation import PROTOCOL
    from cryptoguard.ml.candidates import CANDIDATE_VERSION, EVENT_FEATURE_VERSION
    from cryptoguard.ml.cross_dataset import git_state
    from cryptoguard.ml.evidence import EVIDENCE_VERSION, PACKETS
    from cryptoguard.ml.experiment_spec import SPEC_VERSION
    from cryptoguard.ml.fetch import TSUCHIYA_FILES, digests
    from cryptoguard.ml.label_policy import POLICY_VERSION
    from cryptoguard.ml.reconcile import RECONCILE_VERSION
    from cryptoguard.ml.sources import SOURCES, sha256_file
    from cryptoguard.ml.tsuchiya_archive import PARSER_VERSION

    poisoning = ml_dir / "poisoning"
    checks: list[dict[str, str]] = []

    for name, pinned in TSUCHIYA_FILES.items():
        path = data_dir / "tsuchiya2025" / name

        def tsuchiya(path: Path = path, pinned: Any = pinned) -> tuple[str, str]:
            if not path.exists():
                raise FileNotFoundError(f"{path} (never downloaded automatically)")
            if path.stat().st_size != pinned.size:
                return "FAIL", f"size {path.stat().st_size} != pinned {pinned.size}"
            if path.stat().st_size > 100 << 20 and not hash_archive:
                return "PASS", "size matches (hash skipped on request)"
            _, sha = digests(path)
            ok = pinned.sha256 is None or sha == pinned.sha256
            return ("PASS" if ok else "FAIL"), f"sha256 {sha[:16]}"

        checks.append(_check(f"source {name}", tsuchiya))
    for source in SOURCES.values():
        for f in source.files:
            path = data_dir / source.name / f.path

            def pinned_file(path: Path = path, f: Any = f) -> tuple[str, str]:
                if not path.exists():
                    raise FileNotFoundError(str(path))
                sha = sha256_file(path)
                return ("PASS" if sha == f.sha256 else "FAIL"), f"sha256 {sha[:16]}"

            checks.append(_check(f"source {source.name}/{f.path}", pinned_file))

    def subset_check(name: str) -> Callable[[], tuple[str, str]]:
        def check() -> tuple[str, str]:
            path = poisoning / name
            if not path.exists():
                raise FileNotFoundError(str(path))
            con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            try:
                meta = dict(con.execute("SELECT key, value FROM meta").fetchall())
            finally:
                con.close()
            summary = json.loads(meta["summary"])
            pinned = TSUCHIYA_FILES["address_poisoning_ethereum.sql.gz"].sha256
            ok = (
                meta.get("complete") == "1"
                and meta.get("parser_version") == PARSER_VERSION
                and summary.get("source_sha256") == pinned
            )
            return ("PASS" if ok else "FAIL"), f"{summary['stored_target_rows']:,} stored rows"

        return check

    for name in (
        "archive_subset.sqlite",
        "hard_negative/context_subset.sqlite",
        "review/review_context.sqlite",
    ):
        checks.append(_check(f"derived {name}", subset_check(name)))

    def extract() -> tuple[str, str]:
        from cryptoguard.ml.hard_negative_archive import load_rows

        rows = load_rows(poisoning / "hard_negative")
        return "PASS", f"{len(rows):,} uncategorized rows, hash matches its summary"

    checks.append(_check("derived uncategorized rows", extract))

    for cohort, hashes in rs.COHORTS.items():
        sample = poisoning / (
            "review_sample" if cohort == rs.SAMPLE_VERSION else "hard_negative/cohort_v1"
        )
        work = poisoning / ("review" if cohort == rs.SAMPLE_VERSION else "hard_negative/review")

        def frozen(sample: Path = sample, cohort: str = cohort) -> tuple[str, str]:
            if not (sample / rs.MANIFEST).exists():
                raise FileNotFoundError(f"{sample} (frozen files are local, never committed)")
            m = rs.verify_frozen(sample, cohort=cohort)
            return "PASS", f"{len(m['selected'])} items, selection {m['selection_sha256'][:12]}"

        def packets(work: Path = work, hashes: dict[str, str] = hashes) -> tuple[str, str]:
            path = work / "evidence" / PACKETS
            if "evidence" not in hashes:
                return "BLOCKED", "no evidence packets registered"
            if not path.exists():
                raise FileNotFoundError(f"{path} (rebuild with `ml review build-evidence`)")
            sha = sha256_file(path)
            return ("PASS" if sha == hashes["evidence"] else "FAIL"), f"sha256 {sha[:16]}"

        def reviews(work: Path = work) -> tuple[str, str]:
            subs = [
                p
                for p in poisoning.rglob("submission.json")
                if "review" in p.parts or "hard_negative" in p.parts
            ]
            return ("BLOCKED" if not subs else "PASS"), f"{len(subs)} finalized submission(s)"

        checks += [
            _check(f"frozen cohort {cohort}", frozen),
            _check(f"evidence packets {cohort}", packets),
            _check(f"human review {cohort}", reviews),
        ]
    checks.append(
        {
            "check": "experiment activation",
            "status": "BLOCKED",
            "detail": f"{SPEC_VERSION} inactive: no reviewed labels",
        }
    )
    return {
        "version": VERIFY_VERSION,
        "git": git_state(),
        "versions": {
            "parser": PARSER_VERSION,
            "reconcile": RECONCILE_VERSION,
            "candidates": CANDIDATE_VERSION,
            "event_features": EVENT_FEATURE_VERSION,
            "evidence": EVIDENCE_VERSION,
            "protocol": PROTOCOL,
            "label_policy": POLICY_VERSION,
            "experiment_spec": SPEC_VERSION,
        },
        "checks": checks,
        "summary": {
            s: sum(c["status"] == s for c in checks) for s in ("PASS", "FAIL", "MISSING", "BLOCKED")
        },
        "limitations": [
            "hashes prove the files are unchanged, not that their contents are correct",
            "derived files are checked against their own summaries; re-derivation needs the "
            "archive passes (about 50 minutes each)",
        ],
        "rpc_requests": 0,
    }
