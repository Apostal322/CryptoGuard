"""Public-repository safety scan (protocol 12.8, section 14). The repository is public, so
tracked files and history must hold no credentials, no restricted research data and no
review answer keys.

Only file names and counts are ever returned: a matched value is never included, so the
scan cannot itself leak a secret into a log or a report. Patterns here are the
high-confidence ones (provider tokens, private-key blocks, keyed RPC URLs); a broader
manual review is recorded in the Phase 12.8 report.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "provider_api_key": re.compile(r"sk-(ant-)?[A-Za-z0-9_-]{32,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "keyed_rpc_url": re.compile(
        r"https://[a-z0-9.-]*(alchemy|infura|quiknode|ankr|blastapi|chainstack|getblock|nodereal)"
        r"[a-z0-9.-]*/[A-Za-z0-9_/-]*[A-Za-z0-9]{24,}"
    ),
}
SENSITIVE_NAME = re.compile(
    r"(?i)unblinding|answer_key|(^|/)\.env$|\.pem$|id_rsa|credential|(^|/)ledger[^/]*\.json$"
)
RESTRICTED_PREFIXES = ("data/",)  # local research data: never tracked
USER_PATH = re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]+")
MAX_TRACKED_BYTES = 4 * 1024 * 1024


def _git(root: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout


def scan_text(text: str) -> dict[str, int]:
    """Pattern name -> number of matches. Never returns the matched text."""
    out = {name: len(p.findall(text)) for name, p in SECRET_PATTERNS.items()}
    return {k: v for k, v in out.items() if v}


def scan(root: Path, *, history: bool = False) -> dict[str, Any]:
    """Tracked-file (and optionally history) findings, as names and counts only. Returns
    ``{"available": False}`` outside a git checkout."""
    listing = _git(root, "ls-files")
    if listing is None:
        return {"available": False}
    tracked = [f for f in listing.splitlines() if f]
    secrets: dict[str, dict[str, int]] = {}
    user_paths: dict[str, int] = {}
    large: list[str] = []
    for rel in tracked:
        path = root / rel
        try:
            if path.stat().st_size > MAX_TRACKED_BYTES:
                large.append(rel)
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = scan_text(text)
        if hits:
            secrets[rel] = hits
        n = len(USER_PATH.findall(text))
        if n:
            user_paths[rel] = n
    out: dict[str, Any] = {
        "available": True,
        "tracked_files": len(tracked),
        "secret_pattern_files": secrets,
        "sensitive_names": sorted(f for f in tracked if SENSITIVE_NAME.search(f)),
        "restricted_paths_tracked": sorted(f for f in tracked if f.startswith(RESTRICTED_PREFIXES)),
        "local_user_paths": user_paths,
        "oversized_files": large,
    }
    if history:
        added = _git(root, "log", "--all", "--diff-filter=A", "--name-only", "--format=") or ""
        names = {line for line in added.splitlines() if line}
        patch = _git(root, "log", "--all", "-p", "--format=", "--unified=0") or ""
        hist: dict[str, int] = {}
        for line in patch.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                for name, n in scan_text(line).items():
                    hist[name] = hist.get(name, 0) + n
        commits = (_git(root, "rev-list", "--all", "--count") or "0").strip()
        out["history"] = {
            "commits": int(commits or 0),
            "paths_ever_added": len(names),
            "sensitive_names_ever_added": sorted(f for f in names if SENSITIVE_NAME.search(f)),
            "restricted_paths_ever_added": sorted(
                f for f in names if f.startswith(RESTRICTED_PREFIXES)
            ),
            "secret_pattern_hits": hist,
        }
    out["clean"] = not (
        secrets
        or out["sensitive_names"]
        or out["restricted_paths_tracked"]
        or large
        or (history and (out["history"]["secret_pattern_hits"]
                         or out["history"]["sensitive_names_ever_added"]
                         or out["history"]["restricted_paths_ever_added"]))
    )  # fmt: skip
    return out


def restricted_identifier_overlap(root: Path, restricted: frozenset[str]) -> dict[str, int]:
    """Tracked file -> how many restricted identifiers (addresses or hashes from local,
    non-redistributable sources) it contains. Counts only."""
    listing = _git(root, "ls-files")
    if listing is None:
        return {}
    hexes = re.compile(r"0x[0-9a-fA-F]{64}|0x[0-9a-fA-F]{40}")
    out: dict[str, int] = {}
    for rel in (f for f in listing.splitlines() if f):
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        n = len({m.lower() for m in hexes.findall(text)} & restricted)
        if n:
            out[rel] = n
    return out
