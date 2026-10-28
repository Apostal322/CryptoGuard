"""Inspect built release artifacts: required runtime data present, nothing private shipped.

Usage: python scripts/inspect_dist.py dist   (exit code 1 on any problem)
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

REQUIRED_IN_WHEEL = [
    "cryptoguard/replay/cases/wbtc-1155-poisoning-2024-05-03/fixture.json",
    "cryptoguard/replay/cases/wbtc-1155-poisoning-2024-05-03/manifest.json",
    "cryptoguard/replay/background_cases/__init__.py",
    "cryptoguard/replay/campaign_cases/expansion.json",
    "cryptoguard/database/migrations.py",
]
FORBIDDEN = (
    ".env",
    ".db",
    ".sqlite",
    "/.venv/",
    "node_modules/",
    "__pycache__/",
    ".pyc",
    "/data/",
    ".claude/",
    "e2e-results/",
    "e2e-report/",
    ".mypy_cache",
    ".ruff_cache",
)
FORBIDDEN_TEXT = (b"BEGIN RSA PRIVATE KEY", b"BEGIN OPENSSH PRIVATE KEY", b"mnemonic=")


def forbidden(name: str) -> bool:
    if name.endswith(".env.example"):
        return False
    return any(part in name or name.endswith(part) for part in FORBIDDEN)


def tracked_files() -> set[str] | None:
    """Files git tracks here, or None outside a git checkout (e.g. an unpacked sdist)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],  # noqa: S607
            capture_output=True,
            check=True,
            cwd=Path(__file__).resolve().parent.parent,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return {name for name in out.decode().split("\0") if name}


def main(directory: str) -> int:
    dist = Path(directory)
    problems: list[str] = []
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        problems.append(f"expected one wheel and one sdist, found {wheels} {sdists}")
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as z:
            names = z.namelist()
            problems += [f"wheel: missing {r}" for r in REQUIRED_IN_WHEEL if r not in names]
            problems += [f"wheel: forbidden {n}" for n in names if forbidden(n)]
            problems += [f"wheel: tests shipped {n}" for n in names if n.startswith("tests/")]
            for n in names:
                if any(t in z.read(n) for t in FORBIDDEN_TEXT):
                    problems.append(f"wheel: secret-looking content in {n}")
            print(f"{wheel.name}: {len(names)} files")
    for sdist in sdists:
        with tarfile.open(sdist) as t:
            names = t.getnames()
            problems += [f"sdist: forbidden {n}" for n in names if forbidden(n)]
            if not any(n.endswith("/LICENSE") for n in names):
                problems.append("sdist: LICENSE missing")
            # Anything that is not a tracked file (an untracked local file hidden only by a
            # global excludes file, say) must not ship.
            tracked = tracked_files()
            if tracked is not None:
                files = {m.name.split("/", 1)[1] for m in t.getmembers() if m.isfile()}
                problems += [
                    f"sdist: untracked file {n}" for n in sorted(files - tracked) if n != "PKG-INFO"
                ]
            print(f"{sdist.name}: {len(names)} files")
    for p in problems:
        print("PROBLEM:", p)
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "dist"))
