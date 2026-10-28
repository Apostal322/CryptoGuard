# Releasing

The repository is `Apostal322/CryptoGuard` on GitHub, **private**. Making it public is a
separate decision of the maintainer. Nothing is published to PyPI, npm or a container
registry.

## Repository metadata

Set on GitHub:

- **Description:** Read-only Ethereum wallet security monitoring: explainable findings for
  approvals, EIP-7702 delegation and address poisoning, with a security timeline and
  reproducible point-in-time incident replay.
- **Topics:** `ethereum`, `blockchain`, `security`, `cybersecurity`, `wallet-security`,
  `address-poisoning`, `fraud-detection`, `eip-7702`, `graph-analysis`, `python`, `fastapi`,
  `react`

Repository security settings (2026-10-28): Dependabot alerts enabled; Dependabot version
updates via `.github/dependabot.yml`; Actions default token read-only and unable to approve
pull requests. Not available on this plan for a private repository, and not purchased:
branch protection and rulesets ("Upgrade to GitHub Pro or make this repository public"),
secret scanning and push protection, private vulnerability reporting. Revisit them if the
repository is made public, where they are free.

## How CI relates to a release

`.github/workflows/ci.yml` runs on every push to `main` and on pull requests: backend
(Windows and Ubuntu, Python 3.12; Ubuntu also 3.13), frontend (Windows and Ubuntu), browser
E2E (Ubuntu, Chromium), packaging (Windows and Ubuntu: build, inspect, clean install of the
core package and of the `analytics` extra, smoke test outside the checkout) and a dependency
audit. Every action is pinned to a full commit SHA; `zizmor` (auditor persona) reports no
findings.

Tags do **not** trigger CI. A release tag must point at a `main` commit whose complete CI
run passed, and the release assets are the `dist` artifact of that run's Ubuntu package
job, which uses no dependency cache.

## Checklist

1. On a clean `main`, run `uvx zizmor --offline --persona=auditor .github/` (no findings).
2. Push `main` and wait for every job of the CI run to succeed. A skipped or cancelled job
   is not a pass.
3. Update RELEASE_CANDIDATE_REPORT.md with the run link, commit and job results; commit,
   push and wait for that commit's run to pass too.
4. Tag that exact commit: `git tag -a v0.1.0 -m "CryptoGuard 0.1.0 (pre-release)"`, then
   `git push origin v0.1.0`. Never move a published tag; fix forward with a new version.
5. Download the run's `dist` artifact; check that the wheel and sdist pass
   `python scripts/inspect_dist.py <dir>`, and record their SHA-256 sums.
6. Create a GitHub **pre-release** for the tag with RELEASE_NOTES.md as the body, attaching
   the wheel, the sdist and `SHA256SUMS.txt`.
7. Check the release page: tag commit, assets downloadable, repository still private.

## Verifying a build locally

```powershell
.\scripts\check.ps1                       # everything CI runs (Windows)
uv build; uv run --no-project python scripts/inspect_dist.py dist
uv venv $env:TEMP\cg; uv pip install --python $env:TEMP\cg (Get-Item dist\*.whl)
uv run --no-project python scripts/smoke_install.py --venv $env:TEMP\cg
```
