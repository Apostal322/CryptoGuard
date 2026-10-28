# Releasing

Nothing here has been done yet: the repository has no remote, and publishing needs the
maintainer's explicit go-ahead.

## Suggested GitHub metadata

- **Description:** Read-only, explainable Ethereum wallet security: approvals, EIP-7702
  delegation, address-poisoning detection, security timeline and point-in-time incident replay.
- **Topics:** `ethereum`, `wallet-security`, `address-poisoning`, `blockchain-security`,
  `erc20`, `eip-7702`, `threat-intelligence`, `read-only`, `fastapi`, `react`

## Checklist

1. Create the (private first) GitHub repository and add it as `origin`:
   `git remote add origin git@github.com:<owner>/cryptoguard.git`
2. Pin every action in `.github/workflows/ci.yml` to a full commit SHA (keep the version as
   a comment), then confirm `uvx zizmor --offline .github/workflows/ci.yml` reports no
   `unpinned-uses`. Dependabot keeps the pins current.
3. Push `main` and wait for every CI job (backend and frontend on Windows and Ubuntu, browser
   e2e, package, audit) to pass. Fix anything Linux-specific before going further.
4. Enable branch protection on `main` (required checks, no force pushes) and private
   vulnerability reporting (SECURITY.md points to it).
5. Update RELEASE_CANDIDATE_REPORT.md with the CI run link, then tag:
   `git tag -a v0.1.0 -m "CryptoGuard 0.1.0 (pre-release)"` and push the tag.
6. Create a GitHub **pre-release** from the tag with RELEASE_NOTES.md as the body; attach
   the wheel and sdist from the `package` job (or `uv build`), plus their SHA-256 sums.
7. Publishing to PyPI is optional and separate; do it only with a trusted-publisher setup.

## Verifying a build locally

```powershell
.\scripts\check.ps1                       # everything CI runs (Windows)
uv build; uv run python scripts/inspect_dist.py dist
```
