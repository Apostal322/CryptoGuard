# Release candidate report — CryptoGuard 0.1.0

Validation of `89f1de5` plus the phase 10.1 changes, on 2026-10-28. Environment: Windows 11
Pro, Intel i5 (4 cores), 8 GB RAM; Python 3.12.15 (uv), Node.js 24.15.0, npm 11.12.1,
Playwright 1.64.1 with Chromium. The repository has no remote: **nothing ran on GitHub**.

## Decision: CONDITIONALLY READY

Every local check passes and no known P0/P1 defect remains open. Two material validations
have not been possible here: a **GitHub-hosted CI run** and **any execution on Linux**. Both
need the repository to be pushed (not authorized yet). Until the first CI run is green on
Ubuntu and Windows, publish nothing beyond a private repository.

## Matrix

| Area | Status | Method | Evidence | Remaining issue |
|---|---|---|---|---|
| Backend tests | VERIFIED | `pytest` (full suite) | 402 passed, 4 deselected (`live`), 0 failed; ruff, ruff format, mypy clean | Earlier in the session one run had a flaky lease test (fixed, item 21 in RELEASE_AUDIT.md) |
| Frontend tests | VERIFIED | `vitest`, `tsc`, `vite build` | 52 passed (8 files); typecheck and production build clean | — |
| Browser E2E | VERIFIED (Windows) | Playwright, headless Chromium, real backend + production build, fictional test chain | 25 passed, 1 skipped (opt-in screenshot refresh), 160 s | Under heavy CPU contention from another workload, 1–4 tests timed out (15 s waits); all pass when the machine is not saturated. Not run on Linux. |
| API security | VERIFIED | pytest boundary suite + browser tests | Host allow-list, Origin check, JSON-only POST (415), CSRF from a hostile page has no effect, no secrets in bundle/page/console, malformed input 4xx without traces | No authentication by design (single local user) |
| Ethereum correctness | PARTIALLY VERIFIED | Fixtures, fake-node tests, on-chain receipt checks (phase 10) | Reverted payments never loss evidence; unknown receipt stays unknown; nonce search edge cases | Native ETH received, internal transfers, funding sources: not visible over JSON-RPC (documented) |
| Historical replay | VERIFIED | `replay run`, regression tests | Leads 367 / 42 / 113 / 13,057 blocks; leakage checks pass; regenerated EVALUATION.md identical apart from timings and timestamps | 4 cases: no rate estimate possible |
| Campaign analysis | VERIFIED (as experimental) | `campaigns evaluate`, unit/integration/E2E tests | Regenerated CAMPAIGN_EVALUATION.md identical apart from timings; UI never claims common ownership | No ground truth for attribution |
| Shadow-mode isolation | VERIFIED | API tests + E2E journey 5 | Identical findings with campaign/analytics off vs shadow; experimental sections absent by default | — |
| Database migration | VERIFIED (SQLite) | Upgrade from the captured `7fe824a` schema, idempotence, downgrade, mismatch refusal, interrupted migration | 6 tests pass; interrupted migration now rolls back (defect found and fixed) | PostgreSQL not tested (no server available) |
| Lease concurrency | VERIFIED (SQLite) | Real OS processes (6 contenders), crash recovery, fencing, overrun, per-wallet independence | 5 process-level tests + API tests pass | PostgreSQL semantics reasoned, not tested. Fixed 15 min lease kept: measured snapshots take < 1 s (fixture) to about 30 s (real chain, phase 7), far below it |
| Dependency review | VERIFIED (phase 10) | pip-audit (39 packages), npm audit | 0 known vulnerabilities; `npm install` of Playwright reported 0 | Re-run in CI on every push |
| Packaging | VERIFIED | `uv build` + `scripts/inspect_dist.py` | Wheel 117 files, sdist 229 files; required data present; no env files, databases, caches, tests or secrets in the wheel | — |
| Clean installation | VERIFIED (Windows) | Throwaway venv outside the repo | Core install (no NumPy) runs CLI, replay (same leads), `serve --demo` (ready in 12 s, health 5 ms, demo snapshot 445 ms, 415 for text/plain); `[analytics]` extra reproduces both evaluation reports | Not run on Linux |
| Windows | VERIFIED | Everything above | `scripts/check.ps1`: all steps except the E2E step, whose failures were under CPU contention; the E2E suite then passed in full | — |
| Linux | BLOCKED | — | `scripts/check.sh` and the CI matrix exist | No Linux environment; installing WSL or containers was not authorized |
| GitHub-hosted CI | BLOCKED | Schema validation + zizmor | Workflow and Dependabot config are schema-valid; zizmor: 12 `unpinned-uses` (tag-pinned actions), nothing else | Needs a remote and a push; pin actions to SHAs first (docs/RELEASING.md) |
| Documentation | VERIFIED | Newcomer review against the code; link check | README quick start, troubleshooting, E2E instructions; SECURITY, ARCHITECTURE, CHANGELOG, RELEASE_NOTES, RELEASING, screenshots labelled as fixture data | Linux commands marked unverified |
| Release artifacts | PARTIALLY VERIFIED | Inspection | Version 0.1.0, MIT license in both artifacts, release notes, checklist | Not tagged or published (not authorized) |

## Performance (Windows, bounded workloads, one at a time)

| Workload | Time | Peak memory |
|---|---|---|
| `replay run` (4 incidents) | 5.1 s | 65 MiB |
| `replay run --analytics --no-scaling` (13 subjects) | 23.7 s | 176 MiB |
| `campaigns evaluate` | 8.2 s | 140 MiB |
| API health (installed wheel, demo) | 5 ms average | — |
| Demo snapshot via API | 445 ms | — |
| Backend start (`serve --demo`, cold) | 12.4 s to first health response | — |
| Frontend production build | about 2–6 s | — |
| Backend test suite | 76–320 s (varies with machine load) | — |
| Browser E2E suite | 160 s (6 servers + Chromium) | — |

Measured with `scripts/peak_memory.py` (Windows PeakWorkingSetSize). Timings vary by up to
4× with other workloads on this machine; no performance claims are made beyond these numbers.
RPC request counts for real-chain operations are in EVALUATION.md and CAMPAIGN_EVALUATION.md.

## Defects found and fixed in this validation

See RELEASE_AUDIT.md items 15–21: non-transactional SQLite DDL in migrations, a superseded
finding labelled "resolved", a misleading "no change" line above new findings, a
contradictory campaign warning, mobile overflow, stale and garbled UI text, a flaky test.

## Next action

Authorize creating a **private** GitHub repository and pushing `main`; pin the actions to
commit SHAs; let CI run on Ubuntu and Windows; fix anything Linux-specific; then update
this report and tag `v0.1.0` as a pre-release (docs/RELEASING.md).
