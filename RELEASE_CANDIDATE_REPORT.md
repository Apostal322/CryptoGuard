# Release candidate report — CryptoGuard 0.1.0

Validation on 2026-10-28 in the private repository
[`Apostal322/CryptoGuard`](https://github.com/Apostal322/CryptoGuard) with GitHub-hosted
runners (`ubuntu-latest`, `windows-latest`), plus local checks on Windows 11 (Intel i5, 4
cores, 8 GB RAM, shared with other workloads). Not an independent audit.

## Decision

Every required CI job passes on Windows and Ubuntu, the browser suite passes on Ubuntu, the
packages install cleanly outside the checkout, the evaluations reproduce, and no known P0 or
P1 defect is open. The release tag points at a `main` commit whose complete CI run passed
(the run is linked from the GitHub release, since this file cannot name the run of the commit
that contains it). The repository stays **private**.

## GitHub Actions

| Run | Commit | Result | What it showed |
|---|---|---|---|
| [40665362374](https://github.com/Apostal322/CryptoGuard/actions/runs/40665362374) | `9b48c3e` | failure | First CI run ever: everything passed except one browser test. On Linux the mobile header was wider than the screen (403 px at 375 px). |
| [40666872831](https://github.com/Apostal322/CryptoGuard/actions/runs/40666872831) | `8053537` | failure | Header fixed; next Linux-only overflow: finding titles with unbreakable addresses (411 px). |
| [40671088534](https://github.com/Apostal322/CryptoGuard/actions/runs/40671088534) | `95c5856` | **success** | All 10 jobs. The browser job was re-run once (attempt 2): passed again. |

Jobs of run 40671088534 (counts from the job logs, not from the status alone):

| Job | OS | Result | Evidence |
|---|---|---|---|
| backend, Python 3.12 | Windows | pass | ruff, format, mypy clean; 402 passed, 4 deselected (`live`) |
| backend, Python 3.12 | Ubuntu | pass | same; 402 passed |
| backend, Python 3.13 | Ubuntu | pass | same; 402 passed |
| frontend | Windows | pass | typecheck, 52 Vitest tests, production build |
| frontend | Ubuntu | pass | same |
| browser e2e (Chromium) | Ubuntu | pass (twice) | 27 passed, 1 skipped (opt-in screenshot refresh), 45 s |
| package | Windows | pass | wheel 117 files, sdist 234; inspection OK; clean install of core and `[analytics]`, smoke test outside the checkout |
| package | Ubuntu | pass | same; distributions kept as the `dist` artifact |
| dependency audit | Ubuntu | pass | pip-audit 2.10.1: no known vulnerabilities; npm audit: 0; shellcheck clean |

## Matrix

| Area | Status | Evidence | Remaining |
|---|---|---|---|
| Backend tests | VERIFIED (Windows, Ubuntu) | 402 passed on 3 OS/Python combinations | — |
| Frontend tests | VERIFIED (Windows, Ubuntu) | 52 passed, typecheck, build | — |
| Browser E2E | VERIFIED (Ubuntu CI; Windows locally) | 27 passed + 1 opt-in skip on CI, two consecutive runs. Journeys: startup, search, approvals, poisoning escalation, campaign context, shadow vs default vs degraded, API errors (409, 422, 429, 500, 503, RPC outage), CSRF from a hostile page, Host/Origin, links, secrets in bundle/page/console, hostile metadata, layout at 1280/375/320 px and with a wide font, keyboard and labels | Locally, on a saturated machine, test servers once missed the 180 s start limit (see Stability) |
| Cross-platform | VERIFIED (Windows, Ubuntu) | Two Linux-only UI defects found by CI and fixed, each with a regression test that also fails on Windows | macOS untested |
| API security | VERIFIED | Boundary tests + browser tests on both OSes | No authentication by design (one local user) |
| Ethereum correctness | VERIFIED (fixtures, fake node) | Reverted payments never loss evidence; unknown receipts stay unknown; nonce search edges; coverage gaps reported | Native ETH received, internal transfers: not visible over JSON-RPC |
| Historical replay | VERIFIED | Leads 367 / 42 / 113 / 13,057 blocks in the regression tests on both OSes and in both clean installs | 4 cases: no rate estimate |
| Reproducibility | VERIFIED | Regenerated EVALUATION.md and CAMPAIGN_EVALUATION.md differ from the committed ones only in the timestamp and runtime columns; fixture hashes, outcomes, leads, clusters and memory identical | — |
| Campaign analysis | VERIFIED (experimental) | 54 attempts, 4 → 9 multi-wallet clusters, 23 prior-signer attempts; never earlier than the existing detector; shadow mode only | No ground truth for attribution |
| Database migrations | VERIFIED (SQLite, Windows + Ubuntu) | Upgrade from the captured `7fe824a` schema with data, idempotence, downgrade, interrupted-migration rollback, mismatch refusal | PostgreSQL untested |
| Leases | VERIFIED (SQLite, Windows + Ubuntu) | Real OS processes contend (one winner), crash recovery after expiry, fencing of a stale worker, overrun refused, per-wallet independence | No renewal: measured snapshots take < 1 s (fixtures) to ~30 s (real chain), the lease 15 min; overruns are refused, not raced |
| Packaging | VERIFIED (Windows, Ubuntu) | Built in CI without dependency cache; the sdist is checked against `git ls-files` | — |
| Clean install | VERIFIED (Windows, Ubuntu) | `scripts/smoke_install.py`: import from the venv, CLI, replay leads, demo API (healthy in 1–2 s on CI, Host 400, text/plain 415, snapshot 200), analytics `unavailable` without the extra, computed with it, both offline evaluations with it | — |
| Workflow security | VERIFIED | All actions pinned to verified commit SHAs; zizmor 1.31.1 (auditor persona): no findings; actionlint and schema validation clean; read-only token; no secrets used | — |
| Secrets | VERIFIED | Pattern scans of all 13 revisions (tokens, keys, mnemonics, RPC keys, personal paths) and detect-secrets 1.5.0: only test placeholders and public test vectors. No `.env`, databases or local configuration in history | Commits carry the author's configured e-mail address |
| Repository settings | PARTIAL | Private; Actions token read-only, cannot approve PRs; Dependabot alerts enabled; Dependabot updates configured | Branch protection, rulesets, secret scanning and private vulnerability reporting are not available for private repositories on this plan (not purchased) |

## Defects found in this phase

See RELEASE_AUDIT.md items 23–28: an untracked local file in a locally built sdist (P1), tag
pinning and CI hardening, a non-executable `check.sh`, a thin clean-install test, the two
Linux-only overflow defects, and a cold first analysis request.

## Stability

- CI browser runs: 3 runs; the 2 failures were the real overflow defects above (reproduced,
  fixed, regression-tested). After the fixes: 2 of 2 passes, with no retries configured.
- Locally (Windows) the suite passed in full earlier the same day (26 passed, 1 skipped). Later
  runs on the shared development machine did not reach the tests: a test server missed
  Playwright's start limit (180 s backend, 60 s frontend). Investigated rather than retried:
  the slow phase was Python reading its own compiled `.pyc` files (518 reads, 25.6 s, about
  50 ms each) and Vite loading its config (13.7 s cold, 0.3 s warm). The machine's only disk
  is a hard disk drive holding C: and D:; during these runs its average read latency was
  0.15–0.66 s with 15–34 queued requests from other workloads; the same server started in 9–13 s at other times, and the SciPy warm-up
  took 4.7 s idle against 60–76 s under load. Nothing in CryptoGuard's start-up depends on the
  machine beyond that. The start limits were not raised; the CI runners show the suite's
  behaviour on an unloaded machine (45 s for all tests).

## Performance (measured; Windows figures from a shared, often loaded machine)

| Workload | Time | Peak memory |
|---|---|---|
| `replay run` (4 incidents) | 7.5 s | 65 MiB |
| `replay run --analytics` (13 subjects + synthetic scaling) | 66 s (under load; 24 s earlier) | 196 MiB |
| `campaigns evaluate` | 9.7 s | 141 MiB |
| API ready, installed wheel, demo mode (CI) | 1.1–1.8 s | — |
| Demo snapshot via API (CI) | 0.1–0.3 s | — |
| Analytics warm-up at start (only when enabled) | 4.7 s idle | — |
| CI jobs | 19–117 s each; whole run about 2 min | — |

No mandatory heavy dependency was added; the analytics extra stays optional.

## Next action

Before any public visibility: review the history's author e-mail, enable the protections
that become free for public repositories (branch protection with required checks, secret
scanning and push protection, private vulnerability reporting), and decide on PyPI
publication separately.
