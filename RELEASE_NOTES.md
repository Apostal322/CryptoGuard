# CryptoGuard 0.1.0 — release notes (pre-release)

CryptoGuard is a **read-only**, explainable security monitor for Ethereum wallets. It shows
what is observably true about a wallet, the block each observation comes from, and what was
not covered. It never asks for keys or seed phrases and has no code path that signs or sends
transactions.

**This is a pre-release.** It has not been independently audited, it is not a substitute for
careful verification of recipients, and it must not be the only safeguard for funds.

## What it does

- **Point-in-time inspection**: chain verification, balance, account code and EIP-7702
  delegation (exact 23-byte indicator; delegation *history* is not inferred).
- **ERC-20 approvals**: discovery from `Approval` events in a bounded window, allowances and
  balances read at one block, unlimited and effectively unlimited allowances flagged as
  exposure (not as compromise), unknown values shown as unknown.
- **Security timeline**: snapshots at confirmed blocks, deterministic changes between them,
  versioned rules with separate severity and confidence, a finding lifecycle that never
  resolves on unverifiable data and marks escalations as *superseded*, not resolved.
- **Address poisoning**: full-address similarity with poisoning context (zero-value, spoofed
  and unsolicited transfers), the wallet's own ETH payments as references, reverted payments
  recognised from receipts.
- **Threat graph**: typed relationships with evidence per edge.
- **Historical replay**: 4 publicly reported poisoning thefts and 9 randomly sampled
  background wallets, point-in-time, with leakage checks ([EVALUATION.md](EVALUATION.md)).
  With the wallet's own transactions visible, the detector warned before all 4 thefts
  (42 to 13,057 blocks ahead). Four cases are case studies, not a detection rate.
- **Web UI and REST API** for one local user.

## Experimental (off by default, shadow mode only)

Graph, spectral and temporal analyses, and cross-wallet poisoning campaign analysis. They
never create findings or change severities. Evaluated without measurable gain over the
existing detector; campaign analysis finds real shared-signer links between wallets but
gave no earlier theft warning ([CAMPAIGN_EVALUATION.md](CAMPAIGN_EVALUATION.md)).

## Security boundaries

- One trusted local user; no authentication. The API binds to `127.0.0.1`, answers only to
  allow-listed hostnames (DNS-rebinding protection), accepts only JSON POSTs and checks
  `Origin` (CSRF protection). Do not expose it to a network without an authenticating proxy.
- Snapshots and campaign runs are single-flight across processes (fenced database leases).
- Untrusted chain metadata is rendered as text; external links go only to the chain's
  block explorer.

## Hardening found and fixed during release validation

Each has a regression test ([RELEASE_AUDIT.md](RELEASE_AUDIT.md)):

- Cross-site requests could make the local API start work or acknowledge findings (CSRF),
  and any `Host` header was served (DNS rebinding).
- Concurrent snapshots of one wallet failed with server errors; job coordination was
  per-process only. Now fenced database leases.
- A reverted ETH payment could count as money sent to a lookalike. Receipt status is now
  read; reverted payments are references only, unknown status stays unknown.
- No schema migrations existed; SQLite DDL in a failed migration was not rolled back.
- A superseded finding was labelled "resolved"; the mobile header and timeline overflowed
  narrow screens (the header overflow was found by the first Linux CI run).
- A locally built source distribution could include an untracked local tool file; release
  artifacts are built in CI and checked against the tracked file list.

## Known limitations

- Native ETH *received* by a wallet, internal (contract-mediated) transfers and funding
  sources are not visible over standard JSON-RPC.
- Providers without historical state limit coverage; results say what is missing.
- No scheduled monitoring loop: snapshots run on request.
- Leases are not renewed during a run (default 15 minutes); an overrunning run's results
  are refused rather than raced.
- Tested on SQLite only; PostgreSQL is supported through SQLAlchemy but untested.
- Detection was evaluated on four incidents: a case study, not an accuracy estimate. A quiet
  result never means a wallet is safe.

## Verification

GitHub Actions on the release commit: backend (402 tests, lint, types) on Windows and Ubuntu
with Python 3.12 and on Ubuntu with 3.13; frontend (52 tests, typecheck, build) on both;
browser end-to-end tests (27, headless Chromium, real API against a fictional test chain) on
Ubuntu; wheel and sdist built, inspected and clean-installed (core and `analytics` extra) on
both; pip-audit and npm audit with no known vulnerabilities. macOS is untested. Details and
run links: [RELEASE_CANDIDATE_REPORT.md](RELEASE_CANDIDATE_REPORT.md).

## Install

See [README.md](README.md#quick-start). Python 3.12 via uv; Node.js 22+ for the UI. The
optional `analytics` extra (NumPy, SciPy) is needed only for the experimental analyses.
