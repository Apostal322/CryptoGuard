# Changelog

All notable changes. Versions follow semantic versioning; 0.x means interfaces may change.

## Unreleased (branch `feature/ml-pipeline`)

### Experimental machine learning (shadow mode, `ml` extra)
- Pinned, hash-verified external label sources (PTXPhish, Poison-Hunter, Forta); the two
  without a license are fetched locally, never redistributed (`aee2bf4`).
- Budgeted, resumable collection of point-in-time chain data for a deterministic
  stratified sample; validated feature table with an input-hash manifest (`aee2bf4`).
- Study window, time-ordered splits and per-account purge against reused attacker
  infrastructure; trivial, rule and learned baselines; run ledger; promotion gate;
  hash-pinned model registry; shadow scoring API and CLI; PSI drift monitoring
  (`e9b49f1`). Results in ML_EVALUATION.md, data card and decision log in ML.md.

### ML generalization audit (Phase 11.1)
- Baseline reproduced exactly (metrics, model bytes) and frozen in
  `docs/ml/baseline-phase11.json`; its test split reclassified as a development benchmark.
  The model is now research-only: the API refuses to score with it (`c11e5fb`).
- Fixed: scoring skipped chain verification; a missing receipt was scored; the request
  budget could be lost on a crash or overspent by concurrent collectors; the registry
  trusted a path from its JSON file; intervals resampled rows despite account clustering.
- Added: `cryptoguard ml audit` (recomputed metrics, cluster intervals, prevalence arithmetic,
  shortcut experiments, hub-policy sensitivity, calibration, errors), approval levels,
  LightGBM text serialization, wallet-history features (infrastructure, no accuracy claim).
  Report: ML_GENERALIZATION_AUDIT.md; tables: ML_AUDIT_TABLES.md.

## 0.1.0 — 2026-10-28 (first release candidate, not independently audited)

### Detection and monitoring
- Point-in-time address inspection with chain verification, finality and EIP-7702
  delegation detection (`6f4d523`).
- ERC-20 approval discovery from `Approval` logs with pinned-block allowance verification
  and a `min(balance, allowance)` exposure bound (`ce24d3d`).
- Wallet security timeline: snapshots, deterministic deltas, versioned ruleset `cg-rules`,
  finding lifecycle that never resolves on unverifiable data, reorg rebase (`09c06cf`).
- Address-poisoning detector with full-address similarity, poisoning context signals and
  false-positive guards (`be093bf`); exclusive rule groups so an escalation supersedes
  rather than resolves (`5b85540`).
- Wallet-signed transactions (native-ETH payments) located by nonce search in snapshots
  and scans (`5b85540`).

### Interfaces
- REST API with rate limiting, body limits, restricted CORS and safe errors; CLI.
- Web UI: dashboard, wallet overview, permissions, timeline, findings, poisoning view,
  threat graph (Cytoscape), replay page; strict CSP in production builds (`c77267f`,
  `264d76c`, `15f06cd`).

### Evaluation
- Historical incident replay: publicly sourced manifests, recorded mainnet fixtures,
  point-in-time engine with leakage checks, generated `EVALUATION.md` (`15f06cd`); now 4
  incidents and 9 randomly sampled background wallets (`810c50b`).

### Experimental (off by default, shadow mode only)
- Graph propagation, spectral features and activity-rate statistics, evaluated against the
  existing detector: no measurable gain (`810c50b`).
- Cross-wallet poisoning campaign analysis with budgeted expansion, conservative clustering
  and `CAMPAIGN_EVALUATION.md`: real shared-signer links found, no earlier theft warning
  (`3fde4a8`).

### GitHub CI and cross-platform validation
- First GitHub-hosted CI runs (private repository): backend, frontend and packaging on
  Windows and Ubuntu, backend also on Python 3.13, browser tests on Ubuntu (`4705389`).
- Fixed, found by Linux CI: the mobile header and finding titles overflowed narrow screens
  with wider fonts; layout tests now cover 320 px and a wide font (`8053537`, `95c5856`).
- Experimental analysis libraries load at API start when enabled, not on the first request
  (`95c5856`).
- Actions pinned to verified commit SHAs, Dependabot cooldown, uv and pip-audit pinned;
  packaging job on both OSes with a full clean-install smoke test; sdist checked against the
  tracked files after a local untracked file leaked into a locally built sdist (`4705389`).

### Release candidate validation (phase 10.1)
- Browser end-to-end suite (Playwright, Chromium): the real backend against a fictional test
  chain behind the production UI build; user journeys, error handling, browser security,
  layout and accessibility checks.
- Fixed: a superseded finding was labelled "resolved at block"; the timeline said "No
  security-relevant change observed" above new findings; a shared-signer campaign showed a
  contradictory "single points" warning; mobile timeline overflow; stretched snapshot button;
  stale "native ETH not analyzed" dashboard text; garbled campaign explanation.
- Fixed: SQLite DDL autocommitted, so an interrupted migration left partial changes; SQLite
  connections now let SQLAlchemy start transactions.
- Fixed a timing-dependent lease test.
- CI: concurrency, timeouts, `persist-credentials: false`, Windows + Ubuntu for backend and
  frontend, browser E2E job, packaging job with artifact inspection and clean install.
  Local equivalents: `scripts/check.ps1`, `scripts/check.sh`.

### Release validation (phase 10)
- Local API hardened against DNS rebinding (host allow-list) and CSRF (JSON-only POSTs,
  Origin check).
- Snapshots (per wallet) and campaign runs single-flight across processes via fenced
  database leases; concurrent same-wallet snapshots no longer fail with 500.
- Reverted ETH payments are recognised (receipt status) and never treated as funds sent to
  a lookalike; all recorded fixtures re-checked on-chain (all executed).
- Versioned, reversible schema migrations with startup verification; upgrade from the
  `7fe824a` schema tested.
- Metamorphic point-in-time tests on real fixtures; clean-environment wheel install tested.
  See RELEASE_AUDIT.md.

### Release review
- Security, dependency (pip-audit, npm audit), reproducibility and packaging review; stale
  threat model updated; campaign runs made single-flight. See SECURITY.md.
- Machine learning (brief phase 8) deliberately deferred: too few labelled cases.

### Known limitations
- Native ETH received by a wallet, internal transfers and funding sources are not visible
  over standard JSON-RPC.
- No scheduled monitoring loop; snapshots run on request.
- No authentication: one trusted local user (see SECURITY.md).
- CI covers Windows and Ubuntu; macOS is untested. PostgreSQL is untested.
