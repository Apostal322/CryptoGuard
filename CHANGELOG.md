# Changelog

All notable changes. Versions follow semantic versioning; 0.x means interfaces may change.

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

### Release review
- Security, dependency (pip-audit, npm audit), reproducibility and packaging review; stale
  threat model updated; campaign runs made single-flight. See SECURITY.md.
- Machine learning (brief phase 8) deliberately deferred: too few labelled cases.

### Known limitations
- Native ETH received by a wallet, internal transfers and funding sources are not visible
  over standard JSON-RPC.
- No scheduled monitoring loop; snapshots run on request.
- No Alembic migrations yet; schema changes so far only added tables.
- CI (Windows + Linux) is defined but has not run: the repository has no remote yet.
