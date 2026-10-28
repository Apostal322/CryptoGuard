# Release audit register — 0.1.0 (phase 10)

Audit of revision `7fe824a` (2026-10-28) by the development process itself. **Not an
independent audit.** P0 = release blocker, P1 = important security or reliability issue,
P2 = later work. Every "fixed" item has a regression test (named).

## Fixed

| # | Pri | Finding (how it was found) | Fix | Regression test |
|---|---|---|---|---|
| 1 | P1 | **CSRF on the local API.** A cross-site "simple" POST (`text/plain`, form encodings: no CORS preflight) and a POST with a foreign `Origin` both started a campaign run (200); `POST /findings/{id}/acknowledge` takes no body, so a hostile page could acknowledge (hide) a finding. Probed with attack-shaped requests. | POSTs require `Content-Type: application/json` (415 otherwise); a present `Origin` must be a configured CORS origin or the API's own origin (403 otherwise). | `test_api_boundary.py::test_cross_site_simple_posts_cannot_trigger_work`, `test_foreign_origin_is_refused_and_own_origins_are_allowed` |
| 2 | P1 | **DNS rebinding.** Any `Host` header was served (200 for `Host: evil.example`), so a page that rebinds its hostname to 127.0.0.1 could read watched addresses and findings. | `CRYPTOGUARD_ALLOWED_HOSTS` (default `127.0.0.1`, `localhost`, `::1`; no wildcards); anything else gets 400 `invalid_host`. | `test_rebound_hostname_is_refused`, `test_settings_reject_wildcard_hosts` |
| 3 | P1 | **Concurrent snapshots of one wallet failed with 500** (4 parallel requests: 200, 500, 500, 500; SQLAlchemy flush errors). | Per-wallet database lease; a concurrent request gets 409 `snapshot_in_progress`; other wallets are not blocked. | `test_campaign_api.py::test_concurrent_snapshot_of_one_wallet_is_refused` |
| 4 | P1 | **Campaign single-flight was process-local** (a thread lock): two API processes, or CLI plus API, could run concurrently. | Database lease (`operation_leases`): atomic acquisition (primary-key insert, or conditional takeover of an expired lease), owner token + generation as fencing token checked inside the result-writing transaction, owner-only release, expiry-based crash recovery. Same lease protects snapshots. | `test_leases.py` (6 real OS processes contend, exactly one wins; a crashed owner's lease is recovered after expiry with generation 2; a stale worker is fenced out and cannot release the new lease; an overrunning snapshot saves nothing; a failing run leaves no lock) |
| 5 | P1 | **Reverted ETH payments counted as executed.** The locator took `value` from the transaction without its receipt; a reverted send to a lookalike could become CG-POI-003 ("wallet sent to lookalike", critical evidence). Found by code review of the locator. | Receipt status read for every ETH-carrying wallet transaction (unknown if unreadable or from another block). A reverted send still identifies the intended payee (reference) but is never loss evidence. Stored (`wallet_transactions.succeeded`) and recorded in fixtures: all 16 ETH-carrying transactions in the fixtures were checked on-chain (17 requests to eth.drpc.org) and all executed, so no published result changed. | `test_wallet_tx_edge_cases.py` (reverted, zero-value, unreadable and reorganized receipts; CG-POI-003 only for executed or unknown sends) |
| 6 | P1 | **No migration mechanism.** `create_all` never alters existing tables, so any column change would leave old databases silently broken until an obscure SQL error. | `database/migrations.py`: versioned, idempotent, reversible migrations (`schema_versions` table); `verify` refuses to start on a schema mismatch with a clear message. | `test_migrations.py` (upgrade of a real `7fe824a` schema with data, idempotence, downgrade/re-upgrade, fresh install, mismatch refusal) |
| 7 | P2 | Two of my own new tests were weak (one compared a value with itself; one checked a mangled address and passed trivially). | Rewritten to assert real invariants. | `test_metamorphic.py`, `test_leases.py` |

## Verified, no change needed

- Address validation rejects wrong mixed-case EIP-55 checksums (a probe that seemed to
  show otherwise had flipped a digit). Malformed input (bad addresses, 10,000-character
  paths, huge or negative numbers, invalid JSON, lone surrogates, unknown fields such as
  `rpc_url`, oversized bodies, bad pagination, malformed campaign ids) returns a 4xx with a
  stable error code, no stack trace and no secret: `test_malformed_requests_are_rejected_predictably`.
- SSRF: the RPC endpoint comes only from operator configuration; request bodies reject
  unknown fields.
- No raw SQL outside the migration DDL constants; no HTML injection paths in the UI.
- Point in time: metamorphic tests on real fixtures (future transactions, relabelled ground
  truth, unrelated events, record order, double replay): `test_metamorphic.py`.
- Experimental analyses and campaign analysis are off by default; shadow mode does not
  change findings (`test_analysis.py`, `test_campaign_api.py`).
- Detection regression: replay leads 367 / 42 / 113 / 13,057 blocks and campaign headlines
  unchanged after the fixes (`test_evaluation_regression.py`); regenerated reports differ from
  the previous ones only in fixture hashes and timings.
- Clean install: the built wheel installed into an empty venv outside the repository (no
  NumPy/SciPy) runs the CLI, the offline replay (same leads), a demo-mode API session, and
  enforces the new host and content-type checks.
- Dependencies: lockfile current; pip-audit and npm audit clean (see SECURITY.md).

## Open (documented, not fixed)

| # | Pri | Item |
|---|---|---|
| 8 | P2 | No authentication: the API is for one trusted local user. Expose it only behind an authenticating reverse proxy, adding its hostname to `CRYPTOGUARD_ALLOWED_HOSTS` deliberately. |
| 9 | P2 | Leases are not renewed while work runs (default 15 min). An overrunning run loses its lease and its results are refused rather than raced. |
| 10 | P2 | A cancelled request's worker thread runs to completion; the lease is released afterwards. Long RPC work is bounded by request budgets and timeouts, not by cancellation. |
| 11 | P2 | The in-memory database URL (`sqlite://`, tests only) shares one connection; concurrent writes need a file or server database. |
| 12 | P2 | CI (Windows + Linux) is defined but has never run: the repository has no remote. Only Windows 11 was run locally. |
| 13 | P2 | `expansion.json` records the fixture hashes current when it was recorded; the receipt-status update changed those hashes (not the attempts). The campaign report prints current hashes. |
| 14 | P2 | `starlette.testclient` warns that `httpx` support is deprecated. |
