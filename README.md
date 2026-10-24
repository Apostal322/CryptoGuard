# CryptoGuard — Explainable Wallet Threat Intelligence

CryptoGuard is a **read-only** security analysis tool for Ethereum wallets. It shows what is
observably true about an address, the block that observation comes from, and what the
observation does *not* show. It never asks for private keys, seed phrases or signatures, and
it has no code path that signs or broadcasts transactions.

> **Status: Phase 7 (incident replay).** Applied ML is planned and **not implemented yet**
> (see [Roadmap](#roadmap)). Replay results are in [EVALUATION.md](EVALUATION.md).

## What works today

| Capability | Status |
|---|---|
| Point-in-time address inspection: verified chain id, block number/hash/time, finality, native balance, account code | Implemented |
| EIP-7702 delegation detection (exact `0xef0100 ‖ address`, 23 bytes) plus the delegate's code type | Implemented |
| Hardened JSON-RPC provider: chain verification, bounded retries with jitter, `Retry-After`, timeouts, response size cap, strict validation | Implemented |
| Reorg-safe reads: all state pinned to one block and re-checked against that block's hash | Implemented |
| Idempotent observation storage (SQLite; PostgreSQL via `DATABASE_URL`) | Implemented |
| REST API (`/api/v1`) with rate limiting, body-size limit, restricted CORS, safe errors | Implemented |
| ERC-20 approval discovery from `Approval` logs in a bounded block window (newest-first, adaptive splitting, request budget, optional token scope) | Implemented |
| Current-state verification: `allowance()`, `balanceOf()`, `decimals()`, `symbol()` and spender code at one pinned block | Implemented |
| Exposure upper bound `min(balance, allowance)`, unlimited/effectively-unlimited detection, evidence-classed signals | Implemented |
| ERC-721-shaped `Approval` logs recognized and kept apart from fungible allowances | Implemented (NFT approvals not analyzed) |
| Wallet security snapshots at a confirmed block, with incremental (checkpointed) approval discovery and cumulative coverage including explicit gaps | Implemented |
| Deterministic deltas between snapshots (allowance granted/increased/reduced/revoked/unverifiable, delegation set/changed/cleared), each located between two blocks and tied to a transaction only when an observed event explains it | Implemented |
| Versioned rule engine (`cg-rules` 1.0.0) with separate severity and confidence, deterministic finding fingerprints | Implemented |
| Finding lifecycle: new → active → acknowledged → resolved / superseded, reopen, audit trail; never resolved on unverifiable data | Implemented |
| Reorg handling for history: orphaned snapshots detected, marked and rebased | Implemented |
| ERC-20 transfer discovery (both directions) with bounded transaction-signer lookups, stored per wallet | Implemented |
| Address-poisoning detector: full-address prefix/suffix similarity, zero-value / spoofed / unsolicited transfer context, wallet-sent-to-lookalike evidence, configurable thresholds, false-positive guards | Implemented |
| Detector framework (pure, versioned detectors merged into the finding lifecycle) | Implemented |
| CLI (`inspect`, `approvals`, `poisoning`, `snapshot`, `timeline`, `findings`, `ack`, `status`, `serve`, `purge`, `demo-addresses`) | Implemented |
| Explicit demo mode with clearly labelled fictional fixtures | Implemented |
| Web UI (`apps/web`): dashboard, wallet overview, permission inspector, security timeline, findings with evidence and acknowledgement, address-poisoning view, settings; demo/real labelling and loading, empty, partial-coverage and error states | Implemented |
| Threat graph: typed edges (approved spender, holds token, delegates to, transfers in/out, resembles) built from stored observations, each with its evidence; only similarity edges are inferred; node and approval limits with an explicit summary node; interactive Cytoscape view plus an accessible list | Implemented |
| Historical incident replay: publicly sourced manifests, recorded mainnet fixtures, offline point-in-time engine with leakage checks, generated [EVALUATION.md](EVALUATION.md), Replay page in the UI | Implemented (1 case) |
| Wallet-signed transactions (incl. native-ETH payments) located by nonce search in snapshots and scans; used by the poisoning detector and the graph; degrades to explicit "unlocated" counts without archive state | Implemented |
| Scheduled monitoring loop, native ETH *received*, NFT/Permit2 approvals, ML | Not yet |

## Install (Windows PowerShell)

Requires [uv](https://docs.astral.sh/uv/). Python 3.12 is installed by uv if missing.

```powershell
git clone <repo> cryptoguard; cd cryptoguard
uv sync
Copy-Item .env.example .env   # then set CRYPTOGUARD_RPC_URL
```

## Configure

All settings are environment variables (or `.env`) with the `CRYPTOGUARD_` prefix; see
[.env.example](.env.example). The important ones:

- `CRYPTOGUARD_MODE` — `real` (default) or `demo`. Real mode **never** falls back to demo data:
  without an RPC URL, inspections fail with `rpc_not_configured`.
- `CRYPTOGUARD_RPC_URL` — HTTPS JSON-RPC endpoint (plain HTTP only for `localhost`). It is
  operator configuration only; the API never accepts an RPC URL from a request. It is redacted
  to `scheme://host/…` everywhere it is displayed and scrubbed from logs.
- `CRYPTOGUARD_CHAIN_ID` — `1` (mainnet) or `11155111` (Sepolia). Every session first checks
  `eth_chainId` and refuses to read state from a different chain.

### RPC provider limitations

- `ethereum-rpc.publicnode.com` (checked 2026-10-24) serves recent data only; historical
  ("archive") log and state queries need a personal token. `eth.drpc.org`'s free plan serves
  historical logs and state but limits `eth_getLogs` to about 100 blocks per request;
  CryptoGuard splits larger queries automatically.

- Free/public endpoints rate-limit aggressively; CryptoGuard retries with backoff, but heavy
  use needs a keyed provider.
- Many endpoints prune old state. Reading state at old blocks needs an archive node; such
  failures are reported as `historical_state_unavailable`, never as a zero balance.
- Standard JSON-RPC cannot list every transaction of an address. Inspections are single
  snapshots, and approval scans cover only the block window they report.
- Some free endpoints refuse `eth_getLogs` without a contract `address` filter (for example
  `ethereum-rpc.publicnode.com`, checked 2026-10-23). There, wallet-wide approval discovery
  fails with `log_filter_restricted`; pass `--token <contract>` (API: `tokens`) to scan named
  tokens, or use a provider that allows wallet-wide log queries.
- Your RPC provider sees which addresses you inspect. Run your own node if that matters.

## Use

```powershell
uv run cryptoguard status
uv run cryptoguard inspect 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
uv run cryptoguard inspect <address> --json

# ERC-20 approvals granted in the last 10,000 blocks (default), verified at the head block
uv run cryptoguard approvals <address>
uv run cryptoguard approvals <address> --lookback 50000
uv run cryptoguard approvals <address> --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# Address poisoning: one-off scan of recent ERC-20 transfers (nothing stored).
# Snapshots run the same detector over the wallet's stored transfer history.
uv run cryptoguard poisoning <address> --lookback 5000

# Security timeline: each snapshot is compared with the previous one
uv run cryptoguard snapshot <address>            # first run = baseline
uv run cryptoguard snapshot <address>            # later runs list what changed and why
uv run cryptoguard timeline <address>
uv run cryptoguard findings <address> [--all]
uv run cryptoguard ack <finding-id>
uv run cryptoguard graph <address>             # relationships from the latest snapshot

# Historical incident replay (offline, from packaged fixtures)
uv run cryptoguard replay list
uv run cryptoguard replay run --write-report EVALUATION.md
# Re-record a fixture (needs historical logs + state, e.g. https://eth.drpc.org):
uv run cryptoguard replay record <case-id> --rpc-url <archive-capable RPC>

# Fictional fixtures, no RPC needed (output is labelled SIMULATED):
uv run cryptoguard demo-addresses
uv run cryptoguard inspect <fixture-address> --demo

# HTTP API on http://127.0.0.1:8000 (OpenAPI docs at /docs)
uv run cryptoguard serve

# Delete locally stored observations
uv run cryptoguard purge --yes
```

API:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Liveness and database check |
| GET | `/api/v1/status` | Mode, redacted provider, chain verification, head block, RPC metrics |
| POST | `/api/v1/analyze/address` | `{"address": "0x…"}` → inspection (persisted idempotently) |
| POST | `/api/v1/wallets/{address}/approvals/scan` | `{"lookback_blocks"?, "from_block"?, "tokens"?}` → approval scan report (send `{}` for defaults) |
| GET | `/api/v1/wallets/{address}/approvals` | Latest stored approval scan (404 if none) |
| POST | `/api/v1/wallets/{address}/snapshots` | `{"block"?, "tokens"?, "lookback_blocks"?}` → snapshot with changes and finding transitions |
| GET | `/api/v1/wallets/{address}/timeline` | Snapshots newest first with deltas, finding events, coverage (`limit`, `offset`, `include_orphaned`) |
| GET | `/api/v1/wallets/{address}/findings` | Findings (`status=open` default, `all`, or a single status) |
| GET | `/api/v1/findings/{finding_id}` | Finding with evidence and full transition history |
| POST | `/api/v1/findings/{finding_id}/acknowledge` | Mark a new/active finding acknowledged (`{}` body) |
| GET | `/api/v1/wallets/{address}/graph` | Relationship graph from the latest snapshot (`max_nodes` 10–150, `include_inactive`); every edge has evidence; no RPC calls |
| POST | `/api/v1/wallets/{address}/poisoning/scan` | `{"lookback_blocks"?, "tokens"?}` → poisoning cases with similarity features, signals and evidence |
| GET | `/api/v1/replay/cases` | Packaged incident cases (manifest, sources, fixture hash) |
| POST | `/api/v1/replay/runs` | `{"case_id"}` → offline point-in-time replay result (not stored; no RPC) |
| GET | `/api/v1/rules` | The ruleset: id, version, severities, rule descriptions |
| GET | `/api/v1/wallets/{address}/observations` | Stored observations, paginated (`limit`, `offset`) |
| GET | `/api/v1/demo/addresses` | Fixture addresses (demo mode only) |

Every inspection carries `data_source` (`rpc` / `demo_fixture`), `simulated`, the exact block
it describes, `coverage` and an explicit list of `limitations`.

## Web UI

Requires Node.js 22+ (tested with 24). The UI is a static React app; in development Vite
proxies `/api` to the backend on `127.0.0.1:8000`, so no CORS change is needed.

```powershell
uv run cryptoguard serve            # terminal 1 (add --demo for simulated data)
cd apps/web; npm ci; npm run dev    # terminal 2, then open http://127.0.0.1:3000
```

`npm run build` writes `apps/web/dist/` with a strict Content-Security-Policy. Serve it from
the same origin as the API (any static server or reverse proxy that forwards `/api`).

## Test

```powershell
uv run pytest                 # offline suite (fake JSON-RPC node, no network)
uv run ruff check .
uv run mypy src
cd apps/web; npm run typecheck; npm test; npm run build

# Opt-in live test against a real mainnet endpoint:
$env:CRYPTOGUARD_LIVE_RPC_URL = "https://ethereum-rpc.publicnode.com"; uv run pytest -m live
```

## Roadmap

1. ~~Backend foundation~~
2. ~~ERC-20 approval discovery and allowance verification~~
3. ~~Wallet security timeline: snapshots, deterministic deltas, finding lifecycle~~ (a
   scheduled monitoring loop is still to come)
4. ~~Address-poisoning detector with false-positive fixtures~~
5. ~~Web UI (Vite, React, TypeScript, Tailwind)~~
6. ~~Threat graph~~
7. ~~Historical incident replay with point-in-time guarantees~~ (this milestone; more cases
   needed before any rate can be estimated)
8. ML only if it beats the deterministic baseline on honest temporal splits

See [ARCHITECTURE.md](ARCHITECTURE.md), [DETECTION_METHODS.md](DETECTION_METHODS.md) and
[SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
