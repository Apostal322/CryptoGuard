# CryptoGuard — Explainable Wallet Threat Intelligence

CryptoGuard is a **read-only** security analysis tool for Ethereum wallets. It shows what is
observably true about an address, the block that observation comes from, and what the
observation does *not* show. It never asks for private keys, seed phrases or signatures, and
it has no code path that signs or broadcasts transactions.

> **Status: Phase 1 (backend foundation).** Approval monitoring, the security timeline,
> address-poisoning detection, the web UI, the threat graph and incident replay are planned
> and **not implemented yet** (see [Roadmap](#roadmap)).

## What works today

| Capability | Status |
|---|---|
| Point-in-time address inspection: verified chain id, block number/hash/time, finality, native balance, account code | Implemented |
| EIP-7702 delegation detection (exact `0xef0100 ‖ address`, 23 bytes) plus the delegate's code type | Implemented |
| Hardened JSON-RPC provider: chain verification, bounded retries with jitter, `Retry-After`, timeouts, response size cap, strict validation | Implemented |
| Reorg-safe reads: all state pinned to one block and re-checked against that block's hash | Implemented |
| Idempotent observation storage (SQLite; PostgreSQL via `DATABASE_URL`) | Implemented |
| REST API (`/api/v1`) with rate limiting, body-size limit, restricted CORS, safe errors | Implemented |
| CLI (`inspect`, `status`, `serve`, `purge`, `demo-addresses`) | Implemented |
| Explicit demo mode with clearly labelled fictional fixtures | Implemented |
| ERC-20 approvals, timeline, poisoning detector, UI, graph, replay, ML | Not yet |

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

- Free/public endpoints rate-limit aggressively; CryptoGuard retries with backoff, but heavy
  use needs a keyed provider.
- Many endpoints prune old state. Reading state at old blocks needs an archive node; such
  failures are reported as `historical_state_unavailable`, never as a zero balance.
- Standard JSON-RPC cannot list every transaction of an address. Phase 1 therefore reports a
  single snapshot and says so; it does not claim to know the wallet's history.
- Your RPC provider sees which addresses you inspect. Run your own node if that matters.

## Use

```powershell
uv run cryptoguard status
uv run cryptoguard inspect 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
uv run cryptoguard inspect <address> --json

# Fictional fixtures, no RPC needed (output is labelled SIMULATED):
uv run cryptoguard demo-addresses
uv run cryptoguard inspect <fixture-address> --demo

# HTTP API on http://127.0.0.1:8000 (OpenAPI docs at /docs)
uv run cryptoguard serve

# Delete locally stored observations
uv run cryptoguard purge --yes
```

API (Phase 1):

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Liveness and database check |
| GET | `/api/v1/status` | Mode, redacted provider, chain verification, head block, RPC metrics |
| POST | `/api/v1/analyze/address` | `{"address": "0x…"}` → inspection (persisted idempotently) |
| GET | `/api/v1/wallets/{address}/observations` | Stored observations, paginated (`limit`, `offset`) |
| GET | `/api/v1/demo/addresses` | Fixture addresses (demo mode only) |

Every inspection carries `data_source` (`rpc` / `demo_fixture`), `simulated`, the exact block
it describes, `coverage` and an explicit list of `limitations`.

## Test

```powershell
uv run pytest                 # offline suite (fake JSON-RPC node, no network)
uv run ruff check .
uv run mypy src

# Opt-in live test against a real mainnet endpoint:
$env:CRYPTOGUARD_LIVE_RPC_URL = "https://ethereum-rpc.publicnode.com"; uv run pytest -m live
```

## Roadmap

1. ~~Backend foundation~~ (this milestone)
2. ERC-20 approval discovery (bounded log scans), `allowance()` verification, exposure upper
   bound `min(balance, allowance)`
3. Wallet security timeline: snapshots, deterministic deltas, finding lifecycle
4. Address-poisoning detector with false-positive fixtures
5. Web UI (Next.js, TypeScript, Tailwind)
6. Threat graph
7. Historical incident replay with point-in-time guarantees
8. ML only if it beats the deterministic baseline on honest temporal splits

See [ARCHITECTURE.md](ARCHITECTURE.md), [DETECTION_METHODS.md](DETECTION_METHODS.md) and
[SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
