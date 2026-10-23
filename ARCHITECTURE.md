# Architecture

## Layers and dependency direction

```
cli.py ─┐
        ├─> services/ ──> blockchain/ ──> core/
api/ ───┘        │
                 └──> database/ (repository only; via services' models)
```

Dependencies point downward only. `core` and `blockchain` know nothing about FastAPI,
SQLAlchemy or the CLI, so detectors added later can be run, tested and replayed without HTTP.

| Module | Responsibility |
|---|---|
| `core/errors.py` | Error taxonomy: stable `code`, HTTP status, retryability, user-safe messages |
| `core/config.py` | Settings from env/`.env`; RPC URL validation and redaction |
| `core/address.py` | Address validation, EIP-55 checksums (full 20-byte comparison) |
| `core/hexutil.py` | Strict, size-bounded parsing of JSON-RPC hex values |
| `core/units.py` | Exact integer → decimal formatting (no floats) |
| `core/chains.py` | Supported chains; explorer links built only from validated values |
| `core/logging.py` | JSON logs with secret redaction |
| `blockchain/rpc.py` | JSON-RPC 2.0 transport: retries, backoff+jitter, limits, error classification |
| `blockchain/provider.py` | `EthereumProvider` protocol and the read-only RPC implementation |
| `blockchain/eip7702.py` | Exact EIP-7702 delegation-indicator recognition |
| `blockchain/abi.py` | Minimal strict ABI encode/decode for ERC-20 calls; sanitized `symbol()` |
| `blockchain/erc20.py` | `Approval` log decoding with ERC-20 vs ERC-721 disambiguation |
| `core/known_contracts.py` | Cited display labels for a few published spender contracts |
| `services/inspection.py` | Point-in-time address inspection (observed facts, no risk judgement) |
| `services/approvals.py` | Bounded approval discovery, pinned-block allowance verification, exposure |
| `services/demo.py` | Demo provider over fictional, deterministic fixtures |
| `services/providers.py` | Mode → provider selection; no silent fallback |
| `database/` | ORM models, idempotent observation repository |
| `api/` | FastAPI app factory, middleware (limits, headers, CORS), routes, schemas |

The suggested `apps/api` / `packages/shared-schemas` split was not adopted yet: with one
backend and no frontend, it would add packaging overhead without benefit. The web app will
live in `apps/web` when Phase 5 starts; shared schemas will be generated from the OpenAPI spec.

## Data flow: `POST /api/v1/analyze/address`

1. Middleware: body-size check, per-client token bucket, security headers.
2. Address validated and checksummed (`InvalidAddressError` → 422 before any RPC call).
3. `verify_chain()` — `eth_chainId` must equal the configured chain (cached).
4. Read `eth_blockNumber` → `eth_getBlockByNumber(N)` → `eth_getBalance`/`eth_getCode` at `N`
   (and the delegate's code if the account is delegated).
5. Re-read block `N`; if its hash changed, a reorg occurred — retry (max 2), then fail.
6. Finality from the `finalized` tag (reported as `unknown` if unsupported).
7. Persist the observation; the unique key `(chain_id, address, block_hash, type, source)`
   makes this idempotent.

## Data flow: `POST /api/v1/wallets/{address}/approvals/scan`

1. Validate owner and window (`max_scan_blocks`), verify chain, read head block `N`.
2. Scan `Approval` logs for `[topic0, owner]` newest-first in chunks (optionally scoped to
   token contracts); split chunks the provider refuses; stop at the request budget.
3. Decode logs, drop removed/duplicate/non-ERC-20 shapes, group by (token, spender).
4. At block `N`: token code, `balanceOf`, `decimals`, `symbol`, spender code, `allowance`.
5. Re-check block `N`'s hash (reorg → error), build the report, persist report + events.

## Storage

`address_observations` stores each observation with block number, block hash, block
timestamp (chain time) and `observed_at` (CryptoGuard time) as separate columns, plus the
schema version and data source. Inspections and approval-scan reports both live here,
distinguished by `observation_type`. `approval_events` stores each decoded `Approval` log,
unique on `(chain_id, block_hash, log_index)`, with the uint256 value as a decimal string.
All times are UTC. Schema creation currently uses
`create_all`; Alembic migrations must be introduced before the first schema change.

## Extension points

- New chain-data sources implement `EthereumProvider` (e.g. an indexed-history provider).
- Detectors (Phase 2+) will consume observations through a `DetectionContext` and emit
  versioned `Finding`s; they must not depend on `api/`.

## Decision record (Phase 1)

| Decision | Rationale |
|---|---|
| httpx JSON-RPC client instead of web3.py | Full control over retries, size limits, error classification and redaction; much smaller dependency tree. web3.py may be added later for ABI decoding if hand-rolled decoding becomes a risk. |
| pycryptodome for keccak-256 | `hashlib.sha3_256` is NIST SHA-3, not Ethereum's keccak. |
| Pin reads by block number + hash re-check, not EIP-1898 `blockHash` params | Works on every provider; detects reorgs explicitly. |
| Integers as strings in JSON | JavaScript numbers lose precision above 2^53. |
| In-process rate limiter | No Redis until there is a multi-instance deployment. |
| Demo mode answers only fixture addresses | Never invent state for an arbitrary real address. |

## Known gaps / technical debt

- No Alembic migrations yet (`create_all` only).
- Approval scans are on-demand; there is no forward-monitoring loop or ingestion checkpoint
  yet, and stored `approval_events` are not yet reconciled after reorgs (Phase 3).
- ERC-20 call results are trusted to follow the standard; tokens with non-standard
  `transferFrom` semantics (rebasing, fee-on-transfer, blocklists) can make the exposure bound
  inexact.
- EIP-7702 authorization-list parsing and authority recovery (secp256k1 `ecrecover`) are not
  implemented; current delegation is read from code only, so delegation *history* is unknown.
- Chain verification is cached for the process lifetime; an endpoint that switches chains
  mid-run would only be caught by `/status` or a restart.
- `starlette.testclient` warns that `httpx` support is deprecated; tests will need to move
  to its replacement in a future upgrade.
