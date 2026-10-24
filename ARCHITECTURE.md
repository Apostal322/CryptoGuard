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
| `history/state.py` | Canonical, hashable wallet state at one block |
| `history/delta.py` | Deterministic `previous → current` change list with honest causes |
| `risk/rules.py` | Versioned ruleset `cg-rules`; finding candidates and fingerprints |
| `risk/lifecycle.py` | Pure finding-lifecycle reconciliation |
| `blockchain/logscan.py` | Shared bounded, newest-first `eth_getLogs` scanner (split, budget) |
| `services/transfers.py` | ERC-20 transfer discovery (both directions) and signer lookups |
| `services/wallet_txs.py` | Every wallet-signed transaction in a window, by galloping + bisecting the nonce |
| `detectors/base.py` | `Detector` protocol, `DetectionContext`, merging runner; state-rules adapter |
| `detectors/poisoning.py` | Pure address-poisoning detector |
| `services/poisoning.py` | One-off poisoning scan (no storage) |
| `services/snapshots.py` | Snapshot orchestration: reorg rebase, incremental discovery, verify, diff, detectors |
| `database/history.py` | Snapshot/finding/transition persistence; lifecycle applied in one transaction |
| `graph/build.py` | Pure threat-graph builder: typed nodes/edges with evidence, prioritised limits |
| `services/graph.py` | Loads the latest snapshot, stored transfers and open findings for the graph |
| `api/history_routes.py` | Snapshot, timeline, finding and ruleset endpoints |
| `services/demo.py` | Demo provider over fictional, deterministic fixtures |
| `services/providers.py` | Mode → provider selection; no silent fallback |
| `database/` | ORM models, idempotent observation repository |
| `api/` | FastAPI app factory, middleware (limits, headers, CORS), routes, schemas |

The suggested `apps/api` / `packages/shared-schemas` split was not adopted: the backend stays
one Python package, and the web app lives in `apps/web`.

## Web UI (`apps/web`)

Vite + React + TypeScript + Tailwind v4, chosen over Next.js because the UI is a pure client of
the API (no server rendering needed) and the dev server must stay light on an 8 GB machine.

| Path | Responsibility |
|---|---|
| `src/api/` | Typed client: same-origin `/api/v1`, timeouts, `ApiError` with the backend's error codes; response types mirror the pydantic models (hand-maintained) |
| `src/app/` | Layout, global mode banner (demo / no RPC / provider error / unreachable API), `/status` context |
| `src/pages/` | Dashboard, Settings, and the wallet page with Overview, Permissions, Timeline, Findings and Address-poisoning tabs |
| `src/components/` | Shared UI: severity + confidence badges, full-address display, safe external links, limitation lists |
| `src/lib/` | Explorer-link allow-list, UTC formatting, async state hook |

The UI holds no configuration or secrets: mode, chain and provider come from `/status`. All
large integers stay strings. Untrusted text (token symbols, labels, explanations) is only
rendered as React text; external links are restricted to known block-explorer hosts over
https and omitted entirely for simulated data. Addresses are identified in full (the shortened
form appears only to illustrate a lookalike's wallet display).

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

## Data flow: `POST /api/v1/wallets/{address}/snapshots`

1. Load the last ≤10 non-orphaned snapshots; re-fetch each block's hash. Snapshots whose block
   was reorganized out are marked `orphaned`, stored Approval events above the surviving base
   are deleted (they are re-ingested from the canonical chain), and the base moves back.
2. Pick block `B` (default `head − SNAPSHOT_CONFIRMATIONS`); `B` must not precede the base.
   Same block as the base → return it unchanged.
3. Inspect account code at `B`; discover Approval and Transfer events in `(base, B]`;
   look up outgoing transfers' signers; re-verify carried + new approval pairs.
4. Re-check `B`'s hash; build state; delta vs. base; run the detectors (state rules, and
   address poisoning over stored + new transfers).
5. One transaction: insert events and transfers, snapshot row, finding creates/updates and
   transitions.

## Threat graph

`GET /wallets/{address}/graph` reads only stored data: the latest canonical snapshot (approvals,
balances, delegation at its block), the wallet's stored transfers, open findings, and the
poisoning detector re-run over those transfers. Edges: `APPROVED_SPENDER`, `HOLDS_TOKEN`,
`DELEGATES_TO`, `TRANSFERRED_TO`, `RECEIVED_FROM` (observed, each with evidence: reads at the
snapshot block or Transfer/Approval transaction hashes) and `RESEMBLES` (heuristic address
similarity, labelled as inferred). Findings annotate nodes; no edge asserts wrongdoing.

Limits: at most `max_nodes // 2` approvals (riskiest first: flagged spenders, unlimited,
unknown). Counterparties are ranked (poisoning participants, flagged, wallet-paid, volume) and
the rest folded into one explicit summary node. The UI uses a deterministic radial preset
layout (permissions above the wallet, transfers below, lookalikes next to what they imitate)
and lists every edge as keyboard-accessible text alongside the canvas. Cytoscape is loaded
lazily; its normally injected container style is shipped in our CSS so the strict CSP holds.

## Historical incident replay (`replay/`)

| File | Role |
|---|---|
| `replay/models.py` | `IncidentManifest` (public-source ground truth, scoring only) and `ReplayFixture` (recorded chain data, the only detector input) |
| `replay/record.py` | Records a fixture: all ERC-20 transfers of the wallet in the window, signers, every wallet-signed transaction via nonce bisection, wallet code, block timestamps |
| `replay/engine.py` | Offline, deterministic point-in-time replay at every event block; two visibility levels; leakage checks; runtime and memory |
| `replay/report.py` | Renders `EVALUATION.md` from replay results only |
| `replay/cases/<id>/` | `manifest.json` + `fixture.json` per incident (fixture hashed in every result) |

The engine's detector entry point (`detector_outputs`) takes no manifest, so ground truth
cannot leak into detection; each checkpoint asserts that no input is newer than the cutoff.
A warning counts as early only if it appears at a block before the harmful transaction; a
finding that needs the harmful transfer itself is reported as post-incident classification.

## Storage

`address_observations` stores each observation with block number, block hash, block
timestamp (chain time) and `observed_at` (CryptoGuard time) as separate columns, plus the
schema version and data source. Inspections and approval-scan reports both live here,
distinguished by `observation_type`. `approval_events` stores each decoded `Approval` log,
unique on `(chain_id, block_hash, log_index)`, with the uint256 value as a decimal string.
`wallet_snapshots` (unique per chain, wallet, block hash, data source) stores canonical state,
`state_hash`, the delta, cumulative coverage, token scope, ruleset version and the link to the
previous snapshot. `findings` (unique per chain, wallet, fingerprint) holds current status,
severity, confidence and evidence; `finding_transitions` is the append-only audit trail.
`token_transfers` holds each wallet's ERC-20 transfers (unique per chain, wallet, block hash,
log index) with the transaction signer when known. `wallet_transactions` holds the wallet's
own signed transactions (unique per chain, wallet, tx hash, block hash); snapshot state
(`wallet-snapshot/2`) records the wallet nonce so the next snapshot starts from it.
All times are UTC. Schema creation currently uses
`create_all`; Alembic migrations must be introduced before the first schema change.

## Extension points

- New chain-data sources implement `EthereumProvider` (e.g. an indexed-history provider).
- Detectors implement `Detector` (`detector_id`, `version`, `analyze(DetectionContext)`).
  They are synchronous and pure: services do all chain I/O first, so detectors are
  deterministic and can be replayed on stored data. They return finding candidates only;
  the lifecycle, storage and presentation stay elsewhere.

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

- No Alembic migrations yet (`create_all` only). Every schema change so far only added tables;
  migrations are required before any existing table changes.
- Snapshots are taken on request; there is no scheduled monitoring loop yet. The previous
  snapshot acts as the ingestion checkpoint.
- Reorg rebase looks back at most 10 snapshots; findings first seen in an orphaned snapshot
  keep that reference (their status is still reconciled by the next canonical snapshot).
- A wallet's token scope is fixed at its first snapshot; changing it requires a purge.
- ERC-20 call results are trusted to follow the standard; tokens with non-standard
  `transferFrom` semantics (rebasing, fee-on-transfer, blocklists) can make the exposure bound
  inexact.
- EIP-7702 authorization-list parsing and authority recovery (secp256k1 `ecrecover`) are not
  implemented; current delegation is read from code only, so delegation *history* is unknown.
- Chain verification is cached for the process lifetime; an endpoint that switches chains
  mid-run would only be caught by `/status` or a restart.
- `starlette.testclient` warns that `httpx` support is deprecated; tests will need to move
  to its replacement in a future upgrade.
