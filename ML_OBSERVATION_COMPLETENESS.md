# Observation completeness and candidate discovery (Phase 12.4)

| Item | Value |
|---|---|
| Protocol (frozen before the code and the study) | [`docs/ml/protocol-12.4.md`](docs/ml/protocol-12.4.md), `3a79b74` |
| Implementation (committed before the study ran) | `3917957` |
| Study output (git-ignored) | `data/ml/research/phase12.4/observation-study.json` (`cryptoguard ml observation-study`) |
| New RPC requests / downloads | **0** / none |

## 1. Executive summary

**The miss.** The Stage 2a miss (`scamsniffer-763k-2025-02-20`) **cannot be explained from local evidence**. The paid address occurs in no local artifact except the theft records themselves.

**What the audit confirmed.** The recorder, `observation/1`, does not observe several event classes:
- inbound native ETH;
- zero-value native transactions;
- internal value transfers;
- ERC-1155 events.

It also fetches ERC-721-shaped and malformed `Transfer` logs, then discards them **without keeping even their counts**. So the miss is compatible with several mechanisms, and native-ETH dust remains one hypothesis among them. Two RPC requests would discriminate between them; see §31. They were not made.

**What changed:**
- **`observation/2` (opt-in):** it records the following:
  - native ETH received, found by balance bisection with exact per-block accounting;
  - ERC-721-shaped transfers;
  - malformed-log counts;
  - completeness for each event category.

  An unobserved category is `not_collected` or `unsupported`, never zero. Every existing fixture keeps its bytes and hash.
- **Shadow discovery (`poisoning-candidate-discovery/1`):**
  - **C1** is C0's own rules applied to every observed class. On synthetic cases it recovers native-dust and ERC-721 lookalikes that C0 cannot see.
  - **C2** adds abstention and a **payment-time screen**. The screen flags both known thefts. That is a *development-case regression* result, not validation, because those cases motivated it. It flags 0 of 12 screened unlabelled payments in the background windows.
- **A latent defect, fixed in a versioned path.** `wallet-history/1` reports inbound counts as observed zeros, although native inbound and ERC-721 were never collected: 109 values across 29 in-window queries. No published number used those counts.

**Classification:** confirmed observation improvement, verified on synthetic and mock data only. Also a limited mechanism improvement. For the real miss, the result is data-limited. H5 (ML contribution) was not evaluated, as pre-declared.

## 2. Repository baseline

| Item | Value |
|---|---|
| Initial HEAD | `72cfaf3`, clean, equal to `origin/feature/ml-pipeline` |
| CI on `72cfaf3` | 9 of 9 jobs passed |
| Production detector | `address-poisoning` 1.0.0, unchanged |
| Frozen generator (C0) | `candidates/2`, unchanged |

## 3. Motivating failure, and 4. its exact chronology

Source: the recorded fixture `67e44177…`. Times are block-header timestamps (UTC, 2025-02-20).

| Block (tx index) | Time | Event | Signer | Recorded by `/1` | C0 candidate |
|---|---|---|---|---|---|
| 21,890,495 (65) | 22:19:23 | Victim sends token `0x44ff…` to the reference `0x80404f3e…793375` | victim | yes | (reference) |
| 21,890,508 | — | Victim sends 600 ETH to the reference | victim | yes (wallet transaction) | (reference) |
| 21,890,558 (112) | 22:32:23 | Fake-token `0x29f7…` Transfer "from victim" to `0x8045233d…793375` | `0x7730…Ba3f` | yes | yes (`spoofed_out`) |
| 21,890,871 (72) | 23:35:23 | Fake-token `0x6695…` Transfer "from victim" to `0x804041c8…1f3375` | `0x0C0b…2bb9` | yes | yes (`spoofed_out`) |
| 21,890,874 | — | `0x9008d19f…` (a swap settlement contract) credits the victim with 96,517… base units of `0x44ff…` | — | yes | no |
| 21,890,897 (96) | 23:40:35 | **Theft**: victim sends `0x44ff…` to `0x804051b0…793375`. This is the paid address's first appearance. | victim | yes | — |
| after the window | — | 5 further transfers to the same address (from `found.json`) | victim | not in the window | — |

**Where the paid address appears.** A search of the whole repository and `data/` finds it in exactly two places:
- the theft transfer in the fixture;
- the six theft receipts in `data/ml/research/stage2a/…/found.json`.

**Classification of the miss: unknown.** Each possible cause, and its status:
- **Confirmed recorder omissions** that could explain it:
  - inbound native ETH, nonzero or zero;
  - ERC-721 or ERC-1155 plantings;
  - internal transfers.
- **Not excluded:**
  - an off-wallet channel, such as the reference's own page, another wallet of the victim, or an address book;
  - a planting before the window. That is unlikely here, because the reference use itself lies 402 blocks before the theft.
- **Source attribution:** the roles came from Etherscan's filter semantics, and the chain did not contradict them.

**Counterfactual (synthetic only).** In synthetic case A, a native-dust lookalike planted after a reference payment is invisible to C0 and found by C1. That shows the new support works. It does **not** show that this real case was a dust planting.

## 5. Observation pipeline audit

`eth_getLogs` and `scan_logs` (bounded, newest first, chunks split on refusal)
→ `classify_transfer_log` (3 topics plus 32 bytes is ERC-20; 4 topics and no data is ERC-721-*shaped*; anything else is malformed)
→ `discover_transfers` (both directions; outgoing signer by `eth_getTransactionByHash`; dedup by block hash and log index)
→ `locate_wallet_transactions` (nonce bisection, with receipt status for transactions carrying ETH)
→ `ReplayFixture`
→ `detector_outputs` (ERC-20 events plus wallet-signed native sends, at or before the cutoff; no manifest)
→ `detect_poisoning`.

The research side runs alongside: `ml.history.events_from_fixture` → `history_features` (`wallet-history/1`) and `ml.candidates.generate` (C0) → `warning_rank` (OP1).

| Defect or limitation | Where | Status |
|---|---|---|
| ERC-721-shaped and malformed logs were fetched, discarded, and their counts not persisted | `discover_transfers`, `record_window` | **fixed** in `observation/2`: records and counts kept |
| No inbound native ETH (no per-address index) | recorder | **fixed** in `observation/2`: balance bisection, for plain EOAs |
| A single window-wide `Coverage.complete` turned unobserved inbound into zeros | `ml/history.py` | **fixed** in the versioned `wallet-history/2-scoped`; `/1` kept, so no result changes |
| `touches_frozen` inspected ERC-20 transfers only | `recency_validation` | widened rule `touches_frozen_any` added. It changes no existing exclusion: P5 is 3/3 excluded and 6/6 admitted under both rules. |
| ERC-1155, zero-value native, internal transfers | — | declared `not_collected` / `partial` / `unsupported` |

## 6. Ethereum transaction semantics, and 7–9. coverage

| Class | `/1` | `/2` | Source and semantics | Tests |
|---|---|---|---|---|
| T1 native external out | wallet-signed (nonce bisection) | same | `tx.from`, `to`, `value`, index, status | existing |
| T1 native external in | **not collected** | **complete** (nonzero; plain EOA) | balance bisection; senders from the increase blocks | `test_balance_bisection…` |
| T2 ERC-20 Transfer | complete | complete | the event's `from`/`to` are not the signer | existing; case B |
| T3 zero-value ERC-20 | recorded; `zero_value_in` | same | C0 rule | case D |
| T4 fake token | recorded | same | untrusted by **contract**, never by symbol | case C |
| T5 spoofed `transferFrom` | recorded, signer looked up | same | `spoofed_out`; never a reference | case B |
| T6 internal ETH | **unsupported** | unsupported, with **unattributed** balance credits recorded (no sender) | needs traces | case H; recorder test |
| T7 reverted | outgoing: status kept | inbound: not a transfer (no balance change) | receipt status | case G; recorder test |
| T8 contract-mediated | signer kept; foreign signer means unconfirmed | same | — | existing |
| T9 self-transfer | — | skipped as a counterparty | — | `observations()` |
| T10 duplicates | dedup by block hash and log | dedup by (tx hash, log index or -1) | — | case L |
| ERC-721-shaped | **discarded** | **recorded** | 4 topics, token id kept | recorder test |
| Malformed `Transfer` | **discarded** | **counted** | not decoded | recorder test |
| ERC-1155 | not queried | not queried | `TransferSingle`/`TransferBatch` | declared |
| Zero-value native in | not collected | **partial** (only in blocks read for other reasons) | moves no balance | recorder test |

## 10. Point-in-time invariants

- **Cutoff semantics:** discovery uses observations strictly before `(block, tx index)`.
- **Same-block order** is respected (case I).
- **Tests confirm** that a later planting, a later theft or later native inbound does not change discovery at an earlier cutoff, and that record order does not change the output.
- **Finality:** fixtures are recorded at confirmed blocks, as before. No chain monitor was added.

## 11. Completeness model

`replay/observation.py` gives each category one of these statuses: `complete`, `partial`, `truncated`, `interrupted`, `rejected`, `not_collected`, `unsupported`, `unknown`.

- **`coverage_of`** returns the stated coverage of an `observation/2` fixture, or derives an honest `observation/1` coverage from the documented method.
- **Inbound scope.** A complete inbound history means ERC-20, ERC-721-shaped and nonzero native transfers. Zero-value native and internal transfers can never be complete here, and the scope says so.

## 12. Native ETH support

**Method.** A plain EOA's balance cannot fall without a transaction it signs. So within each run of blocks without an own transaction, bisecting `eth_getBalance` finds every block where the balance rose.
- That block's transaction list names the external senders.
- When values don't add up, receipts are read.
- Any remainder is **unattributed**: an internal transfer, a withdrawal or a fee credit, with the sender unknown.
- Blocks containing the wallet's own transactions are read directly. Internal credits there can't be separated from the fee, so the unattributed category becomes `partial`.
- Wallets with code (contracts, EIP-7702 delegations) are `unsupported`.
- The method never uses an outcome address.

**Cost on the mock end-to-end scenario:**

| Recording | Requests | Recorded |
|---|---|---|
| `observation/1` | 36 | 1 transfer, 1 wallet transaction |
| `observation/2` | 60 (24 more, all reserved in the ledger) | adds 2 native inbound, 1 unattributed, 1 ERC-721 |

On chain, the extra cost is about 2 × (own-transaction runs + 1) balance reads, plus about log₂(run length) reads and one block read per increase block.

## 13. Internal transfers

The RPC layer has no trace method (`trace_*` / `debug_*`), and no local trace artifacts exist.
- **Unattributed balance credits** are the only internal-value evidence, and they name no sender.
- **No internal transfer is fabricated.**
- **Verdict for case 2:** whether an internal transfer was involved is unverifiable without traces.

## 14. Candidate-generator changes

- **C0** is frozen.
- **C1** has no new rule. It runs on typed observations (ERC-20, native, NFT) with provenance: signer, emitter, status, identity.
- **C2** adds abstention, for an incomplete reference history or no reference in the window, and `screen_payment`.
  - **Production:** neither detector nor production finding changes. A test shows `detector_outputs` is identical on `/1` and `/2` recordings of the same chain.

## 15. Hypotheses: results

| ID | Result | Evidence |
|---|---|---|
| H1 | **SUPPORTED** | 6 classes not observed by `/1` (§6). Two were fetched and then discarded. |
| H2 | **SUPPORTED on P1; BLOCKED BY DATA on real windows** | Mock end to end: C1 adds the native-dust lookalike, the ERC-721 lookalike and one non-lookalike `zero_value_in` (a 0-ETH stranger). C0 finds only the fake-token lookalike. No real `/2` window exists, so on P3 and P5, C1 equals C0. |
| H3 | **SUPPORTED** | 109 inbound-dependent values, out of 29 in-window queries × 5 features, are numeric under `/1` and undefined under scope. P3 accounts for 66 and P5 for 43. |
| H4 | **SUPPORTED** | Cases B, C, G, J, K and L match their oracles. |
| H5 | **NOT EVALUATED** (pre-declared) | No labelled population has the new classes. P3 and P5 are described below. |
| H6 | **SUPPORTED** | ≤ 1.3 ms and ≤ 26 KiB traced per window per variant; whole study 0.17 s; peak RSS 68 MiB |

**Disclosure about oracles.** Two oracles were corrected to the *pre-stated* rule definitions after their first run:
- Case E used a 5-base-unit USDT transfer, which is `dust_in` by C0's documented threshold. The case now uses 5 USDT.
- In the end-to-end test, C1's unchanged `zero_value_in` rule fires on a 0-ETH stranger.

Neither correction changed code. The second is a real candidate-volume risk (§21).

## 16. Synthetic mechanism coverage (P1)

All 12 cases (A–L) and the invariance tests pass: 22 tests in `tests/test_ml_candidate_discovery.py`, plus 4 recorder tests in `tests/integration/test_observation_v2.py`. These are correctness counts, not rates.

## 17. Temporal features, 18. graph features, 19. unsupervised ML

- **Temporal (descriptive).** Blocks from the reference's last use to the planting, for C1 candidates with an imitated reference: n = 5, median 20, range 9–60. All five come from the pilot. The Stage 2a plantings are `spoofed_out` and carry no matched reference under C0's rules.
- **Graph.** No planting signer is shared across P3 and P5, so there are 0 cross-wallet links. A shared token contract is never a link (case J).
- **Unsupervised ML.** None was trained. There is no labelled or verified-negative population for the new classes, and fitting an anomaly model on 8 small, mostly empty windows would answer no hypothesis. This is a deliberate negative choice.

## 20. Candidate recoverability, and 21. volume and ambiguity (real windows)

| Window | Population | C0 = C1 lookalikes | Per wallet-day | C2 abstains | Unlabelled payments: screened / flagged |
|---|---|---|---|---|---|
| usdt-counterfeit… | P3 | 6 | 3.0 | no | 0 / 0 (1 abstained) |
| scamsniffer-763k… | P3 | 2 | 0.67 | no | 5 / 0 (1 abstained) |
| bg-003, bg-010 | P5 | 0 | 0 | yes, no reference in the window | 0 / 0 |
| bg-005, bg-013, bg-014 | P5 | 0 | 0 | no | 0 / 0 (1 abstained each) |
| bg-011 | P5 | 0 | 0 | no | 7 / 0 (1 abstained) |

**C1 changes nothing on real windows**, since no `/2` window exists yet.

**Payment-screen volume:** 0 flagged of 12 screened wallet-signed payments, with 6 abstentions. Those payments are unlabelled, so this is **not** a false-positive rate. The sample is tiny.

**Risk on future `/2` windows.** C1 applies `zero_value_in` to 0-ETH native transactions. Any third party can send those, so they can inflate the volume of non-lookalike candidates. C1 lists them, unweighted.

**Development-case payment screen** (motivated by P3; **not validation**):

| Theft | Flagged | Imitated reference | Affix | Recipient seen before |
|---|---|---|---|---|
| pilot `0x053dc459…` | yes | `0x053dba72…` | 4 + 4 | yes |
| Stage 2a `0x804051b0…` | yes | `0x80404f3e…` | 4 + 6 | unknown (inbound not fully observed) |

The screen acts at signing time, so its "lead" is zero blocks but before execution. It needs a wallet integration that CryptoGuard's replay does not model.

## 22. Source selection limitations

- **P3:** two public, large, firm-noticed thefts, both now development cases.
- **P5:** six unlabelled background windows, which are not benign.
- **P2:** excluded (frozen cohort).
- **P4:** unused (no native or NFT observations).

## 23. Existing incident regression outcomes

Both Level I cases reproduce exactly. Their frozen hash-and-result tests pass, and their Phase 12.3 results are unchanged.

## 24. Production isolation

- **Unchanged:** the detector, the risk engine, the API and scoring.
- **Defaults:** `record_window` and `replay record` default to `observation/1`.
- **Isolated:** shadow discovery is research-only, behind `cryptoguard ml observation-study`, and is never called by the scanner.

## 25. Performance, and 28. resources

| Measure | Value |
|---|---|
| Whole offline study | 0.17 s; peak RSS 68 MiB |
| Discovery per window | ≤ 1.3 ms |
| Disk | a study JSON of a few KB |
| RPC requests / downloads | 0 / none |
| Process control | no other process was touched |

## 26. Reproducibility

`observation-study.json` records the git SHA, the protocol, the discovery and scoped-history versions, every fixture's SHA-256 and coverage schema, runtime and peak RSS. Rerunning `cryptoguard ml observation-study` regenerates it offline.

## 27. Tests and CI

| Check | Command | Result |
|---|---|---|
| Lint | `uv run ruff check .` | clean |
| Format | `uv run ruff format --check .` | 278 files formatted |
| Types | `uv run mypy src` | clean (149 files) |
| Tests | `uv run pytest -q` | **893 passed**, 4 deselected (`gpu`/`slow`), 0 failed, 0 skipped |

Of those, 26 tests are new: 22 synthetic and invariance tests, and 4 recorder tests. The CI result is recorded in the PR #1 description.

## 29. Positive findings

1. Two event classes were silently discarded, and four were never observed. All six are now explicit.
2. Native inbound ETH can be observed exactly for plain EOAs without traces, with honest limits.
3. Category-scoped completeness removes 109 false zeros.
4. A payment-time lookalike screen would have flagged both known thefts (development cases).

## 30. Negative findings

1. The real miss cannot be explained from the data recorded.
2. C1 adds nothing on any existing real window.
3. No ML model is justified by the available data.
4. C1's mirrored `zero_value_in` rule adds non-lookalike candidates.

## 31. Unresolved questions, and the queries that would answer them (not issued)

| Query | Requests | What it settles |
|---|---|---|
| Q1 `eth_getTransactionCount(0x804051b0…, 21869296)` and `(…, 21890896)` | **2** | Whether the paid address signed *any* transaction before the theft. If it signed none, a native transfer *sent by it* is ruled out, which leaves contract-emitted logs, NFTs, internal transfers and off-wallet channels. |
| Q2 `observation/2` re-recording of the victim window | about 1,100 (645 measured for `/1`, plus balance bisection and the ERC-721 records) | Native inbound and ERC-721 plantings |
| Q3 `eth_getLogs` for `TransferSingle` / `TransferBatch` with the victim as `to` (topic 3) | 2 × 216 = 432 | ERC-1155 plantings |
| Q4 `trace_filter {toAddress: victim}` over the window | needs a trace-capable provider (a separate approval) | Internal transfers |

## 32. Next scientific experiment

**Proposal:** approve **Q1, 2 requests**, then, if its answer leaves the question open, **Q2 (about 1,100)**.

**Contribution:** it would turn the Stage 2a miss from "unknown" into either an identified observation gap or a confirmed off-wallet channel.

**Comparison it allows:** a first real `observation/2` window, where C1 can be compared with C0.

**Limits:** it remains a development case, never validation. Independent validation still needs untouched incidents recorded with `observation/2` from the start.
