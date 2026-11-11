# Protocol 12.4: observation completeness and candidate discovery

**Frozen:** 2026-11-04, in the commit that adds this file. That is before the extended observation code exists, and before any C1 or C2 output is computed on a recorded window.

**Development analyses already performed:** the code audit, and the reconstruction of the missed Stage 2a case from its recorded fixture (§3). They are labelled as such.

**RPC:** 0 requests. No budget is open, and none is requested here.

## 1. Question

Does observing more of the historically available chain evidence, and stating explicitly what was *not* observed, let CryptoGuard find poisoning candidates the frozen pipeline misses? And can it do so without unsupported claims or a flood of warnings?

## 2. Contamination policy

- **Original results stay fixed.** The two Level I cases (`usdt-counterfeit-39890-2026-08-09`, `scamsniffer-763k-2025-02-20`) keep their original results as recorded in Phase 12.3. Those results are frozen by regression tests and are never rewritten.
- **The cases are now known.** For any method written after their outcomes were known, they are **development cases (P3)**. A method that recovers the missed address on them is a **development-case regression success**, never independent validation.
- **Five records are kept apart:**
  1. the frozen detector and generator (C0) and their original outcomes;
  2. the extended observation pipeline (`observation/2`);
  3. the new candidate rules (C1, C2);
  4. changes motivated by the known cases, marked `motivated-by: P3`;
  5. future untouched data. None exists yet.

## 3. Development analysis already done (not confirmatory)

**The Stage 2a miss**, from its fixture only:
- The victim paid the reference `0x80404f3e…793375` at block 21,890,495.
- Two fake-token lookalikes were planted after that, and both were warned.
- The paid address `0x804051b0…793375` appears **nowhere in any local artifact** before the theft.

**The recorder (`observation/1`) does not collect:**
- inbound native ETH;
- zero-value native transactions;
- internal value transfers (no trace access);
- ERC-1155 events.

It also fetches ERC-721-shaped and malformed `Transfer` logs, then **discards** them without persisting even their counts.

**The cause of the miss is therefore not identifiable from local data.** Native-ETH dust is one hypothesis among several.

## 4. Hypotheses

| ID | Hypothesis | Population | Baseline | Measure | Fails if |
|---|---|---|---|---|---|
| H1 | `observation/1` omits event classes used by documented poisoning mechanisms | P1 and the code audit | — | event classes present in a controlled source but absent from `observation/1` | every class used in P1 is recorded |
| H2 | Correctly recording those classes recovers candidates invisible to C0, with the rules unchanged | P1 | C0 on `observation/1` | exact count of oracle candidates recovered by C1 on `observation/2` and not by C0 | C1 recovers no extra oracle candidate, or adds any non-oracle candidate in P1 |
| H3 | Category-scoped completeness prevents unobserved activity being reported as zero | P1, plus all local fixtures (metadata only) | `wallet-history/1` (one window-wide boolean) | features that are a number under `/1` but undefined under strict scope, for the same input | strict scope changes no feature on any input where a category was not collected |
| H4 | Keeping signer, event-sender, token and transaction provenance prevents false equivalences | P1 cases B, C, G, J, K, L | — | oracle agreement | any case disagrees with its oracle |
| H5 | Temporal or graph context adds information beyond the deterministic signals, on a valid diagnostic task | P3, P5 | C0 order | — | **pre-declared NOT EVALUATED unless a labelled population exists.** None does for the new classes: P4 has no native or NFT observations. P3 and P5 are only described. |
| H6 | The extension runs in bounded memory and acceptable time | P1, P3, P5 | C0 | runtime, peak traced memory, candidates per wallet-day | peak > 200 MiB, or more than 10× C0's runtime |

**C2** is the experimental semantic rule set. It is motivated by P3, as recorded in §2.
- **Payment-time screen:** at the moment of a wallet-signed payment, the recipient is checked against the wallet's own pre-payment references, using the same similarity rule as C0. It needs no planting observation. The recipient is the user's own pending input, never an outcome label.
- **Abstention:** when the reference history is unavailable, C2 reports *insufficient history* instead of "no candidates".

C2's alert volume on P5 is **reported**, never called a false-positive rate, because P5 is unlabelled.

## 5. Populations (never pooled)

| ID | What it is | Supports |
|---|---|---|
| P1 | Synthetic cases A–L, with oracles written independently of the implementation in the test file | correctness and mechanism coverage only; no rates |
| P2 | The 4 packaged replay fixtures | **excluded from computation**: they hold frozen Cohort B items. Coverage metadata only. |
| P3 | The 2 Level I cases | development-case replay and diagnosis |
| P4 | Research archives | not used: no native or NFT observations, and an expensive pass |
| P5 | Background windows without frozen items (6 of 9) | candidate and alert volume, coverage, runtime. Unlabelled: not benign. |

## 6. Fairness

Within a window, every variant gets:
- the same cutoff, `(block, tx index)` strictly before;
- the same window;
- the same deduplication key, `(chain, tx hash, log index)`, or `(chain, tx hash, -1)` for a transaction's own value;
- the same similarity rule as C0 (`MIN_AFFIX` 6, `MIN_SUFFIX` 3).

Changes to the candidate set are reported as set differences: added, removed and kept.

## 7. Stop and integrity rules

- The detector, OP0, OP1 and `ml.candidates` (C0) are unchanged, and production findings are unchanged.
- `observation/2` is opt-in. `observation/1` fixtures keep their bytes and hashes.
- No new RPC request, no download, no paid API, and no change to the frozen cohorts.
- No label is created. Nothing unknown is treated as benign.
- Gates are labelled PASS, PASS WITH LIMITATIONS, FAIL, BLOCKED BY DATA or NOT EVALUATED. A gate never passes merely because code exists.
