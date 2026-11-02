# Evidence completion and review readiness (Phase 11.7)

**State: still REVIEW_READY: HUMAN ANNOTATION PENDING.**

| Item | Status |
|---|---|
| Finalized human submissions | 0 |
| Human-reviewed items | 0 of 95 (190 decisions pending) |
| Reviewers recruited | none |
| RPC requests / downloads | 0 / 0 |
| Model trained | none |

## 1. Executive summary

- **Evidence recovered offline.** One extra streaming pass over the local archive gave
  all 19 Cohort B archive items that had *no* local wallet history some pre-cutoff rows.
  Cohort B's median rose from 0 to 18 rows.
  - The rows are still only what the source kept, never complete history.
- **Evidence semantics fixed.** The packets now:
  - count same-block rows of unknown order instead of dropping them silently;
  - say what "no earlier interaction" means under complete, source-selected or absent
    coverage.

  These changes are registered as amendment 3, before any review or package.
- **The remaining evidence gap needs authorization.** Signers are unknown for 85 of 95
  items, receipts for all 95, and token legitimacy for 28 tokens. Local data cannot close
  this; about 292 RPC requests could (§19).
- **Independent corroboration.** PTXPhish (expert-reviewed, NDSS 2025) holds 214
  address-poisoning transactions. 207 of them are Tsuchiya payoffs. Where both sources
  name an attack method (173), they agree 141 times (81.5%). For 11 Cohort A items, the
  victim's later payment is a PTXPhish transaction, and the methods agree 11 of 11.
  - This corroborates *losses* and attack methods at the source level. It is not review
    of the plantings.
- **Negative finding.** On archive-style data, which has no signer, `candidates/2`
  re-emits only 6 of 1,409 source positives (0.4%), or 51 (3.6%) with an optimistic signer
  assumption. Its main planting rule needs the transaction signer.
- **Hardening.**
  - The review server now refuses negative or malformed `Content-Length` (a negative
    value made it read until the client closed) and foreign browser `Origin`s.
  - New tests: an independent reference implementation for the generator, and a full
    synthetic review workflow with failure injection.
  - `ml verify-research` reports reproducibility status.

## 2. Research state

**Track A** (PTXPhish classifier) is unchanged and separate.

**Track B** (wallet-centric poisoning):
- the production rule detector stays the baseline;
- the pre-registered ML comparison (`docs/ml/experiment-spec.json`) is inactive;
- no labels exist.

## 3. Frozen cohort integrity

Both cohorts verify byte for byte (`ml review verify`, `ml verify-research`):

| | Cohort A (60 items) | Cohort B (35 items) |
|---|---|---|
| Selection | `e368beb4…` | `ae9df36a…` |
| Sheet | `a0ec4b6e…` | `121c112d…` |
| Key | `407b412f…` | `f333386d…` |
| Manifest | `c38ae31d…` | `05dc1b16…` |

- The design audit still passes.
- The only change is amendment 3: new evidence-packet files, registered by hash. The
  frozen sheets, keys and manifests are untouched.

## 4. Evidence availability (all 95 items)

**Matrix.** The item-level matrix is local (`data/ml/poisoning/review/
evidence_coverage_matrix.jsonl`, git-ignored). Aggregates:

| Field | Cohort A (60) | Cohort B (35) |
|---|---|---|
| Candidate transfer available | 60 | 35 |
| Signer known | 0 | 10 (recorded-wallet items) |
| Receipt recorded | 0 | 0 (a recorded Transfer log implies success) |
| Token on the reviewed list | 33 | 29 |
| Wallet rows before cutoff (median) | 22 | 18 (was 0) |
| Items with no local wallet rows | 0 | 1 (a recorded wallet with an empty window) |
| Earlier rows between wallet and address | 26 | 3 |
| Graph context available | 60 (archive) | 24 (archive) |
| Same-block rows of unknown order | 4 items | 1 item |

## 5. Cohort B historical coverage

**Before:** 19 of the 24 archive items had no local wallet row before the cutoff.

**After the recovery pass:**
- 0 of 24 archive items lack rows;
- 24 items gained rows;
- the 11 recorded-wallet items are complete for their window, but nothing before it.

## 6. Offline recovery attempts

| Source searched | Review wallets found | Usable? |
|---|---|---|
| Tsuchiya archive, new targeted pass (wallets, addresses, txs of all 95 items) | all | **yes**: 24,142 rows, 1,369 s, peak 256 MiB |
| Existing archive subsets | Cohort A only | already used |
| Recorded replay windows | 7 Cohort B wallets | already used |
| Pilot recordings | 0 | no |
| Poison-Hunter sample | 0 | no |
| PTXPhish chain records | 11 Cohort A wallets | **no**: all 11 are the victims' *later* payments (20 to 930,525 blocks after the cutoff). They are outcomes, so they are excluded from evidence |

- **What no local source has:** transaction signers, receipts or token metadata for
  archive-derived items, and complete ordinary history for any archive wallet.

## 7. Point-in-time guarantees

- **The cutoff** is the candidate's block, and the evidence position is just before the
  candidate's transaction.
  - Rows strictly earlier are shown.
  - Same-block rows are shown only when the recorded transaction order proves they came
    first.
  - Same-block rows of unknown order are *counted* and flagged, never shown or dropped
    silently.
- **What the packets never read:** flags, intended addresses, payoffs or labels.
- **Tests:** metamorphic tests cover future rows, later payoffs, relabelling, future graph
  edges, duplicates across sources and reordering.
- **Checks on the real packets:** no payoff transaction and no source label appear. All
  10 history rows dated in the cutoff block are recorded-window rows of proven earlier
  order.

## 8. Reviewer evidence quality

**Can a reviewer recognise impersonation without being told the answer?**

- **Cohort A: yes, partially.** In all 60 packets the imitated counterparty is visible as
  an earlier counterparty. Reviewers must find it themselves; no similarity is computed.
  But the archive keeps only look-alike-related rows, which can make attacks look more
  obvious than a full history would (disclosed).
- **Cohort B: now yes, for every archive item.** The recorded-wallet items show their full
  window.
- **Wording.** The evidence panel's wording and the reviewer guide now explain each
  coverage case, including that a missing interaction under partial coverage is not
  novelty.

## 9. Review application fixes

**Defects fixed:**
- **P1:** a negative `Content-Length` made a handler read until the client closed.
  Non-numeric values crashed the handler. Both now get 400.
- **P2:** a request carrying a foreign `Origin` header was accepted. It is now refused;
  the existing token header already blocked cross-site requests.

**Checked and found adequate:**
- a 24-byte session token sent only in a header;
- the token lives in the URL fragment, which browsers never send to the server or as a
  Referer, and is removed from the address bar;
- 12-hour expiry, a Host check, strict CSP, a static whitelist (no file paths from
  requests) and a 64 KiB body cap;
- no request logging;
- answer keys never loaded by the server;
- stores and finalization separate per reviewer.

**End-to-end synthetic workflow** (test). Package, then HTTP saves, then a server restart
(the old token is refused and saved work kept), a torn save recovered, finalization,
submission check, a corrupt export refused, premature unblinding refused, agreement, and
unblinding with exactly one logged key access. The synthetic reviewers are software
fixtures.

## 10. Statistical validation

Agreement and estimators were already tested against hand-computed values (Phase 11.4,
11.6). New this phase is the sufficiency table (`ml/power.bound_table`): the upper bound on
FPR when 0 or 1 of *n* reviewed legitimate events is flagged.

| n | Design effect | Upper bound, 0 flagged (one-sided 95% exact) | Upper bound, 1 flagged | Upper bound, 0 flagged (two-sided 95% Wilson) |
|---|---|---|---|---|
| 30 | 1 | 9.5% | 14.9% | 11.4% |
| 35 | 1 | 8.2% | 12.9% | 9.9% |
| 50 | 1 | 5.8% | 9.1% | 7.1% |
| 100 | 1 | 2.95% | 4.7% | 3.7% |
| 100 | 2 | 5.8% | 9.1% | 7.1% |
| 300 | 1 | 0.99% | 1.6% | 1.3% |
| 1,000 | 1 | 0.30% | 0.47% | 0.38% |

**Reading the table.**
- 35 negatives, even all correct, cannot show an FPR below about 8%.
- A 1% claim needs about 300 effectively independent negatives with no error.
- These describe the sampled population only. Neither cohort's class mix is prevalence,
  and the two are never pooled.

## 11. Benchmark design

`docs/ml/experiment-spec.json` (generated from `ml/experiment_spec.py`, inactive) now also
fixes:
- **fairness:** same events, cutoff, labels and split for rules and models;
- **label provenance:** for positives, negatives and unknowns;
- **candidate population:** defined before any model;
- **an untouched test set;**
- **six label-count stages:** smoke test, exploration, tuning, estimation, low-FPR claim,
  generalization;
- **an ablation without source proxies:** no value, token or shape features, because they
  separated the source frames almost perfectly.

## 12. Valid offline diagnostics (`ml diagnostics`, aggregate)

**A. Source-positive candidate coverage.**
- **Population:** 1,409 payoff-linked source positives (60 reserved excluded): 745 fake
  token, 614 spoofed `transferFrom`, 50 dust.
- **Method:** a 7-day history of source-selected archive rows before each planting.

| Mode | Emitted | Fake token | Spoofed transferFrom | Dust |
|---|---|---|---|---|
| strict (no signer known) | **6 (0.4%)** | 0/745 | 2/614 | 4/50 |
| optimistic (victim's own non-poisoning sends signed) | 51 (3.6%) | 0/745 | 2/614 | 49/50 |

- **Why so low.** Fake-token and spoofed plantings appear as transfers *from* the victim
  (98% in the archive). The rule for them (`spoofed_out`) needs the planting transaction's
  real signer, which the archive does not record. With known signers, dust plantings are
  found by `lookalike_in` (49/50).
- **What this is.** A structural limitation measured on source-selected data, not the
  generator's recall on real wallets. It is the clearest evidence that signer data is the
  bottleneck.

**B. Evidence availability:** §4.

**C. Generator invariance** on all 13 recorded windows: reordered input, upper-case
addresses and added future activity leave the candidates identical (13/13 each).

**D. Scalability** (synthetic, with memory tracing on, which slows it):

| Transfers | Time | Peak memory |
|---|---|---|
| 1,000 | 0.09 s | 1.0 MiB |
| 10,000 | 0.90 s | 9.9 MiB |
| 30,000 | 2.95 s | 28.4 MiB |

Without tracing, 10,000 transfers take 0.13 s, as before.

**E. Source agreement (PTXPhish vs Tsuchiya).**
- 207 of 214 PTXPhish poisoning transactions (96.7%) are Tsuchiya payoffs.
- Attack-method agreement on the 173 linked to an attempt: 141 (81.5%). Most disagreements
  are PTXPhish "zero-value" cases whose latest attempt before payment was a fake token (19),
  consistent with competing plantings.
- **Caveat:** the two datasets may share upstream signals (for example explorer phishing
  tags), so this is corroboration, not independence proof.

**F. Rule-failure taxonomy.** The demonstrated failure (A) is missing signer data. No
other failure class is claimed without labels.

## 13. Candidate-generator evaluation

- **Independent reference.** A new test re-implements `candidates/2` from its documented
  rules: its own affix comparison and choice set, with no shared code. It matches on 40
  random fixtures. These include shared suffixes, checksum-case addresses, unknown and
  third-party signers, and untrusted tokens.
- **Malformed addresses** neither crash nor match.
- **Suffix bucketing is exact:** the rule requires at least 3 shared trailing characters.

## 14. Code quality

| ID | Pri | Finding | Status |
|---|---|---|---|
| 41 | P1 | Negative or non-numeric `Content-Length` in the review server | Fixed; test |
| 42 | P2 | Foreign `Origin` accepted | Fixed; test |
| 43 | P1 | Evidence silently dropped same-block rows of unknown order | Fixed (`evidence-packets/2`); test |
| 44 | P1 | "0 earlier rows" read the same under complete and partial coverage | Fixed: coverage-specific wording; test |
| 45 | P2 | `verify-research` would report absent frozen files as FAIL | Reported as MISSING; test |
| 46 | P2 | Corrupted lease database: confirmed not mapped to `LeaseBusyError` | Test added; no change needed |

**Reviewed, not changed.**
- Two `_canonical` JSON helpers (review sample vs annotation) differ by design. Each is
  the frozen hash basis of its artifact; unifying them would change committed hashes.
- No other duplicated logic was found to cause an inconsistency.

## 15. Security findings

- **Review server:** §9.
- **Data:** all archive-derived files, packets, matrices, packages and diagnostics stay
  local. Only code, specs and aggregates are committed.
- **No secrets** in logs (the server logs nothing).
- **Parsing:** archive parsing never executes SQL. The SQLite queries take parameters,
  and their only f-string is a fixed column list.

## 16. Testing and CI

The PR description records the counts from this phase's full run. New tests:
- `tests/unit/test_ml_evidence_completion.py`: same-block ambiguity, coverage wording,
  duplicates, future graph edges, Origin and length refusal, the independent generator
  reference, malformed addresses, exact bounds, spec export, offline verification, a
  corrupt lease database, and the end-to-end workflow.

## 17. Resource usage

| Step | Runtime | Peak |
|---|---|---|
| Recovery pass (35 M rows) | 1,369 s | 256 MiB |
| Evidence rebuild (95 items) | about 20 s | under 400 MiB |
| Diagnostics | 263 s | (not traced) |
| Verification incl. 2.3 GB hash | about 30 s | small |
| Disk | +11 MB (`review_context.sqlite`) | |

0 RPC requests.

## 18. Remaining human dependencies

1. Two independent human reviewers for both cohorts: 190 decisions, plus training.
2. Without them, gates E, F, I and J cannot move.

## 19. Remaining data dependencies

**Proposed, not executed.** Separate approval is needed for a provider with historical
(archive) state. The request:
- `eth_getTransactionByHash` for the 85 items with unknown signers;
- `eth_getTransactionReceipt` for all 95 planting transactions (status and log emitter);
- `eth_getCode` and `name`/`symbol`/`decimals` at the cutoff block for 28 unreviewed
  tokens.

**About 292 requests; cap 365 with retries.** It would close the signer, receipt and token
gaps for every review item. Complete ordinary wallet history is a far larger collection
(ML_HUMAN_VALIDATION_READINESS.md §15).

## 20. Highest-value next research action

**Recruit the two independent reviewers** and start the review with the current packets.
It needs no new data and no authorization. Everything else waits on their decisions.

**If you prefer to close the signer gap first,** the request in §19 is small and exactly
sized. Deciding on it is yours.

## Decision gates

| Gate | Status |
|---|---|
| A Frozen sample integrity | **PASS** |
| B Evidence quality | PASS WITH LIMITATIONS (history for 94/95; signers unknown for 85, receipts for 95) |
| C Historical correctness | **PASS** (metamorphic tests; real-packet leak checks) |
| D Reviewer independence | PASS WITH LIMITATIONS (procedural on shared computers; no humans yet) |
| E Positive labels | BLOCKED BY HUMAN REVIEW |
| F Negative labels | BLOCKED BY HUMAN REVIEW |
| G Source bias | PASS WITH LIMITATIONS (measured and documented; selection bias remains) |
| H Leakage-safe splits | PASS WITH LIMITATIONS (guards tested; no real labelled split) |
| I Statistical adequacy | **FAIL** (0 labels; 35 negatives cannot bound FPR below about 8%) |
| J ML comparison readiness | BLOCKED BY HUMAN REVIEW (spec inactive; signer data also missing for rule replay on archive items) |
| K Production isolation | **PASS** |
| L Engineering quality | **PASS** (defects 41-46 handled; tests and CI listed in the PR) |
