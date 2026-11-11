# Human validation readiness (Phase 11.6)

**State: REVIEW_READY: HUMAN ANNOTATION PENDING.**
- Finalized human submissions: **0**. Real items reviewed: **0** of 95 (190 planned
  decisions).
- No label, benchmark or model exists from this work. 0 RPC requests, 0 downloads.

## 1. Research objective

Can a model distinguish genuine address-poisoning attempts from legitimate activity that
looks like poisoning, using only information available at the prediction cutoff? Phase
11.6 builds the bridge between blockchain evidence, independent human judgment and future
evaluation. It does not answer the question.

## 2. Current annotation status

| Item | Status |
|---|---|
| Reviewers recruited | none |
| Packages issued | none (verified: no annotation log or submission exists under `data/`) |
| Training cohort | built; synthetic only |
| Cohort A `review-sample/1` | 60 items, frozen, evidence packets registered |
| Cohort B `hard-negative-candidates/1` | 35 items, frozen, evidence packets registered |

## 3. Frozen cohort verification

**Both cohorts.** `cryptoguard ml review verify [--cohort …]` re-hashes the raw bytes of
the queue, sheet, key and manifest, recomputes the selection hash and checks ids. Both
pass. Their bytes are unchanged since freezing:

| | Cohort A | Cohort B |
|---|---|---|
| Selection | `e368beb4…85a62` | `ae9df36a…6ddb57` |
| Sheet | `a0ec4b6e…814027` | `121c112d…ca108` |
| Key | `407b412f…03bb2d` | `f333386d…802ad9` |
| Manifest | `c38ae31d…dbdc3` | `05dc1b16…e3868` |

**Cohort A.** The design audit reruns clean: unique items, one per campaign and per victim,
allocation reproduced, reserve order, exact weights.

**Cohort B history**, audited from the files kept in `superseded/cohort_v1_first_draw/`:
- **First draw.** Frozen at 12:45 on 2026-11-02, on commit `59c8207` with uncommitted
  code (manifest `git.dirty = true`).
- **Defect.** Minutes later, a weak-similarity candidate outside the screened block range
  was found to be marked "no known overlap" instead of "insufficient information".
- **Effect.** Comparing the two draws: identical selected items, reserves, strata, weights
  and reviewer sheet bytes. Exactly 3 key rows changed, all `screen_status` of selected
  items (`no_known_overlap` → `insufficient_information`).
- **Why the redraw is valid:**
  - no package was issued and no label existed or was viewed;
  - the frame hash, and therefore the selection hash, changed only through the corrected
    statuses;
  - the selection itself did not change.
- **Record.** The superseded files are kept, and ML_HARD_NEGATIVE_STUDY.md §12 records the
  episode. Independence is not compromised. The one limitation: the design was finalized
  minutes after a draw had been seen by the maintainer, who is not a reviewer.

## 4. Evidence packet quality

**Builder.** `ml/evidence.py` (`evidence-packets/1`):
- deterministic and offline;
- reads the sheet, never the key, and never the source's flags, intended address or
  payoff markings;
- strictly pre-cutoff, with a same-block row included only when the recorded order
  proves it came earlier;
- unknowns are explicit;
- a cutoff that contradicts the data raises `EvidenceError`.

| | Cohort A (60) | Cohort B (35) |
|---|---|---|
| Candidate transfer found locally | 60 | 35 |
| Wallet rows before cutoff | median 22 | none locally for 19 of 24 archive items; the full recorded window for the 11 others (1 of them empty) |
| Earlier rows between wallet and address | 26 items | 3 items |
| Coverage | all `source_selected_rows_only` + `unknown_signer`; 27 also `unknown_token_legitimacy` | 24 archive (19 `partial_history`), 11 `complete_for_declared_scope`; 25 `unknown_signer`, 6 `unknown_token_legitimacy` |
| Packets SHA-256 | `68f11afb…2d46ae` | `1c7f32c6…dc01bf` |

**Checks on the real served state** (counts only):
- 0 of 60 payoff transactions appear;
- 0 source summaries or category labels appear;
- the field name `zero_value` is the packet's observed value flag, not a label.

**The imitated address is visible by design.** In all 60 Cohort A packets it appears
among the earlier rows, as a counterparty the wallet really paid before the cutoff. This
is observable pre-cutoff evidence, disclosed in amendment 2.

**Metamorphic tests.** Future rows, later payoffs and altered source flags or intended
addresses never change a packet.

## 5. Blinding limitations

- A block explorer shows later activity and phishing tags; the offline panel reduces the
  need for one.
- Each decision records later-payment exposure, third-party-label influence, explorer use
  and offline-panel use (amendment 2). Exposed items are kept, and sensitivity analyses
  are pre-specified (protocol B4).
- Archive packets are source-selected, which can make attacks look more obvious than a
  full history would. The coverage status says so.

## 6. Reviewer workflow

**Server.** The local app (loopback only) has:
- a session token in a custom header, and a Host check;
- strict CSP and text-only rendering;
- sessions that expire after 12 hours.

**The page** adds:
- a cutoff banner and an evidence checklist;
- the offline evidence panel, with coverage warnings;
- reason codes and evidence citations;
- keyboard shortcuts, drafts, resume and mobile layout (all checked in the browser on the
  synthetic training package).

**Saving and finalizing** are hash-chained and atomic.

**Submission checks** (`ml/submissions.py`, `review check-submission`) report every
problem:
- missing or corrupt file;
- edited content;
- stale protocol;
- wrong cohort or sample;
- mixed reviewer ids;
- unknown, missing or repeated items.

**Training.** A synthetic cohort of ten cases (`training/1`); it can never be unblinded.

## 7. Label policy (`ml/label_policy.py`)

**Seven statuses, never collapsed:** external source assertion, reviewed attack, reviewed
legitimate, likely attack, unknown, conflicting, later victim loss.

**Strict binary benchmark.** It admits only `reviewed_attack` (two or more reviewers, all
*confirmed attempt*) and `reviewed_legitimate` (all *confirmed legitimate*). Every
exclusion is counted. Adjudication is a separate layer.

## 8. Statistical design

**Estimands, never pooled:**

| Estimand | Cohort | Unit | Weights |
|---|---|---|---|
| Source-positive confirmation rate | A | campaign group (1,395 in the frame) | stratified, `N_c/n_c` |
| Hard-candidate legitimate rate | B | eligible candidate frame (5,232 items in 2,664 groups) | stratified, `N_c/n_c` (up to 197.5) |
| Agreement | each | the items reviewed | unweighted |
| Evidence sufficiency | each | items | unweighted |

- **Attempt-level (A):** bounds only. **Victim-level:** not estimated.
- **Intervals:** design-based Wilson on the effective sample size, with collapsed strata
  (amendment 1).
- **Not a population rate.** Neither cohort's class mix is Ethereum prevalence.
- **Cohort B is too small for a low-FPR claim.** Even if all 35 items were reviewed
  legitimate, the zero-error Wilson bound is about 0.10 unweighted and wider with
  weights, not 1%.

## 9. Agreement analysis

`ml/agreement.py`, `review agreement` (needs no key):
- exact agreement, confusion matrix, disagreement counts;
- Cohen's kappa (`None` with a reason when undefined, never 0);
- Gwet's AC1;
- insufficient- and conflicting-evidence rates per reviewer;
- per-stratum results only with 10 or more items.

These are tested against hand-computed values. Agreement measures consistency, not truth.

## 10. Source-selection bias

The Phase 11.5 findings stand:
- value alone separates the source frames (AUC 1.0);
- direction gives 0.98;
- everything except value gives 0.99.

**Safeguard.** The benchmark contract refuses feature names containing label, outcome,
payoff, score or prediction, and also source, dataset, cohort, frame, row-index,
line-number or file names.

**Caveat.** Removing explicit identifiers does not remove selection bias. Reviewed
positives (Cohort A) and reviewed negatives (Cohort B) come from different frames. A
classifier separating them could learn the frames. A benchmark built only from these two
cohorts would be easy and unrepresentative, and the experiment spec forbids that.

## 11. Negative-data validity

- **Status.** No reviewed legitimate example exists.
- **Cohort B is a frame of candidates, not of negatives.** 7 of its 8 background-wallet
  candidates have attack shapes, and 42% of its archive frame was excluded as known
  attacks before sampling.

## 12. Benchmark leakage protections

- **Typed grouping.** It links events through planting transactions, lookalikes, signers,
  victims, imitated addresses, counterfeit tokens and verified attack infrastructure, but
  never through public tokens or routers.
- **Holdout.** `benchmark.holdout_from_sheets` protects *both* cohorts as one holdout, and
  any development use is recorded permanently.
- **Point-in-time features.** Tested metamorphically for features and for packets.
- **Split report.** Measures entity overlap between splits.

## 13. ML experiment specification (`ml/experiment_spec.py`)

**Status: inactive.** It is pre-registered:
- **Unit and cutoff:** a victim-event, judged at the cutoff.
- **Target:** the strict binary label.
- **Splits:** grouped-temporal.
- **Threshold:** chosen on validation (highest recall with FPR ≤ 5%).
- **Primary metric:** AP, with recall at FPR ≤ 5%.
- **Calibration:** only with 100 or more items per class.
- **Baselines:** the production rule, the similarity, shape and history heuristics, LR and
  LightGBM.
- **Feature groups:** similarity, transaction, wallet history, temporal, graph and combined.
  Every column is checked against the real feature row.
- **Budget:** CPU only, under 2 GB and 2 minutes.
- **No GNN.**

**Activation** needs at least 30 reviewed labels per class, from at least 5 campaign groups
each. 60 labels from one campaign are refused (tested).

## 14. Sample size (`ml/power.py`)

Reviewed legitimate events needed so the two-sided 95% Wilson upper bound on FPR falls
below the target:

| Target FPR | True FPR 0 | True FPR = half the target | ×1.5 clustering | ×2 clustering |
|---|---|---|---|---|
| 10% | 35 | 139 | 53 / 209 | 70 / 278 |
| 5% | 73 | 292 | 110 / 438 | 146 / 584 |
| 1% | 381 | 1,522 | 572 / 2,283 | 762 / 3,044 |

**Choosing a target.** A tool scanning every event of many wallets needs a low FPR to be
usable. Which FPR is acceptable is an operational decision, not a statistical one, and no
evidence for it exists yet.

## 15. Data acquisition cost (scenarios, nothing collected)

**Basis:**
- background candidate volume: 8 per 27 wallet-days (unlabeled);
- the legitimate share *f* is unknown;
- the planner gives 1,345 requests per 3-day wallet window (free endpoint, conservative).

| Reviewed legitimate events | *f* | Wallet-days | Wallets | RPC requests | Items to review (decisions) |
|---|---|---|---|---|---|
| 73 | 0.5 | 493 | 165 | 221,925 | 146 (292) |
| 73 | 0.25 | 986 | 329 | 442,505 | 292 (584) |
| 73 | 0.125 | 1,971 | 657 | 883,665 | 584 (1,168) |

**Why these are scenarios.** Background candidates looked mostly like attacks, so a low
*f* is plausible. Storage is small: the recorded windows are 1–190 KB each. Any collection
needs a separately approved cap.

## 16. Licensing restrictions

- **Kept local:** archive-derived packets, sheets, keys, packages and submissions
  (CC BY-NC-ND 4.0).
- **Unresolved:** whether per-item labels or packets may be published. This is not legal
  advice.
- **Synthetic and public data:** the training cases are synthetic, and the recorded
  fixtures are public chain data.

## 17. Testing and CI

See the final report in the PR for the exact counts of this phase's run.

**New tests cover:**
- evidence packets: cutoff, metamorphic future rows and labels, inconsistent cutoff,
  missing transaction, exact in-block order, determinism, bounded history;
- the training cohort and refused unblinding;
- tampered evidence and session expiry;
- amendment-2 validation;
- submission checks and the agreement report;
- the label policy, spec activation, power and leakage guards;
- the generator: same-block order and duplicate input.

**Lease reliability.** One earlier full run had a lease-contention failure.
- It was not reproduced in 16 rounds under CPU and fsync-heavy disk load.
- The one mechanism found: a locked database raised a raw `OperationalError`. It now raises
  a typed, retryable `LeaseBusyError`.
- The contention test reports each child's exception and asserts safety separately from
  liveness.
- A deterministic test covers the busy path.

**Generator.** `candidates/2` now buckets chosen counterparties by suffix (exact). 10,000
transfers take 0.13 s instead of 13 s, with output identical on all 13 recordings.

## 18. Remaining blockers (by scientific importance)

1. **Human:** two independent reviewers for 95 items (190 decisions).
2. **Human:** no reviewed legitimate examples. Gates E, I and J depend on them.
3. **Data:** 19 of 35 Cohort B items have no local wallet history; reviewers need an
   explorer.
4. **Statistics:** 35 candidates cannot support low-FPR claims (§14).
5. **Licensing:** the per-item publication question.

## 19. Human reviewer handoff

[docs/ml/reviewer-handoff.md](docs/ml/reviewer-handoff.md) has:
- the invitation draft and eligibility;
- the workload, about 9 hours per reviewer (an assumption);
- data handling and independence;
- the maintainer checklist.

The reviewer guide and protocol amendments 1 and 2 are in `docs/ml/`.

## 20. Next scientific experiment

**Experiment.** The two reviewers work through the training package, then both cohorts,
per the checklist.

**Requirements:**
- **People:** two humans.
- **No new data, no RPC and no new authorization.**
- **No new engineering** beyond fixing what their feedback reveals.

**Value.** The first independent positives and candidate negatives, agreement on both, and
measured review time, which replaces the 5-minute assumption.

## Decision gates

| Gate | Status |
|---|---|
| A Frozen data integrity | **PASS** (both cohorts byte-identical; Cohort B history documented) |
| B Evidence sufficiency | PASS WITH LIMITATIONS (packets for all 95; archive rows are source-selected; 19 B items lack local history) |
| C Reviewer independence | PASS WITH LIMITATIONS (separate packages, stores and finalization; procedural on a shared computer; no humans yet) |
| D Positive-label validation | BLOCKED BY MISSING HUMAN EVIDENCE |
| E Negative-label validation | BLOCKED BY MISSING HUMAN EVIDENCE |
| F Source bias | PASS WITH LIMITATIONS (documented; source identifiers refused as features; selection bias remains) |
| G Temporal correctness | **PASS** (metamorphic tests on features and packets) |
| H Split independence | PASS WITH LIMITATIONS (typed grouping and holdout guards; untested on real labelled splits) |
| I Statistical adequacy | **FAIL** (0 labels; 35 candidates bound FPR at about 10% at best) |
| J ML readiness | BLOCKED BY MISSING HUMAN EVIDENCE (spec inactive) |
| K Production isolation | **PASS** (research modules load neither database nor API; findings unchanged) |

## Phase 11.7 update

[ML_EVIDENCE_COMPLETION.md](ML_EVIDENCE_COMPLETION.md) supersedes the evidence numbers in
§4 and the gate statuses above. Changes:
- all 24 Cohort B archive items now have pre-cutoff wallet rows (19 recovered offline);
- the packets are now `evidence-packets/2` (amendment 3);
- the gates are re-evaluated as A-L.

The state is unchanged: REVIEW_READY: HUMAN ANNOTATION PENDING.
