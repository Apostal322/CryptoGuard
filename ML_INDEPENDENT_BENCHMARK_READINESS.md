# Independent benchmark readiness: ground truth, blind evaluation, generalization (Phase 12.8)

| Item | Value |
|---|---|
| Protocol (frozen before any harness code) | [`docs/ml/protocol-12.8.md`](docs/ml/protocol-12.8.md), `d6f4916` |
| Code (committed before the measured run) | `3b512d7`; labelling fix `332dbfd` |
| Measured run | `cryptoguard ml benchmark-readiness` on `332dbfd`: 47 s, 225 MiB peak RSS. It reproduced the `3b512d7` run exactly. |
| Output (git-ignored) | `data/ml/research/phase12.8/readiness.json`, `ledger-development.jsonl` |
| RPC requests / downloads | **0** / none |

**Every number below is from development data.** No independent incident exists locally, so
nothing here is validation.

## 1. Executive summary

**Readiness decision: ready after new observation recordings and additional verified
labels.** The evaluation contract now exists and works end to end. What is missing is data:

| Need | Have |
|---|---|
| Independent incidents | **0** (16 local windows: 7 protected by frozen-cohort overlap, 3 development incident windows from 2 incidents, 6 unlabelled background) |
| Verified-legitimate labels | **0** (0 reviewer submissions on the 60 + 35 frozen items) |
| A window observing every mechanism | **0** of 16 (internal transfers, ERC-1155 and zero-value native are unsupported or partial everywhere) |

**What was built** (research only; the detector is untouched):
- a five-dimension label ontology with evidence rules;
- a case contract whose collector request cannot carry an answer;
- a blind harness: prediction without an outcome parameter, an outcome vault, a run-once
  ledger;
- metrics with explicit denominators;
- a nine-class failure taxonomy;
- group splits and a leakage audit;
- a paired sample-size planner;
- a public-repository safety scan.

**Development regression** (known cases, not validation):
- **Outcome-linked address was a candidate before the cutoff:** 2 of 3 windows. The third is
  the `observation/1` recording that cannot see native ETH; it is classified
  `observation_unsupported`, not as a ranking failure.
- **End-to-End Top-10 under the current order:** 2 of 2 mechanism-eligible windows; 2 of 3
  over all verified windows.

**One new measurement.** On the archive development split (source-conditional), when the paid
lookalike ties a rival on similarity, it is the most recently planted of the tied ones in
**79.0 %** of 423 episodes, against a chance rate of 33.5 %. The excess is +0.454
[0.412, 0.495]. On this non-adversarial data, recency is the right tie-break, which supports
keeping the current order over P1b.

**No model was trained:** no task has independent labels.

**The repository is public.** The safety scan is clean over 412 tracked files and 112
commits. One blinding risk is reported in §28.

## 2. Research motivation

Phase 12.7 found a ranking gain that Phase 12.7.1 traced to benchmark construction. The
remaining questions (recency vs hash ties, reference rotation vs similarity) cannot be
settled by more simulation. They need real incidents, scored under a contract fixed in
advance, with outcomes kept away from inference.

## 3. Previous ML findings

| Phase | Finding |
|---|---|
| 12.1–12.2 | recency best predicts the paid lookalike on the archive (source-conditional) |
| 12.3 | 2 real incidents: 1 warned, 1 missed |
| 12.4 | the miss was an unobserved native-dust planting; `observation/2` recovers it |
| 12.5 | proxy-task ML loses to frequency baselines under temporal shift |
| 12.6–12.6.1 | evidence groups, guarded signer recovery, bounded summaries |
| 12.7 | P1/P1b looked better than similarity-first on a biased synthetic grid |
| 12.7.1 | on a debiased benchmark, P1b − B0 = −0.018 [−0.031, −0.004]; not promoted |

## 4. Dataset inventory

Sizes are by `stat` only.

| Source | Class | Size | Records | Licence | Eligibility |
|---|---|---|---|---|---|
| Tsuchiya archive | source-derived events | 2.2 GiB, 4 files | — | CC BY-NC-ND 4.0 | development only |
| Archive episodes (12.1 task) | source-derived, paid-lookalike outcome | 5.3 MiB | 1,067 (640 dev / 427 test) | derived, local only | dev split exploratory; **test split spent** |
| Archive subset / unconfirmed payoffs | source-derived | 139 MiB / 610 MiB | — | derived, local only | development; unconfirmed set exhausted |
| Review packets | candidates without outcome | 1.3 MiB | 1,469 | derived, local only | reviewer evidence, unlabelled |
| Cohort A / Cohort B | human review, frozen | — | 60 / 35 | derived, local only | **protected; 0 submissions** |
| Hard-negative pool | candidates without outcome | 109 MiB | — | derived, local only | unlabelled; not negatives |
| Poison-Hunter / PTXPhish / Forta | other sources | < 1.5 MiB each | — | none published / per licence | data card; separate tasks |
| Replay incident windows | wallet windows, verified incident | 4 windows | — | public chain data | development; **all 4 protected** |
| Level I incident windows | wallet windows, verified incident | 2 windows (+1 local `/2` re-recording) | — | public chain data | development |
| Background windows | wallet windows, unlabelled | 9 recorded | — | public chain data | not negatives; 3 protected |
| Synthetic generators | controlled synthetic | code | — | project code | robustness only |

These classes are never merged into one labelled dataset.

## 5. Source provenance

- **Per-file provenance** stays in `ml/inventory.py` (the registry gained entries for the
  Level I cases, the campaign expansion and `data/ml/research`).
- **Recorded windows** were all taken from a keyless public endpoint.
- **Incident outcomes** come from public reports, checked on-chain in the manifests.
- **The archive's labels** are the source's own heuristics.

## 6. Label ontology (`benchmark-labels/1`)

Five independent dimensions: mechanism, provenance, relationship, outcome and legitimacy.
Each has an `unknown`-type value, and nothing is forced into a binary fraud label.

**The vocabulary is kept separate:**
- observed transaction;
- suspicious candidate;
- confirmed planting;
- paid lookalike (an outcome, not proof about earlier events);
- confirmed loss;
- legitimate activity;
- unknown.

## 7. Label reliability

**A label is rejected when:**
- an asserting value has no evidence reference;
- an outcome value lacks a chain transaction;
- `confirmed_legitimate` rests on anything but a reviewer decision or a synthetic oracle
  (absence of a report is never evidence);
- `confirmed_malicious` rests on an on-chain event alone;
- a reviewer reference has no reviewer id;
- an oracle reference appears on a real case;
- a non-asserting value claims `verified`;
- an outcome or legitimacy label is marked as a pre-cutoff model input.

Conflicting labels on one subject need review.

**Local labels today:**

| Label | Count | Basis |
|---|---|---|
| Outcome (`paid_to_candidate`, verified) | 3 | harm transaction plus report; 2 distinct incidents |
| Mechanism (supported, forensic) | 3 | the first pre-harm record involving the paid address |
| Legitimacy | **0** | — |
| Reviewer decision | **0** | — |

## 8. Observation completeness

| Window | Schema | native_dust | zero-value / fake token | spoofed | all mechanisms | Incomplete categories |
|---|---|---|---|---|---|---|
| 15 `observation/1` windows | `/1` | **unsupported** | complete | complete | unsupported | 7 of 10 |
| ScamSniffer blind `/2` | `/2` | complete | complete | complete | **unsupported** | 4 of 10 |

- **No window supports an all-mechanisms detection benchmark.**
- **Still missing in `/2`:** internal value transfers, ERC-1155, zero-value native, and
  unattributed inbound.
- **Interpretation:** a missing event in an incomplete category is not evidence of absence.
  Eligibility is per mechanism.

## 9. Historical cutoff design

- **Cutoff:** `(harm block, 0)`, strictly before the harmful block. Within-block order is not
  assumed.
- **Enforcement:**
  - `predict` asserts that no candidate record is at or after the cutoff;
  - the leakage audit re-checks every record against pre-cutoff observations;
  - `case_quality` rejects a cutoff after the harm block and an outcome transaction that
    precedes the cutoff.
- **Tests:**
  - a planting in the harmful block is not usable;
  - a post-cutoff lookalike never becomes a candidate.

## 10. Blind evaluation protocol

**Flow:** `predict(case, fixture)` → seal → `OutcomeVault.open` → `score` → `Ledger.record`.

| Guarantee | How it is enforced |
|---|---|
| Inference cannot see an outcome | `predict` has exactly two parameters (tested) |
| No unblinding before sealing | the vault raises `UnblindingError` |
| One scoring per case | the same prediction returns the stored result; a different one raises `RerunError` and is logged |
| The collector cannot be given an answer | `CollectorRequest` forbids extra fields (tested with a paid address) |

**Measured:**
- the development ledger recorded 3 cases, and the rerun on `332dbfd` was accepted as
  identical (0 refused reruns);
- the harness itself caught one defect during development: stored results were not
  JSON-identical to fresh ones. Fixed before the measured run.

## 11. Independent incident eligibility

A case is independent only if all of these hold:
- victim, paid address and harm transaction are absent from every development artifact;
- it shares no attack cluster with one;
- it was not used to design or tune a method;
- its source is traceable;
- its outcome identity is clear.

**Local result: 0 independent incidents, 0 independent victims.** The ScamSniffer `/2`
re-recording stays development and shares its cluster with the `/1` recording (2 clusters in
total).

## 12. Negative-control requirements

**Acceptable sources of verified-legitimate labels:**
- human adjudication under the review protocol (two reviewers);
- a controlled wallet whose owner attests each payment;
- explicit synthetic controls (for harness testing only).

**Not acceptable:**
- background wallets;
- unreported activity;
- source "uncategorized" rows.

**Status: T8 (false alerts) is BLOCKED.** `false_positive_rate` returns `blocked` without
verified negatives (tested: unreviewed, ambiguous and insufficient-evidence subjects never
count).

## 13. Annotation protocol

- **Existing schema** (`poisoning-annotation/1`) already offers confirmed / likely poisoning,
  legitimate, ambiguous, insufficient evidence and not evaluable, with evidence references,
  reason codes and confidence.
- **Mapping into the ontology:**
  - "likely" is never converted to "confirmed";
  - a reviewer decision is the only route to `confirmed_legitimate`.
- **Frozen cohorts:** untouched and unread beyond the blinded sheets.

## 14. Reviewer agreement feasibility

- **Tooling exists** (`ml/agreement.py`): exact agreement, confusion matrix and Cohen's kappa
  for two reviewers, tested on synthetic labels.
- **Real submissions:** **0**, so no agreement is reported.
- **Scope limit:** a multi-reviewer statistic (Fleiss) is not implemented; the protocol plans
  two reviewers.
- **Small-sample caveat:** with 95 items and rare classes, kappa will be unstable. The
  insufficient-evidence rate should be reported beside it.

## 15. Leakage audit

**Automated checks per case:**

| Check | Development cases |
|---|---|
| No post-cutoff evidence | pass (3 of 3) |
| No outcome field in the collector request | pass |
| Prediction matches the recording | pass |
| No protected-cohort overlap | pass |
| **Not a spent population** | **fail (3 of 3)** |

So **confirmatory claims are blocked for all three**, as intended.

**Spent populations registered:**
- the archive test split (12.1);
- the archive development split;
- both Level I incidents;
- the recorded windows;
- both synthetic grids.

## 16. Group-aware splits

- **Groups:** connected components over victim, attack cluster, paid address and optional
  signer/lookalike keys.
- **Strategies:** chronological holdout and leave-one-group-out, each with a leakage check.
- **Feasibility today:** 2 groups, so no split is meaningful. Below 3 groups nothing is;
  below 10 a holdout has under 4 test groups. Leave-source-out and cross-period designs are
  not feasible either.

## 17. Benchmark task definitions

| Task | Question | Denominator |
|---|---|---|
| T1 | planting observed before the cutoff? | verified cases whose mechanism category is complete |
| T2 | candidate generated? | eligible cases |
| T3 | rank | generated cases |
| T4 | top-K | conditional: generated; end-to-end: all eligible (generation failures are misses) |
| T5 | mechanism identified? | generated cases with a mechanism label |
| T6 | evidence fidelity | all candidate records |
| T7 | alert burden | all windows |
| T8 | false alerts | verified-legitimate labels (blocked) |
| T9 | ML generalization | independent groups (blocked) |

No single "detection accuracy" number is produced.

## 18. Candidate-generation metrics (development cases; not validation)

| Metric | Value |
|---|---|
| ObservationCoverage (mechanism-assessable) | 2 / 2 |
| ObservationCoverage (all verified) | 2 / 3 |
| CandidateRecall (mechanism-eligible) | 2 / 2 |
| CandidateRecall (all verified) | 2 / 3 |
| Mechanism identification | 2 / 2 |
| Evidence fidelity | 14 / 14 records resolve to pre-cutoff observations |
| Burden | mean 3.7 candidates per window (max 6); 1.22 per wallet-day; summary ≤ 5.3 KB |

## 19. Ranking metrics (development cases; not validation)

| Method | Rank: ScamSniffer `/2` | Rank: pilot | MRR on generated (n = 2) |
|---|---|---|---|
| B0 (similarity → recency) | 1 | 3 | 0.667 |
| B1 (recency) | 3 | 2 | 0.417 |
| B4 (reference rotation) | 1 | 3 | 0.667 |
| P1 / P1b (seed 0) | 1 | 5 | 0.600 |

**Under B0:**

| K | Conditional TopK | End-to-End TopK (mechanism-eligible) | End-to-End TopK (all verified) |
|---|---|---|---|
| 1 | 1 / 2 | 1 / 2 | 1 / 3 |
| 3, 5, 10 | 2 / 2 | 2 / 2 | 2 / 3 |

With n = 2 clusters these describe the harness, not the methods.

## 20. Failure taxonomy

One class per scored case, assigned in order: `outcome_not_verified`, `label_uncertain`,
`observation_unsupported`, `observation_partial`, `not_observed_in_complete_stream`,
`candidate_not_generated`, `incorrect_reference_matching`, `ranked_below_k`, `exposed`.

- **Development cases:** `exposed` × 2, `observation_unsupported` × 1 (ScamSniffer `/1`).
- **Tested:** every class is exercised by a synthetic test.
- **Naming detail** (not in the protocol): `ranked_below_k` uses B0 at K = 10. Per-K exposure
  is reported separately.

## 21. Existing baseline registry

**Generators:** C0, C1, C2 and `candidate-evidence/2`.
**Orders:** B0, B1, B4, P1 and P1b.
**Each entry has:** version, required categories, missingness behaviour and status.

- **P1b:** "failed the 12.7.1 debiased benchmark; comparison only, not preferred" (asserted by
  a test).
- **M-LTR:** listed as not registered for scoring.
- **No method was modified.**

## 22. Local data eligibility

| Windows | Count | Status |
|---|---|---|
| Replay incident windows | 4 | `not_evaluable`: touch frozen Cohort B |
| Background, protected | 3 | `not_evaluable` |
| Background, unprotected | 6 | no outcome; 0 candidates each; not negatives |
| Development incident windows | 3 | `valid_with_limitations` |
| **Independent** | **0** | — |

**Leads in the committed registries** (a lead is not an incident): 7 unrecorded, none with
complete identifiers.

| Lead | Claimed mechanism | Identifiers present | Missing for collection | In archive period |
|---|---|---|---|---|
| usdt-700k-2025-04 | zero-value token | planting tx, harm tx | victim (derivable only from chain data) | no |
| wbtc-2.38-2025-12-18 | unknown | harm tx | victim | no |
| pink-drainer-10eth-2024-06-27 | unknown | victim, intended recipient | harm tx | yes (victim not in the archive episodes) |
| webacy-6.88m-usdt-2025-09 | unknown | victim | harm tx (RPC was rejected twice in Stage 2a) | no |
| dea-usdt-55k-2023 | other | none | victim, harm tx | yes |
| usdt-100k-2026-08 | unknown | none | victim, harm tx | no |
| usdt-50k-2026-10 | unknown | none | victim, harm tx | no |

- **No new web discovery** was run in this phase. Stage 2 preparation already searched
  public reports and found that they usually truncate addresses.
- **Selection risk:** choosing leads by how easy the outcome is to locate would bias the
  sample, so the eligibility rules are fixed before selection.

**Missingness sensitivity** (in-memory degradations; not real recorder failures):

| Degradation | ScamSniffer `/2` (native dust) | Pilot (fake token) |
|---|---|---|
| none | exposed, rank 1 | exposed, rank 3 |
| no signer lookups | exposed, rank 1 | exposed, rank 3 |
| no receipts | exposed, rank 1 | exposed, rank 3 |
| recipient history incomplete | exposed, rank 1 | exposed, rank 3 |
| first half of the window removed | exposed, rank 1; coverage no longer complete | exposed, rank 3; coverage no longer complete |
| **no native observations** | **`observation_unsupported`; candidate lost** | exposed, rank 3 |

The original `/1` ScamSniffer recording is `observation_unsupported` under every condition.
Rank never changed with missing support data. This matches Phase 12.6.1.

## 23. ML readiness

| Task | Independent labels | Classification |
|---|---|---|
| Rank the paid lookalike (archive) | 640 dev episodes; test split spent | ready for development evaluation only |
| Poisoning vs legitimate (binary) | 0 verified negatives | **blocked by insufficient labels** |
| Candidate generation on real incidents | 2 development clusters | **blocked by data** |
| Reviewer-label classifier | 0 submissions | **blocked by insufficient labels** |
| Next-mechanism proxy (12.5) | done; negative | not repeated (no new hypothesis) |
| All-mechanisms detection | no complete window | **blocked by observation coverage** |
| Generalization of any ranker | 0 independent groups | **blocked by data** |

## 24. Exploratory experiments

**No model was trained.**

**One pre-registered measurement (D5), on the archive development split:**

| Quantity | Value |
|---|---|
| Evaluable episodes | 640 (632 groups) |
| Episodes where the paid lookalike ties a rival on similarity | 423 (mean 5.1 tied candidates) |
| Paid one is the newest of the tied | **79.0 %** |
| Chance (1/t) | 33.5 % |
| Excess over chance | **+0.454 [0.412, 0.495]**, p < 0.001 (group bootstrap and sign-flip) |
| Over all candidates, ignoring similarity | +0.483 [0.448, 0.517] |

**Interpretation:**
- on real, non-adversarial, payoff-conditioned data, recency is a strong tie-break;
- this supports B0's tie rule over P1b's hash;
- it is consistent with Phase 12.1 and is **not** new independent evidence;
- it does not cover an adversary who controls timing (12.7.1).

## 25. Statistical power

In a paired comparison (exposed within K under method A vs B on the same incidents) only
**discordant** incidents inform. Exact one-sided sign test, α = 0.05, when the better method
wins a discordant incident with probability 0.8:

| Discordant incidents | Critical count | Power |
|---|---|---|
| 5 | 5 of 5 | 0.33 |
| 10 | 9 of 10 | 0.38 |
| 20 | 15 of 20 | 0.80 |
| 30 | 20 of 30 | 0.97 |

Ten incidents with identical predictions give power 0.

## 26. Sample-size planning

`cryptoguard ml benchmark-power --p-better P --discordance D [--eligible-rate E --deff F]`.
Nothing is hard-coded. Scenarios at power 0.8, with half of screened incidents eligible:

| P(better wins a discordant incident) | Discordance | Discordant needed | Eligible needed | Screened needed |
|---|---|---|---|---|
| 0.9 | 0.5 | 11 | 22 | 44 |
| 0.9 | 0.3 | 11 | 37 | 74 |
| 0.8 | 0.5 | 18 | 36 | 72 |
| 0.8 | 0.3 | 18 | 60 | 120 |
| 0.8 | 0.1 | 18 | 180 | 360 |
| 0.7 | 0.3 | 42 | 140 | 280 |

- **Clustering:** a design effect of 1.5 multiplies every row by 1.5.
- **The earlier "about 70"** corresponds to one row of this table (0.8, 0.3, without the
  eligible-rate factor). It is an assumption, not a requirement.
- **Current sample:** 0 independent incidents, 2 development clusters.

## 27. Resource estimates (plan only; nothing was requested)

| Item | Estimate | Basis |
|---|---|---|
| Requests per window | about 700–1,300 | measured: 475 (pilot), 1,299 (`/2` blind), 1,433 (Stage 2a including resolution) |
| Per-window ceiling | 2,500 | the cap used for the `/2` blind recording |
| Feasibility set (10 recordings) | about 7,000–13,000; ceiling 25,000 | |
| Powered scenario (60 eligible, 120 recorded) | about 84,000–156,000 | row (0.8, 0.3) above |
| Disk per window | about 50–200 KB | existing fixtures |
| Memory | under 300 MiB | this study peaked at 225 MiB |
| Unusable recordings | about 1 in 3 so far (1 of 3 Stage 2 attempts was rejected by the provider) | very small sample |

**Controls already in the codebase:**
- a durable request ledger whose caps cover retries and fail closed;
- no budget carry-over;
- a bounded resource preflight.

Busy wallets can exceed these figures. **A plan is not permission: explicit approval of a new
cap is required before any request.**

## 28. Public repository safety

**Scan** (`ml/repo_safety.py`; names and counts only, never matched values):

| Check | Tracked files (412) | History (112 commits) |
|---|---|---|
| High-confidence secret patterns | 0 | 0 |
| Sensitive file names (keys, `.env`, unblinding, ledgers) | 0 | 0 |
| Anything under `data/` | 0 | 0 ever added |
| Local user paths | 0 | — |
| Oversized files (> 4 MiB) | 0 | — |

**Manual review:**
- A broader pattern pass flagged 15 strings. All are ERC-20 contract addresses assigned to
  variables named `token`, or redaction-test URLs.
- Recorded windows name only a keyless public endpoint.
- No archive-derived record is tracked.

**One risk to know about (not a secret leak):**
- 54 identifiers from the frozen Cohort B sheet appear in 17 tracked files, because Cohort B
  was drawn from recorded windows that were already public.
- No sheet and no key is tracked.
- A reviewer who searches the public repository for an item's address could find the
  incident manifest, including its outcome. That weakens blinding for the items drawn from
  the 4 incident windows.
- **Mitigation for the owner to decide:** tell reviewers not to consult the repository, or
  treat those items as unblinded in the analysis.

**Also public:** commit author identities, including an email domain. Nothing was rewritten,
and visibility was not changed.

**Regression test:** `test_this_repository_is_clean` keeps the high-confidence checks in CI.

## 29. Test results

- **New tests:** 23 in `tests/test_ml_benchmark_contract.py`.
- **What they cover:**
  - the controlled end-to-end benchmark;
  - every failure class;
  - metric denominators;
  - ledger and vault behaviour;
  - label rules and data-quality rules;
  - independence;
  - splits and leakage;
  - sample-size planning;
  - the safety scan.
- **Full-suite and CI results:** in the Validation section below.

## 30. Reproducibility

- **Reruns:** the measured run was repeated on `332dbfd` and matched `3b512d7`.
- **Prediction digest:** covers the observation hash, the cutoff, the candidate identities
  and every method's order.
- **Ledger:** stores the digest and refuses a different one.
- **No randomness** beyond the fixed public seed of P1/P1b.

## 31. Positive findings

1. A working, tested blind-evaluation contract with outcome isolation and a run-once ledger.
2. Failures are attributed correctly: the known miss is `observation_unsupported`, not a
   ranking failure.
3. End-to-end metrics count generation failures as misses; conditional metrics are separate.
4. Recency ties are right on real archive data (79.0 % vs 33.5 % chance).
5. The public repository is clean of secrets and restricted data.

## 32. Negative findings

1. **0 independent incidents;** no confirmatory claim is possible.
2. **0 verified negatives and 0 reviewer submissions;** false-alert evaluation is blocked.
3. **No window supports all mechanisms.**
4. **None of the 7 unrecorded leads has complete identifiers.**
5. **All 4 original incident windows are locked** behind the frozen cohort until it is
   reviewed.
6. **Reviewer blinding** for cohort items from public incident windows is weakened by the
   repository being public.

## 33. Current blockers

| Blocker | What removes it |
|---|---|
| No independent incidents | new incidents with a victim wallet and harm transaction, recorded with `observation/2` under a newly approved RPC cap |
| No verified negatives | two human reviewers completing the frozen cohorts (the owner contacts them) |
| Unsupported categories | trace access (internal transfers), ERC-1155 decoding, zero-value native observation |
| Locked incident windows | completion of the Cohort B review |
| Incomplete leads | full identifiers from the original sources, or approval to resolve them on-chain |

## 34. Independent benchmark readiness decision

**Ready after new observation recordings and additional verified labels.**

| Aspect | Status |
|---|---|
| Methodology, tooling and safety | ready |
| Evidence | blocked by data on three fronts: independent incidents, verified negatives, mechanism coverage |

Label uncertainty and source-selection bias are controlled by the contract, but cannot be
measured until data exist.

## 35. Recommended next experiment (not started)

**A prospective feasibility benchmark** under this contract:
- **Selection:** the owner supplies at least 10 untouched incidents selected by the §11
  rules *before* looking at how they would score. Multi-recipient victims are preferred, so
  that B0 and B4 can disagree.
- **Recording:** `observation/2` to the harm block, with a per-window cap of 2,500 and a
  total cap of 25,000 requests.
- **Scoring:** frozen methods B0, B1, B4 and P1b; the blind flow of §10; each case scored
  once.
- **Primary readout:** the failure-class distribution and End-to-End Top-5 over
  mechanism-eligible cases, plus the number of B0/B4 discordant incidents.
- **Labels needed:** paid address, intended recipient and harm transaction per incident.
- **Falsification:** if fewer than 5 of the first 10 incidents are mechanism-eligible, or B0
  and B4 are discordant on fewer than 2, a powered comparison is not worth its RPC cost at
  that discordance and should not be funded on current assumptions.

**Phase 12.9 is not started. No RPC was requested.**

## Gates

| Gate | Status | Basis |
|---|---|---|
| G1 Dataset provenance | **PASS WITH LIMITATIONS** | every source registered; archive labels are source heuristics |
| G2 Label quality | **PASS WITH LIMITATIONS** | evidence rules enforced; only 3 outcome labels and 0 legitimacy labels exist |
| G3 Historical correctness | **PASS** | cutoff asserted in prediction, audit and quality rules; tested |
| G4 Observation completeness | **PASS** | eligibility is per mechanism; all-mechanisms correctly blocked |
| G5 Protected-set integrity | **PASS** | cohort hashes unchanged; 7 protected windows never computed on |
| G6 Split correctness | **PASS WITH LIMITATIONS** | grouping and leakage checks tested; no split feasible with 2 groups |
| G7 Benchmark reproducibility | **PASS** | identical rerun; digest-checked ledger |
| G8 Metric correctness | **PASS** | denominators tested, including generation failures as misses |
| G9 Negative-label validity | **PASS** | unknown never counted as benign; FPR refused |
| G10 Model readiness | **NOT EVALUATED** | no model trained; no task has independent labels |
| G11 Generalization evidence | **BLOCKED BY DATA** | 0 independent incidents |
| G12 Public-data safety | **PASS WITH LIMITATIONS** | scan clean; reviewer-blinding risk noted |
| G13 Production isolation | **PASS** | detector untouched; research-only modules |

## Validation

| Check | Result |
|---|---|
| `ruff check .` / `ruff format --check .` | clean / 309 files formatted |
| `mypy src` (Windows and `--platform linux`) | clean (160 files) on both |
| Full suite | **1,098 passed, 0 failed**, 4 deselected (8 min 10 s); 23 new tests in `tests/test_ml_benchmark_contract.py` |
| Frozen cohorts | sheet and key hashes unchanged (`a0ec4b6e…`, `407b412f…`, `121c112d…`, `f333386d…`) |
| Incident fixtures | untouched (no data file modified) |
| Package and CI | recorded in the PR #1 description |
