# Benchmark readiness: `poisoning-attempt/1` (Phase 11.4)

**Verdict: not a benchmark yet. Supervised training is not justified.**
- The review sample is ready, but no human decision exists.
- There are no verified negatives anywhere.
- No collection is authorized.

Code: `ml/benchmark.py`, which builds on `events.quality_gates`, so the two cannot
disagree. Annotation design: [ML_ANNOTATION_AUDIT.md](ML_ANNOTATION_AUDIT.md).

## 1. Readiness criteria

| # | Criterion | Now | Evidence |
|---|---|---|---|
| 1 | Clear prediction unit | pass | victim-event at a cutoff (`poisoning-event/1`) |
| 2 | Reliable source labels | fail | archive categories are the source's heuristics |
| 3 | Independent review evidence | **fail: waiting on people** | 60-item sample frozen and tooling ready; 0 decisions |
| 4 | Suitable negatives | fail | 0 `verified_legitimate` events |
| 5 | Point-in-time features | pass | `event-features/1` uses data up to the planting only |
| 6 | Candidate-generation coverage | fail | needs full wallet histories (§3) |
| 7 | Entity-aware splitting | infrastructure only | `grouped-temporal/1`; nothing labelled to split |
| 8 | Temporal validation | partial | block-level order; no within-block order in the archive |
| 9 | Untouched final holdout | pass | the 60 reviewed items are guarded (§6) |
| 10 | Stable evaluation protocol | fail | deliberately undefined until 3 and 4 pass |

## 2. Labels: available and missing

| Have | Tier | Usable for |
|---|---|---|
| 1,469 payoff-linked attempts | review candidates, no label | the frozen review sample |
| Poison-Hunter rows | `weak_attempt` | descriptive only |
| Tsuchiya categories (17.4 M rows) | source heuristics, not loaded as labels | agreement analysis |
| Verified attempts | 0 (60 to be reviewed) | — |
| Verified negatives | **0** | — |

`insufficient_evidence` maps to `unknown` and `conflicting_evidence` to `conflicting`.
Neither ever becomes a negative (tested).

## 3. Candidate-generation coverage

- **Two separate measures.** Candidate recall (did `candidates/1` emit the event at all?)
  is kept apart from classifier performance. A model cannot score what the generator never
  emits.
- **What would measure recall:** running the generator over complete wallet histories
  around reviewed attempts. Those histories do not exist locally.
- **What has been measured:** the archive agreement in ML_CROSS_DATASET_VALIDATION.md §16
  measures agreement with the source's own definitions, not recall.

## 4. Negative-data protocol (proposal; nothing collected)

**What a negative is.** A candidate event that `candidates/1` emits on an ordinary wallet,
and that two independent reviewers mark `confirmed_legitimate_interaction`, with the
legitimate explanation observed.

**Candidate categories to look for** (these are where to look, not labels):
- a counterparty's own second address;
- similar vanity or exchange deposit addresses;
- first-time counterparties;
- legitimate airdrops and dust;
- router and aggregator transfers;
- ordinary low-value transfers.

**Matching.** Draw negatives through the same generator, from wallets matched to the
reviewed victims on:
- period;
- activity band (nonce range);
- token class;
- transaction shape;
- coverage.

Never compare specialist-source attacks with random unrelated transactions.

**Unknown stays unknown.** A wallet with no published theft is not benign.

**Sample size.** Gate B needs at least 30 verified per class from 5 or more campaign
groups. Allow for:
- candidates per wallet-week, which are unknown and possibly below 1;
- reviewer yield.

The proposal is therefore 120 wallet-weeks:
- the 60 reviewed victims, in the week before their planting;
- 60 matched ordinary wallets.

Collection stops at the cap, whatever has been found by then.

| Item | Estimate (`cryptoguard ml plan-collection`, no requests sent) |
|---|---|
| Window | 50,400 blocks (about 7 days) per wallet |
| Requests at 100-block log ranges (free endpoint used in the pilot) | 1,978 per wallet; **237,360 for 120 wallets**; about 16.5 h at 4 requests/s |
| Requests at 2,000-block log ranges | 927 per wallet; 111,240 total |
| Retry allowance | +10% (included) |
| Expected fully resolved wallets | 96 of 120 (80% coverage assumption) |
| Disk and memory | not measured: the pilot's recorded fixtures were lost (ML_PILOT_AUDIT.md §4). Measure on the first 5 wallets before continuing |
| Review cost | 2 reviewers × every emitted candidate; about 5 minutes each (an estimate) |
| Hard cap to request | the plan's total, enforced by `RequestLedger`; the plan hash is recorded before any run |

**Approval.**
- This needs **separate, explicit approval** of a request cap and a provider. None is given.
- The pilot's 364 leftover requests are not usable for this.
- Paid providers are excluded unless you decide otherwise.

## 5. Evaluation task (when gates pass)

- **Classification.** Score each emitted candidate event at its cutoff.
- **Primary metric.** Precision-recall on a grouped, time-ordered test split.
- **Reported separately:**
  - candidate recall;
  - alert volume per wallet-week, from the matched ordinary wallets.
- **Baselines:** the existing rules detector and a trivial classifier.

## 6. Splits and leakage

- **Splits.** `grouped-temporal/1` puts whole campaign groups on one side, with the latest
  groups as the test set.
- **Review holdout.** `benchmark.check_training_events` refuses any training event that
  shares an event, wallet, lookalike or planting transaction with the 60 reviewed items.
- **If the reviewed items are used in development** (for example, retuning the detector
  after reading review errors), `mark_development` records it permanently. They are then
  development evidence, not an independent evaluation.
- **Never train on the 60 and report on the 60.**
- **Versioned manifest.** `benchmark_manifest` pins task, event schema, candidate
  generation, features, source and human label versions, split policy and evaluation
  protocol. Results are comparable only under the same hash.

## 7. Isolation from the existing classifier

- **Separate tasks.** The PTXPhish transaction classifier stays a different task, and the
  shadow scorer refuses a model card for `poisoning-attempt/1`
  (`tests/unit/test_ml_pipeline.py`).
- **Never loaded by production.** The review and annotation modules are research-only, and
  `tests/unit/test_ml_reconcile.py` checks that they load neither the application database
  nor the API. Wallet scans and findings are unchanged.
