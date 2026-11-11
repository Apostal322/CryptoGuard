# Protocol 12.8: independent benchmark contract, ground-truth quality, readiness

**Frozen:** 2026-11-10, in the commit that adds this file. That is before any Phase 12.8
harness code exists and before any quantity below is computed.

**Base:** `ffbdb6a`.

**RPC budget:** 0. No collection happens under this protocol.

**Purpose.** Phases 12.7 and 12.7.1 showed that a ranking method can look better because of
how a benchmark was built. This phase adds no new ranking method. It fixes the contract under
which any method is evaluated on real incidents:
- what each label means;
- what evidence a label needs;
- which cases are eligible for which task;
- how outcomes are kept away from candidate generation and ranking;
- which denominators the metrics use.

**The repository is public.** Nothing derived from restricted sources (CC BY-NC-ND archive
data, review sheets, unblinding keys) may enter a tracked file. Reports carry aggregates only.

## 1. Vocabulary (never collapsed)

| Term | Meaning |
|---|---|
| Observed transaction | a recorded chain event |
| Suspicious candidate | an event that satisfies a candidate-generation rule |
| Confirmed planting | evidence establishes a specific poisoning mechanism under the criteria of §2 |
| Paid lookalike | the victim later sent value to the candidate address. This is an outcome label; it does not make every earlier event from that address malicious. |
| Confirmed loss | sufficiently supported evidence of financial loss |
| Legitimate activity | independent evidence supports a legitimate reading |
| Unknown | cannot be classified |

Three rules follow:
- an unknown candidate is not a negative;
- a background wallet with no known theft is not a verified benign wallet;
- unreported is not benign.

## 2. Label ontology (`benchmark-labels/1`)

**Five independent dimensions.** `unknown` is a value in every one.

| Dimension | Values |
|---|---|
| mechanism | `native_dust`, `zero_value_token`, `fake_token`, `spoofed_transfer`, `other`, `unknown` |
| provenance | `signer_verified`, `emitter_verified`, `receipt_verified`, `relationship_verified`, `inferred`, `unsupported`, `unknown` |
| relationship | `exact_address`, `lookalike_of_recipient`, `no_recipient_relationship`, `ambiguous_multiple_references`, `unknown` |
| outcome | `paid_to_candidate`, `paid_to_legitimate_recipient`, `harmful_transfer`, `no_verified_outcome`, `unknown` |
| legitimacy | `confirmed_malicious`, `confirmed_legitimate`, `ambiguous`, `unreviewed`, `insufficient_evidence` |

**Each label record carries:**
- an id and the schema version;
- dimension and value;
- evidence references, each typed as `chain_transaction`, `receipt`, `incident_report`,
  `campaign_attribution`, `reviewer_decision` or `synthetic_oracle`;
- source, determination date and method;
- reviewer id, where applicable;
- confidence: `verified`, `supported`, `weak` or `none`;
- ambiguity and limitations;
- its **cutoff relation:** `pre_cutoff_observable`, `post_cutoff_outcome` or `forensic`.

**Validation rules.** A label is rejected when:
1. an asserting value (anything except `unknown`, `unreviewed`, `no_verified_outcome`,
   `insufficient_evidence`, `ambiguous`) has no evidence reference;
2. `paid_to_candidate`, `paid_to_legitimate_recipient` or `harmful_transfer` lacks a
   `chain_transaction` reference;
3. `confirmed_legitimate` rests on anything other than a `reviewer_decision` or a
   `synthetic_oracle`. Absence of a report is never evidence;
4. `confirmed_malicious` rests only on a `chain_transaction` (address similarity or an
   on-chain event alone does not establish intent);
5. a `reviewer_decision` reference has no reviewer id, or a `synthetic_oracle` reference is
   used on a non-synthetic case;
6. a non-asserting value carries confidence `verified`;
7. an outcome or legitimacy label is marked `pre_cutoff_observable`. Those are never model
   inputs.

Two labels of one dimension on one subject that assert different values are a conflict
(`needs_review`).

## 3. Case contract (`benchmark-case/1`)

**A case holds only what a collector may know:**
- case id, chain, victim wallet and block window;
- observation schema;
- cutoff and cutoff rule;
- source provenance;
- an attack-cluster id;
- a declared population: `development`, `independent_candidate` or `synthetic`.

**The outcome lives in a separate sealed record:** paid address, harmful transaction and
block, and labels.

**Collector request.** The collector accepts exactly: chain id, wallet, from-block, to-block,
observation version and resource limits. The request type forbids any other field, so an
attacker address, a paid address, a harmful transaction hash or an answer key cannot be
passed.

**Cutoff.** `(harm block, 0)`: strictly before the harmful block. Within-block order relative
to the harmful transaction is not assumed. The window may contain the harmful block, but
observations at or after the cutoff are never read. An earlier declared monitoring time is
allowed and recorded.

## 4. Data-quality rules

**Severities:** `valid` < `valid_with_limitations` < `needs_review` < `not_evaluable` <
`invalid`. A case's status is its worst issue. Excluded cases stay in the ledger with their
reasons, and nothing is silently dropped.

**Checks:**
- invalid address or hash;
- chain mismatch;
- duplicate case, or duplicate records inside a window;
- inconsistent block order;
- window not covering the cutoff;
- harm block outside the window;
- cutoff after the harmful block;
- the outcome transaction present among pre-cutoff observations;
- incomplete signer lookups;
- unread receipts;
- category statuses other than `complete`;
- conflicting labels;
- missing label evidence;
- outcome missing or unverified;
- protected-cohort overlap;
- development contamination.

## 5. Observation eligibility

Coverage is per category (`replay.observation`). Each mechanism requires its own categories
to be `complete`:

| Mechanism | Required categories |
|---|---|
| native_dust | `native_inbound_external` |
| zero_value_token, fake_token | `erc20_transfer_logs` |
| spoofed_transfer | `erc20_transfer_logs` and (`erc20_outgoing_signers` or `wallet_signed_transactions`) |
| **all-mechanisms detection** | every category, including `internal_value_transfers`, `erc1155_transfer_logs` and `native_inbound_zero_value` |

No current recorder satisfies the all-mechanisms row, so that benchmark is **blocked**.
Results are reported per supported mechanism and say so. A missing event in a category that is
not `complete` is not evidence that the event did not occur.

## 6. Independence

A case is `independent_candidate` only if all of these hold:
- its victim, paid address and harmful transaction are absent from every development
  artifact (the recorded incident and background windows, the Level I cases, the frozen
  cohorts, the archive episodes);
- it shares no attack cluster with one;
- it was not used to design or tune any frozen method;
- its source is traceable;
- its outcome identity is clear.

Otherwise it is `development`, with the reasons listed. Three consequences:
- a new recording of a known incident stays development;
- related wallets or transactions form one cluster and count once;
- a case with incomplete coverage may support a coverage study, but it does not enter a
  detection benchmark for the mechanisms it cannot observe.

## 7. Blind flow and run-once ledger

1. Record (not in this phase).
2. Check coverage.
3. Freeze the observation artifact (hash).
4. Generate candidates.
5. Freeze candidate identities.
6. Rank with every registered frozen method.
7. **Seal** the prediction: a digest over the case id, observation hash, cutoff, candidate
   identities and every method's order.
8. Open the outcome **only in the evaluator**, which takes a sealed prediction.
9. Compute the declared metrics.
10. Append the result to an immutable ledger.

**Code-level guarantees:**
- The prediction function has no outcome parameter.
- The outcome vault refuses to open before a prediction for that case is sealed.
- The ledger refuses a second scoring of a case with a different prediction digest. A rerun
  attempt is recorded, not hidden.
- Failed and ineligible cases are written to the ledger too.

## 8. Tasks, populations and denominators

| Task | Question | Population (denominator) |
|---|---|---|
| T1 observation recoverability | is the outcome-linked planting in the pre-cutoff observation stream? | cases with a verified outcome whose mechanism category is `complete`; others are reported as "not assessable" |
| T2 candidate generation | is the outcome-linked address a candidate before the cutoff? | all eligible cases (CandidateRecall) |
| T3 ranking | rank of that candidate | cases where it was generated |
| T4 bounded exposure | rank ≤ K | **Conditional TopK:** cases where it was generated. **End-to-End TopK:** all eligible cases; generation failures count as misses. |
| T5 mechanism identification | do the candidate's mechanisms match the labelled mechanism? | cases with a mechanism label and a generated candidate |
| T6 evidence fidelity | does every evidence record of every candidate resolve to a pre-cutoff observation with its provenance fields? | all candidates of all cases (needs no outcome) |
| T7 alert burden | candidates per window and per wallet-day; records per candidate; summary bytes | all windows, labelled or not |
| T8 false alerts | — | **requires verified-legitimate labels; blocked without them** |
| T9 ML generalization | does a trained model beat strong baselines on untouched groups? | independent groups only |

- **MRR** is computed on the T3 population and labelled as such.
- **K** ∈ {1, 3, 5, 10}.
- **Calibration** is never reported for uncalibrated scores.
- **No single "detection accuracy" number is ever produced.**

## 9. Failure taxonomy

**Exactly one class per scored case, assigned in this order:**
1. `outcome_not_verified`;
2. `label_uncertain`;
3. `observation_unsupported` (required category `unsupported` / `not_collected`);
4. `observation_partial` (required category not `complete`);
5. `not_observed_in_complete_stream` (category complete, planting absent);
6. `candidate_not_generated`;
7. `incorrect_reference_matching` (generated without the labelled reference);
8. `ranked_below_k` (reachable only through pagination);
9. `exposed`.

Missing data is never counted as a ranking failure, nor the reverse.

## 10. Baseline registry

**Frozen methods, read-only:**
- generators C0, C1, C2 and `candidate-evidence/2`;
- orders B0 (similarity → recency), B1 (recency), B4 (reference rotation), P1 and P1b.

**Each entry records:** id, revision, config hash, required categories, missingness behaviour
and evaluation status.

**P1b's status** is "failed the 12.7.1 debiased benchmark; comparison only". No method is
modified in this phase.

## 11. Splits and leakage

**Groups** are the connected components over victim, attack cluster, lookalike and planting
signer.

**Strategies:** chronological holdout by group start; leave-one-group-out. Each is feasible
only when enough groups exist, and feasibility is reported, not forced.

**Automated leakage checks** (a failure blocks confirmatory claims):
- post-cutoff observation used;
- outcome fields in the collector request;
- a group on both sides of a split;
- protected-cohort overlap;
- reuse of a spent test population (the 12.1 archive test split; the known incidents).

## 12. Statistical planning

**A reusable tool, with no hard-coded sample size.** For a paired binary comparison (exposed
within K under method A vs B on the same incidents) only **discordant** incidents carry
information. The tool returns, for stated assumptions:
- the exact one-sided sign-test power for n discordant pairs when the better method wins a
  discordant pair with probability p;
- the smallest number of discordant pairs reaching a target power;
- the total incidents needed, given the discordance rate, the eligible fraction and a cluster
  design effect.

Ten incidents with identical predictions decide nothing.

## 13. Offline work on existing data (all development; none is validation)

**D1. Inventory:** every local source, by class:
- source-derived events;
- wallet windows;
- verified incidents;
- outcome-less candidates;
- human-reviewed evidence (expected: 0 submissions);
- synthetic.

Each row gives licence, counts, label status, coverage, protected overlap and eligibility.

**D2. Eligibility:** every local window and every lead in the committed registries, classified
under §4–§6.

**D3. Development regression:** the blind flow run end to end on the unprotected known
windows (pilot, ScamSniffer `/1`, ScamSniffer blind `/2`). Reported as T1–T7 and failure
classes, labelled "known development cases — not independent validation".

**D4. Missingness sensitivity:** controlled in-memory degradations of those windows, never
written and never claimed as real recorder failures:
- no signer lookups;
- no receipts;
- no native observations;
- first half of the window removed;
- recipient history incomplete.

Eligibility, candidate inclusion, rank and failure class are reported for each.

**D5. One targeted measurement, no model.** Phase 12.7.1 left open whether recency ties are
right on real data.
- **Population:** the Phase 12.1 archive **development split only** (the test split is never
  loaded into features). Episodes where the paid lookalike ties at least one rival on
  similarity (`B0`).
- **Quantity:** the share of episodes where the paid one is the most recently planted among
  the tied candidates, against the chance rate 1/t (t = tied candidates). Paired group
  bootstrap over 12.1 groups.
- **Status:** development evaluation, source-conditional (every episode ended in a payoff;
  attackers were not gaming a ranker). Phase 12.1 already reported recency beating similarity
  on this archive, so a positive result is expected and is **not** new independent evidence.

**No model is trained in this phase unless the readiness audit finds a task with independent
labels.** It is not expected to.

## 14. Public-repository safety

A scan of tracked files and of every commit's added lines for:
- high-confidence secret patterns (provider tokens, private-key blocks, RPC URLs with keys,
  URL credentials);
- sensitive file names;
- anything ever tracked under `data/`;
- local user paths;
- identifiers from restricted local sources (archive cache, review sheets). Reported as
  counts only.

A regression test keeps the high-confidence checks in CI. No history is rewritten, and
visibility is not changed.

## 15. Gates

- **Statuses:** PASS, PASS WITH LIMITATIONS, FAIL, BLOCKED BY DATA, NOT EVALUATED.
- **Gates:** G1–G13 as in the phase brief.
- **G11 (generalization evidence)** can pass only on independent incidents. A working
  framework does not pass it.
