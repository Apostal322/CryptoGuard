# Annotation audit: the frozen review sample (Phase 11.4)

Status: **review-ready. No human decision exists yet.** Two independent human reviewers are
needed. Nothing below is a reviewed result.

- Every number comes from `cryptoguard ml review audit`, which is offline, makes 0 RPC
  requests and writes aggregate-only JSON to `data/ml/poisoning/review/design_audit.json`.
- Code:
  - `ml/review_sample.py` (verification);
  - `ml/sample_design.py` (design and estimators);
  - `ml/annotation.py`, `ml/review_server.py`, `ml/agreement.py`, `ml/unblind.py`
    (workflow).
- Protocol: [docs/ml/review-protocol.md](docs/ml/review-protocol.md), with amendment 1.

## 1. Frozen sample identity

Re-verified on 2026-11-02 from the raw bytes (`cryptoguard ml review verify`). All five
committed hashes in ML_CROSS_DATASET_VALIDATION.md §26 match:

| Item | SHA-256 | Basis |
|---|---|---|
| review queue (input) | `84f8268e…b42e83` | raw bytes |
| selection | `e368beb4…85a62` | SHA-256 of compact, key-sorted JSON of the selection fields (`review_sample._canonical`) |
| `reviewer_sheet.jsonl` | `a0ec4b6e…814027` | raw bytes (LF line endings, key-sorted JSON lines) |
| `unblinding_key.jsonl` | `407b412f…03bb2d` | raw bytes |
| `sample_manifest.json` | `c38ae31d…dbdc3` | raw bytes |

**How verification works:**
- It recomputes the selection hash from the manifest instead of trusting the recorded
  value. It also checks the manifest's own file hashes and that the selected ids equal the
  sheet ids.
- It never writes. A mismatch is reported, and the file is left as found.
- **No canonicalization was changed.** The hash bases above are the ones used at freezing.
- Redrawing from the queue with the frozen code gives the identical selection.
- No frozen file was modified, regenerated or reordered in this phase.

## 2. Dataset provenance

- **Frame:** the 1,469 payoff-linked attempt packets, built by `ml/reconcile.py`
  (`reconcile/1`) from Tsuchiya et al.'s attempt archive and payoff list
  (CC BY-NC-ND 4.0). See ML_CROSS_DATASET_VALIDATION.md §11.
- **Who is in it:** each packet is the latest source-labelled attempt by a lookalike
  against a victim before that victim paid that lookalike.

## 3. Sampling frame and units

| Unit | Count | Meaning |
|---|---|---|
| attempt (packet) | 1,469 | one payoff-linked planting attempt |
| victims | 1,407 | distinct victim wallets |
| campaign group | 1,395 | attempts linked by victim, lookalike, planting tx or imitated address |
| representative | 1,395 | one attempt per group: the lowest `sha256(seed\|rep\|id)` |
| item | 60 | representatives drawn into the sample |

- 62 groups hold more than one attempt (136 attempts, at most 6 per group).
- 26 groups span more than one stratum.
- 12 groups hold two victims.
- **74 attempts are not representatives** and could never be selected.
- All 60 items come from single-attempt groups.

## 4. Campaign grouping and the 1,401 versus 1,395 discrepancy

- **Where each number came from:**
  - **1,401** appeared only in a chat progress message during Phase 11.3. It was the output
    of an exploratory profiling script, run before the sampler was written, that linked
    attempts by victim, lookalike and planting transaction only.
  - **1,395** is the frozen design. It also links by imitated address, because attempts
    imitating the same counterparty were treated as one campaign. That merges 12 of the
    exploratory groups into 6.
- **No defect in the frozen draw:** the manifest, §26 and the code agree on 1,395, and the
  1,401 figure was never committed. The audit recomputes both counts on every run.
- **When the rule was chosen:** after seeing aggregate group and subtype counts, before any
  review existed. No outcome information was available or used.

## 5. Sampling strata

- **Definition:** subtype × block-height period × rival lookalike present. The strata are
  mutually exclusive and cover all 1,395 representatives (audit checks
  `strata_partition_representatives` and `strata_counts_match_queue`).
- **Year names are approximate:** the year boundaries (blocks 16,308,190 and 18,908,895)
  were entered from memory and could not be checked offline, because the archive has no
  timestamps. The strata are exact as block ranges. 15 attempts lie within 7,200 blocks
  (about a day) of a boundary.

| Stratum | Attempts | Groups N | Ideal share | Selected n | π | Weight N/n | Reserves |
|---|---|---|---|---|---|---|---|
| dust, 2023, no rival | 8 | 8 | 1.44 | 1 | 1/8 | 8.0 | 7 |
| dust, 2023, rival | 29 | 25 | 4.50 | 5 | 5/25 | 5.0 | 20 |
| dust, 2024, no rival | 8 | 8 | 1.44 | 1 | 1/8 | 8.0 | 7 |
| dust, 2024, rival | 14 | 9 | 1.62 | 2 | 2/9 | 4.5 | 7 |
| fake token, 2023, no rival | 305 | 293 | 9.63 | 10 | 10/293 | 29.3 | 283 |
| fake token, 2023, rival | 363 | 339 | 11.15 | 11 | 11/339 | 30.82 | 328 |
| fake token, 2024, no rival | 39 | 39 | 1.28 | 1 | 1/39 | 39.0 | 38 |
| fake token, 2024, rival | 62 | 59 | 1.94 | 2 | 2/59 | 29.5 | 57 |
| spoofed transferFrom, 2022, no rival | 111 | 103 | 4.04 | 4 | 4/103 | 25.75 | 99 |
| spoofed transferFrom, 2022, rival | 59 | 58 | 2.28 | 2 | 2/58 | 29.0 | 56 |
| spoofed transferFrom, 2023, no rival | 105 | 103 | 4.04 | 4 | 4/103 | 25.75 | 99 |
| spoofed transferFrom, 2023, rival | 344 | 330 | 12.94 | 12 | 12/330 | 27.5 | 318 |
| spoofed transferFrom, 2024, no rival | 1 | 1 | 0.04 | 1 | 1/1 | 1.0 | 0 |
| spoofed transferFrom, 2024, rival | 18 | 17 | 0.67 | 1 | 1/17 | 17.0 | 16 |
| zero-value, 2023, rival | 3 | 3 | 3 | 3 | 3/3 | 1.0 | 0 |

- **Rounding.** The allocation was recomputed independently and matches. The minimum of
  one per stratum gave the single-group stratum (spoofed, 2024, no rival) one item, so the
  largest spoofed stratum got 12 instead of 13. The weights account for this.
- **Zero-value is a census of the frame only.** Its 3 groups are all the zero-value
  attempts in the payoff-linked frame, not all zero-value poisoning.
  - Here, zero-value means a zero-value transfer *to* the victim.
  - A zero-value `transferFrom` that shows the victim as sender is labelled "spoofed
    transferFrom".

## 6. Selection probabilities

- **Exact part:** given the representatives, an item's inclusion probability is exactly
  `n_c / N_c` (stratified sampling without replacement, keyed-hash ranking treated as a
  random permutation).
- **The attempt level needs a model:** `(1/m_g)·n_c/N_c` holds only if the representative
  is considered random within its group. Under the fixed hash, the 74 non-representatives
  have probability zero.
- **No label influenced selection beyond the strata.** The rival flag comes from the
  source archive, as preregistered.

## 7. Weighting and estimands

| Estimand | Definition | How it is estimated |
|---|---|---|
| A, campaign (primary) | share of the 1,395 campaign groups whose representative attempt reviewers support as an attempt | stratified (Hájek) estimator, weights `N_c/n_c` |
| B, attempt | share of the 1,469 attempts supported | **bounds only**: `[L·1395/1469, (U·1395+74)/1469]` from A's interval |
| C, agreement | consistency between two reviewers on the 60 items | unweighted (it describes the sample) |
| D, subtype | A within each subtype | same estimator; zero-value is a frame census |
| victim level | – | **not estimated**: victims are nested in groups, and 12 groups hold two |

- **Weights:** exact rationals in the analysis. The manifest's rounded values differ by at
  most 1.8×10⁻⁷. They sum to 1,395.
- **Kish design effect:** 1.20 overall (effective n ≈ 50), 1.00–1.06 within subtypes.

## 8. Confidence-interval assumptions

- **What the original protocol's bounds were.** "0.94 overall, 0.86 per 24-item subtype"
  are the lower ends of **two-sided unweighted Wilson 95%** intervals (0.9398 and 0.8620),
  which assume a simple random sample of items. They are reproduced exactly, and they do
  not describe the weighted design.
- **Design-based interval (amendment 1).** It is a Wilson interval on the effective sample
  size:
  - `n_eff = p(1−p)/v̂`;
  - `v̂` is the stratified variance with finite-population correction, using pre-specified
    collapsed strata for the four single-item strata;
  - when `p` is 0 or 1, it uses `n / deff_Kish` instead.
- **If all 60 were confirmed**, the lower bounds would be:

  | Scope | Lower bound |
  |---|---|
  | overall | **0.929** |
  | fake token | 0.862 |
  | spoofed transferFrom | 0.856 |
  | dust | 0.689 |
  | zero-value | 1.0 (frame census, no sampling error) |

- **These intervals are approximate.** For dust (9) and zero-value (3), raw counts are the
  primary report.

## 9. Reviewer blinding

| Hidden from the reviewer (never sent by the server) | Still visible |
|---|---|
| subtype, source labels, imitated address, payoff, rival lookalikes, evidence summary, strata, weights, model score | wallet, address under review, planting transaction, block |

**How it is enforced:**
- The server reads only the reviewer package: the sheet and the reviewer's own store. The
  package never contains the key or the manifest.
- Static files hold no data.
- A test searches every response (HTML, JS, CSS, state, saves and errors) for every value
  only the key holds.
- Drafts in browser storage hold only the reviewer's own input. The session token stays in
  the tab's session storage.

**What stays visible:** a block explorer shows later activity, including the payment, and
explorer labels such as phishing tags. This is partial blinding. Amendment 1 records it
per item: explorer use, viewing after the cutoff, external labels, source or model output.

**Evidence sufficiency:**
- Hiding the imitated address does not prevent judgement. Reviewers find the earlier
  counterparty in the wallet's history before the cutoff, and record it with the matched
  characters.
- At unblinding, their counterparty is compared with the source's imitated address,
  giving an independent check of the source's matching.
- An offline evidence packet was **not** built. The only local pre-cutoff history is the
  source's own intended-transfer matching, which would reveal the answer.

## 10. Reviewer independence

- Each reviewer gets a separate package (`cryptoguard ml review package`) and store, and
  can open no one else's.
- A second server on the same store is refused (OS lock).
- The maintainer combines submissions only after both are finalized.
- On a shared computer, independence is procedural, not technical. The guide asks for
  separate machines or accounts.
- The two reviewers must be **two distinct people**. Two model sessions, prompts or
  classifier outputs are not reviewers.
- The maintainer who built the sample has seen the source information and must not review.

## 11. Evidence requirements

Amendment 1 adds structured checks to each decision (`poisoning-annotation/1`):
- planting transfer, earlier counterparty (address and matched characters), token, value,
  initiator and legitimate explanation;
- each with an evidence state: observed / looked for and absent / not available / not
  looked at / not applicable / contradictory.

Strong decisions are refused without their evidence (`annotation.evidence_problems`).
Missing data is never read as negative evidence. Later theft is not required for an
attempt.

## 12. Replacement policy

**Allowed reasons:** technical inaccessibility only (`transaction_not_found`,
`chain_data_unavailable`, `sheet_record_malformed`).

**Rules:**
- The replacement is the next reserve of the same stratum, in frozen order, enforced by
  `validate_replacements`.
- Each record keeps the original and the replacement (event and item), the stratum, the
  reserve position, the reason, the evidence, which reviewers were exposed to the
  original, who recorded it and when, and the protocol version.
- A replacement never edits the frozen files. It goes into
  `data/ml/poisoning/review/replacements.jsonl`, and the reviewer package receives only
  the blinded line.
- **Statistics:** the replacement takes its original's design slot (missing at random
  within the stratum is assumed). A sensitivity analysis treats each replaced original as
  missing, with bounds at 0 and 1.

## 13. Submission freeze

- **The log:** each reviewer's log is append-only and hash-chained. Every save rewrites
  the file atomically (temporary file, fsync, replace).
- **Revisions:** a revision appends, and the earlier record stays. An identical resubmit
  is a no-op. A save based on an older revision is refused.
- **Finalizing** needs a decision for every item. It writes `submission.json` with a
  content hash, then refuses further edits; changes need an amendment.
- **Tampering:** edited logs and submissions are detected (hash chain, content hash).

## 14. Agreement analysis

`ml/agreement.py` reports:
- paired and unpaired items;
- per-reviewer counts;
- the confusion matrix and number of disagreements;
- observed agreement;
- Cohen's kappa (`None`, with a reason, when undefined);
- Gwet's AC1, because one category is expected to dominate.

It covers both the five decisions and attempt versus not-attempt. Subgroups (subtype, year,
rival) are reported only with 10 or more items. Weighted kappa is not used, because the
categories have no order.

## 15. Adjudication

- **Optional, and never a replacement.** A third person's decision is recorded beside the
  two originals, never instead of them.
- **Who may adjudicate:** the adjudicator must differ from both reviewers, and the recorded
  originals must equal the submissions. Agreed items cannot be adjudicated.
- **How it is reported:** the primary result keeps the disagreement (an item counts only if
  both reviewers say "attempt"). The sensitivity result counts an item if either says so.
  The adjudicated result is secondary.

## 16. Unblinding

`cryptoguard ml review unblind` runs these checks first:
- frozen hashes;
- valid replacements;
- two distinct finalized submissions, with valid content hashes, for this sample, sheet and
  protocol, covering exactly the active items;
- valid adjudications.

On any failure it opens nothing. There is no override flag. Each key access is appended to
`key_access.log.jsonl`.

**Outputs:**
- an aggregate report;
- a row-level item table (local, git-ignored);
- source comparison categories: full agreement, partial agreement, reviewer disagreement,
  insufficient evidence, source disagreement, unresolved ambiguity.

Source labels never overwrite reviewer decisions.

## 17. Outcome leakage

The frame is payoff-linked, so a reviewer may see the later payment.

- **Two separate questions:** *attempt validity* (was the planting an attempt?) and the
  *subsequent outcome* (did a payment follow?). The protocol asks only the first.
- **What is recorded:** exposure is recorded per decision.
- **Exploratory comparison:** the report compares attempt decisions with and without
  after-cutoff viewing, per reviewer. This is not preregistered and not causal.

## 18. Statistical limitations

- **Population.** The estimates describe payoff-linked campaign groups from one source's
  detector, over July 2022 to June 2024, for ERC-20 tokens. They do not give global
  poisoning prevalence, detector precision, recall or false-positive rates.
- **Positive frame only.** With no legitimate items in the sample, reviewers know almost
  everything is a candidate, so acquiescence is possible. Agreement and rationales are the
  safeguard. Negatives come later (ML_BENCHMARK_READINESS.md).
- **Small strata.** Four strata have one item, and dust and zero-value are small. Their
  intervals are approximate, and counts are primary.
- **Licensing.** Review decisions are keyed by event ids derived from CC BY-NC-ND data.
  Whether derived per-item labels may be published is unresolved, so submissions and item
  tables stay local. This is not legal advice.

## 19. Audit register (Phase 11.4)

| ID | Pri | Finding | Status |
|---|---|---|---|
| 21 | P1 | **Estimand unit mismatch.** Protocol §7 asked for a design-weighted estimate "for the queue" (1,469 attempts), but the weights are campaign-level, and 74 attempts have zero inclusion probability | Amendment 1: campaign estimand primary; attempt level as bounds; victim level not estimated |
| 22 | P1 | **Protocol bounds assumed simple random sampling.** 0.94 and 0.86 are unweighted two-sided Wilson; the design-based all-confirmed bound is 0.929 overall | Amendment 1: design-based interval primary; unweighted labelled illustrative |
| 23 | P1 | **No variance rule for single-item strata** (four strata) | Amendment 1: pre-specified collapse rule (`collapse_partners`), fixed before any review |
| 24 | P1 | **No exposure recording.** The explorer reveals later payments and phishing tags | Amendment 1: exposure fields per decision; exploratory comparison |
| 25 | P1 | **Free-text rationale only.** Strong labels could not be checked against evidence | Amendment 1: structured checks with validation |
| 26 | P1 | **No mechanics for finalization, unblinding or replacement** | Implemented: hash-chained store, finalization, gated unblinding, replacement log |
| 27 | P2 | **Year boundaries described as "from a block explorer"** but entered from memory | Comment corrected; strata are exact block ranges; values unchanged |
| 28 | P2 | **1,401 versus 1,395 groups** | Explained (§4): exploratory count without the imitated-address link; never committed |
| 29 | P2 | **Manifest weights rounded to 6 decimals** | The analysis uses exact `N_c/n_c` |
| 30 | P2 | **"Zero-value" naming** covers only zero-value transfers to the victim | Documented (§5) |

No P0 finding: every hash, uniqueness, separation, allocation and reserve-order check passes.

## 20. Second cohort (Phase 11.5)

- **The cohort.** A separately frozen cohort, `hard-negative-candidates/1` (35 unlabeled
  candidates), uses the same app, store, finalization and unblinding gate.
- **How cohorts are kept apart:**
  - each cohort has its own committed hashes in `review_sample.COHORTS`;
  - a reviewer package names no cohort, so the server finds the cohort by the sheet's hash;
  - items carry the neutral title "Candidate for independent security review".
- **The Phase 11.4 sample is unchanged** (re-verified).
- Design and hashes: [ML_HARD_NEGATIVE_STUDY.md](ML_HARD_NEGATIVE_STUDY.md) §12.

## 21. Amendment 2 and evidence packets (Phase 11.6)

- **Evidence packets.** Both cohorts now carry offline, pre-cutoff evidence packets
  (`evidence-packets/1`, hashes registered). The packets never contain source flags, the
  intended address, payoffs or similarity scores.
- **New decision fields.** Each decision records later-payment exposure, third-party-label
  influence, offline-panel use, reason codes and evidence citations.
- **Calibration.** A synthetic training cohort precedes real review.
- **Sensitivity analyses** are pre-specified in protocol B4.
- **Status:** [ML_HUMAN_VALIDATION_READINESS.md](ML_HUMAN_VALIDATION_READINESS.md).

## 22. Amendment 3 (Phase 11.7)

- **New packets.** The evidence packets are now `evidence-packets/2`: same-block rows of
  unknown order are counted, and the coverage wording is explicit. Recovered archive rows
  give every Cohort B archive item pre-cutoff history. The hashes are registered before
  any review.
- **Server fixes.** The review server refuses malformed `Content-Length` and foreign
  `Origin`s.
- **Workflow test.** A full synthetic review workflow, with failure injection, is tested
  end to end.
- **Details:** [ML_EVIDENCE_COMPLETION.md](ML_EVIDENCE_COMPLETION.md).
