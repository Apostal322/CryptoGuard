# Review protocol for the frozen payoff-linked sample (`review-sample/1`)

This protocol was fixed on 2026-11-02, together with the sample and before any review. The
sample's design and hashes are in
[ML_CROSS_DATASET_VALIDATION.md](../../ML_CROSS_DATASET_VALIDATION.md) §26.

## 1. What the review is for

The archive's poisoning categories are Tsuchiya et al.'s own heuristics. The review checks,
independently of them, whether each sampled planting transaction is an address-poisoning
attempt against the listed wallet. Only a reviewed decision can turn a packet into a
`verified_attempt` label (`ml/review.py`). Nothing is labelled from source overlap.

## 2. Materials

All three files are local and git-ignored (`data/ml/poisoning/review_sample/`). They hold
addresses derived from CC BY-NC-ND 4.0 data, so share them only with reviewers, for this
review, and never publish them.

| File | Who sees it | Contents |
|---|---|---|
| `reviewer_sheet.jsonl` | reviewers | 60 items: event id, wallet, address under review, transaction, block |
| `unblinding_key.jsonl` | the maintainer only, after all decisions are in | full packets (subtype, source labels, imitated address, payoff, rival lookalikes) for the 60 items and the 1,335 reserves |
| `sample_manifest.json` | anyone with data access | design, strata, weights, reserves, file hashes |

Before the review starts, check the hashes. Rerunning `cryptoguard ml freeze-review-sample`
verifies the frozen files and changes nothing.

## 3. What a reviewer checks, per item

Use a public block explorer. **No model score exists or is shown.**

1. Does the transaction exist at the given block, and did it move a token (or a
   zero-value transfer record) between the wallet and the address under review?
2. Did the wallet, before that block, transact with a *different* address that shares the
   leading and trailing characters of the address under review? Record which address it
   was and how many characters match.
3. What kind of token is it: a widely used token, or a contract that imitates one (name,
   symbol, decimals)? What is the value: zero, dust, or ordinary?
4. Who initiated the transfer: the wallet itself, or a third party, for example through
   `transferFrom` with zero value?
5. Is there a plausible legitimate reason for this interaction? For example, the address
   under review is the wallet's own second address, or a known counterparty's.

## 4. Decisions

Each reviewer returns one line per item in `poisoning-review/1` format
(`ml/review.py: ReviewDecision`):
- `victim_event_id`;
- `decision`;
- `rationale`, naming the evidence from §3;
- `reviewer` (a pseudonym);
- `reviewed_at` (an ISO time).

| Decision | Use when |
|---|---|
| `confirmed_poisoning_attempt` | 1–4 show an imitation of a real earlier counterparty with no legitimate explanation |
| `likely_poisoning_attempt` | the pattern fits but one element cannot be checked |
| `confirmed_legitimate_interaction` | 5 shows a legitimate relationship |
| `insufficient_evidence` | the explorer data does not allow a decision |
| `conflicting_evidence` | the evidence points both ways |

## 5. Rules

- **Two independent reviewers per item.** Neither sees the other's decisions before both
  have submitted. A disagreement stays on record (`resolve_labels` turns it into
  `conflicting`). Adjudication, if any, is a third, separately recorded decision.
- **Review blind.** Do not open the unblinding key until all decisions are in.
- **No replacements for difficulty.** An item that is hard or ambiguous gets
  `insufficient_evidence` or `conflicting_evidence`. Replacing it would bias the sample.
  A reserve (the next one in the same stratum, in manifest order) is used only when an
  item cannot be presented at all. The replacement and its reason are recorded.
- **Import is all-or-nothing.** `review.import_reviews` validates every line before
  anything is appended. Earlier labels are never overwritten.

## 6. Known limits of the blinding

- An explorer page for the wallet also shows the later payment to the address under
  review. The payment is not hidden; it is only left off the sheet.
- Every item is a source-flagged candidate, with no decoys, so reviewers may expect most
  to be attempts. The rationale requirement and two-reviewer agreement are the
  safeguards. Agreement with the source labels measures label validity on payoff-linked
  attempts. It is not detector precision.
- The sample covers payoff-linked attempts only: attempts that later succeeded. Its
  results do not carry over to attempts in general without the design weights. Even with
  them, they cover the 1,469-packet queue, not the whole archive.

## 7. Analysis plan (fixed in advance)

- **Primary.** The share of items both reviewers mark `confirmed_poisoning_attempt` or
  `likely_poisoning_attempt`.
  - Overall and per subtype, with Wilson 95% intervals (unweighted).
  - Also a design-weighted estimate for the queue.
- **Agreement.** Raw agreement and Cohen's kappa between the two reviewers.
- **Disagreement with the source.** Every item a reviewer marks
  `confirmed_legitimate_interaction` is listed and examined.
- **For scale.** If all 60 items were confirmed, the Wilson 95% lower bound would be 0.94
  overall and 0.86 for each 24-item subtype. The dust (9) and zero-value (3) cells are
  descriptive only.
- **Not concluded from this review:** detector precision or recall, theft probability, or
  any population rate.

---

# Amendment 1 (2026-11-02, before any review)

**Status when written:**
- No reviewer had been recruited.
- No decision existed.
- No reviewer package had been issued.
- The unblinding key was not opened. Its bytes were hashed only.
- No outcome data was inspected. The only data examined were the frozen manifest's
  aggregate design counts and the review queue (the sampling frame), both seen earlier by
  the maintainer while building the sample.
- The frozen sample and the hashes in §2 are unchanged and remain usable.
- No new data is needed.

The text above stays as written. This amendment replaces the clauses it names.
Background: [ML_ANNOTATION_AUDIT.md](../../ML_ANNOTATION_AUDIT.md) §19.

## A1. Defects in the original protocol

1. **§7 asked for a design-weighted estimate "for the queue"** (1,469 attempts). The design
   samples campaign groups through one fixed representative each, so 74 attempts could
   never be selected.
2. **The §7 scale figures (0.94 and 0.86)** are unweighted two-sided Wilson bounds. They
   assume simple random sampling.
3. **No rule existed for variance in strata with one item.**
4. **§6 named the exposure problem but recorded nothing.**
5. **Decisions carried only free text**, so strong labels could not be checked.
6. **Finalization, unblinding and replacement had no mechanics.**

## A2. Corrections

- **Decision format.** Decisions use `poisoning-annotation/1` (`ml/annotation.py`):
  - the §4 decision and a confidence level;
  - the §3 checks as structured evidence states, including the earlier counterparty
    address the reviewer found and the matched characters;
  - exposure: explorer use, viewing after the cutoff block, external labels, source or
    model output;
  - a rationale, and optional notes.

  Every record converts to `poisoning-review/1` for `review.import_reviews`.
- **Evidence rules:**
  - `confirmed_poisoning_attempt` requires the planting observed, the imitated earlier
    counterparty observed and recorded with its matched characters, a legitimate
    explanation looked for and absent, and a rationale of at least five words;
  - `likely` requires the planting observed;
  - `confirmed_legitimate_interaction` requires the legitimate explanation observed;
  - `conflicting_evidence` requires one check marked contradictory.

  Missing evidence is never negative evidence.
- **Estimands.** The primary estimand is the campaign-level share (ML_ANNOTATION_AUDIT.md
  §7). Attempt-level results are bounds only. Victim level is not estimated.
- **Primary statistic.** It is unchanged: an item counts only if both reviewers mark it
  confirmed or likely.
  - The estimate is stratified (weights `N_c/n_c`).
  - Its interval is a two-sided Wilson 95% on the effective sample size, with variance from
    pre-specified collapsed strata (`sample_design.collapse_partners`).
  - Unweighted Wilson intervals are reported, labelled illustrative.
  - For dust and zero-value, raw counts are primary.
- **Sensitivity and secondary results:**
  - counting an item if either reviewer says attempt;
  - an adjudicated result (secondary);
  - replaced originals treated as missing, with bounds.
- **Agreement.** Cohen's kappa (undefined, never 0, when only one category is used) and
  Gwet's AC1, on the five decisions and on attempt versus not. Subgroups are reported only
  with 10 or more items.
- **Exploratory only.** Attempt decisions with and without after-cutoff viewing.
- **Mechanics:**
  - one package and store per reviewer;
  - append-only hash-chained log;
  - finalization with a content hash, after which no edits are possible;
  - replacements only for technical inaccessibility, the next reserve in frozen order,
    logged separately;
  - unblinding only after two distinct finalized submissions pass every check, with each
    key access logged.

## A3. Maintainer checklist

1. `cryptoguard ml review verify`: all five hashes match.
2. Recruit two people with Ethereum explorer experience who did not build the sample. Give
   each a pseudonym (`A`, `B`). Keep any identifying details outside the repository.
3. `cryptoguard ml review package --reviewer A --out <dir>`, and the same for B. Hand each
   reviewer only their own directory and [reviewer-guide.md](reviewer-guide.md). Never
   hand over the key, the manifest, this protocol's analysis sections or the other
   reviewer's directory.
4. If an item cannot be shown at all, run `cryptoguard ml review replace`, then remake the
   packages. Never replace for difficulty.
5. Collect both `annotations/submission.json` files, and record their content hashes in
   the run notes.
6. Optional: adjudication by a third person, recorded as `poisoning-adjudication/1`.
7. `cryptoguard ml review unblind --submission A.json --submission B.json`.
8. Report from `unblinded_report.json` (aggregate). Keep `unblinded_items.jsonl` and the
   submissions local.

---

# Amendment 2 (2026-11-02, before any review; applies to both cohorts)

**Status when written:**
- No reviewer had been recruited, no package issued and no decision made, in either
  cohort.
- No unblinding key was opened. Packets are built from the reviewer sheet and local
  recorded data only.
- The frozen sheets, keys and manifests of `review-sample/1` and
  `hard-negative-candidates/1` are unchanged. Amendment 2 only *adds* a separate,
  hash-registered file.

## B1. Defect

Reviewers of the first cohort saw only four facts:
- the wallet;
- the address under review;
- the transaction;
- the block.

To judge impersonation they had to rebuild the wallet's earlier counterparties on a block
explorer. An explorer also shows the later payment that put every item in this cohort
(hindsight). Where no explorer was used, the protocol gave reviewers too little to work
with.

## B2. Correction: offline pre-cutoff evidence packets (`evidence-packets/1`)

**What a packet holds.** For each item (`ml/evidence.py`, built by
`cryptoguard ml review build-evidence`):
- the candidate transfer(s);
- transaction semantics;
- the token and whether it is on CryptoGuard's reviewed list;
- the number of earlier rows between the wallet and the address;
- up to 50 of the wallet's rows *strictly before* the cutoff block;
- for archive data, how often the address appears with other wallets before the cutoff;
- explicit coverage statuses.

**What it never holds:**
- the source's category flags, its `intended` (imitated) address or its payoff markings;
- any row at or after the cutoff block;
- any model output;
- any similarity score. Reviewers still find the imitated counterparty themselves.

**Coverage.** Archive packets contain only the rows the research dataset kept, so the
imitated counterparty will usually be visible among the earlier rows, but ordinary activity
is missing. The packet says this (`source_selected_rows_only`). It is observable pre-cutoff
information, not the source's conclusion.

**Registered hashes:**

| Cohort | Packets SHA-256 | Items |
|---|---|---|
| `review-sample/1` | `68f11afba87266ee393dcf33a84c913c55fca9c01656f7a1b1d6dfc5122d46ae` | 60 |
| `hard-negative-candidates/1` | `1c7f32c64c9c2beb0342baf8762d5381a5923f0c04389e83dd5da4919cdc01bf` | 35 |

Built at commit `240ba9b` on a clean tree. The review app refuses a packet file whose hash
is not registered.

## B3. Correction: recorded exposure, reasons and citations

Each amendment-2 decision also records:
- `saw_later_victim_payment`: no / yes / unsure;
- `third_party_label_influenced`: no / yes / unsure;
- `used_offline_evidence`: whether the reviewer used the offline panel;
- `reason_codes`: at least one for any confirmed decision;
- `evidence_refs`: transaction hashes or addresses, validated.

Amendment-1 records stay loadable. New submissions must be amendment 2, or the unblinding
gate refuses them.

## B4. Pre-specified sensitivity analyses

1. **Primary results** use every item, whatever the exposure. No item is dropped because
   it was exposed.
2. **Exposure sensitivity.** Repeat the primary analysis excluding items where *either*
   reviewer answered `yes` to `saw_later_victim_payment` or `third_party_label_influenced`.
   Report it beside the primary.
3. **Offline-only sensitivity.** Restrict to items both reviewers judged with
   `used_explorer = false`, where available.

These comparisons are descriptive. Any difference is reported, not "corrected".

## B5. Training before review

Each reviewer first works through the synthetic training package
(`cryptoguard ml review training-package`). It has ten invented cases with evidence
packets and separate teaching notes, read afterwards. Training decisions stay in the
training folder and can never be unblinded. The real items are never used for
calibration.

---

# Amendment 3 (Phase 11.7, before any review or package)

**Status when written:**
- No reviewer had been recruited, no package issued, no decision made.
- No key was opened. The frozen sheets, keys and manifests are unchanged.

## C1. Changes

The evidence packets become `evidence-packets/2`:
1. **Same-block rows of unknown order** relative to the item are counted and flagged
   (`same_block_order_unknown`). Before, they were dropped silently. They are still not
   shown.
2. **The address relationship** carries a coverage-specific interpretation. "None" under
   source-selected or absent coverage is stated not to mean novelty.
3. **Inputs** now include the Phase 11.7 recovery pass: every archive row touching a
   review wallet, address or planting transaction. All 19 Cohort B archive items that had
   no local wallet rows now have pre-cutoff rows. These rows are still source-selected.

## C2. Registered hashes

Built at commit `3ee994f` on a clean tree:

| Cohort | Packets SHA-256 |
|---|---|
| `review-sample/1` | `7f75f5936c7b6e3f96eea7921e9bf2097f114ce65123f7a4db4c46a4c7295747` |
| `hard-negative-candidates/1` | `fcb4765e4a2ef870c003bd1abc4ddf1bf40e69dc1c0747748dd4ce75e51ad567` |

They replace the amendment-2 hashes. Packages made earlier would be refused, but none
existed.

## C3. Leak checks on the built packets

- No payoff transaction and no source label term appear.
- Every history row is before the cutoff block, or a same-block row whose recorded order
  proves it came earlier.
