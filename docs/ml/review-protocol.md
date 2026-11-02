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
