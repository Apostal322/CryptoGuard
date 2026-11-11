# Reviewer-blinding protocol (Phase 12.9)

**Status:** prospective. It applies to any review run after 2026-11-11. No reviewer has been
contacted, no kit has been sent and no decision exists, so nothing here changes a past
review.

**Rules it implements:** protocol 12.9, sections 1 to 6. The exposure levels and dispositions
are computed by `cryptoguard ml review-blinding`; per-item results stay in the git-ignored
research directory.

## 1. What this protocol can and cannot do

**What it does:**
- **Separates access.** The reviewer sees the task payload only: never the repository, the
  unblinding key, registry statuses, model output or another reviewer's decision.
- **Records what each reviewer knew.** A declaration per task records prior familiarity and
  every consultation.

**What it cannot do:**
- **It cannot make a publicly exposed item blind again.** An item whose outcome is publicly
  discoverable (level R3) stays R3, whatever the interface hides.
- **Instructions are not proof of blindness.** An instruction not to consult public sources is
  a procedural protection only.
- **Only a declaration can show exposure.** Without one, the reviewer's exposure is
  **unknown**, never assumed absent.

## 2. Exposure levels used in tasks

| Level | Meaning | Use |
|---|---|---|
| R0 | no public match found | eligible for an explicitly qualified blinded review |
| R1 | identifier visible in neutral public files only | eligible for an explicitly qualified blinded review |
| R2 | incident or campaign context publicly discoverable | qualified blinding; reported as a sensitivity stratum |
| R3 | outcome publicly discoverable | not eligible for confirmatory blinded evaluation |
| RU | only truncated matches, or unreadable | exposure must be clarified first |
| R4 | the reviewer declared familiarity or a consultation on an R3 item | excluded from confirmatory use |

- **R4 is never computed from R3.** It comes only from the reviewer's own declaration, or from
  independent evidence that the reviewer saw outcome-bearing material.

## 3. Task payload

**A task's payload is built from a fixed whitelist of blinded-sheet fields:**
- `item`, `chain_id`, `wallet`, `address_under_review`, `transaction`, `block`;
- `context`, holding `block`, `counterparty`, `direction` and `value` only;
- `coverage_note`.

**Before a task is issued, `assert_payload_clean` refuses:**
- any other key that names a label, status, verdict, outcome, payoff, attribution, score, rank,
  prediction, decision, source, cohort, stratum or purpose;
- any text value with outcome-bearing wording.

The error names the location, never the value.

**The task record (not shown to the reviewer) carries:**
- an opaque task id: a hash of the sheet hash and the item number, which names neither the
  cohort nor its purpose;
- the item version (the sheet's SHA-256);
- the evidence version and the evidence SHA-256;
- the item's computed exposure level.

## 4. Reviewer guidance (given to reviewers verbatim)

<!-- reviewer-guidance:start -->
You will see one wallet, one address under review and one transaction. Some tasks also list
a few of the wallet's other transfers.

Decide, from the evidence shown, which decision option best describes how the address under
review relates to the wallet. Use only the evidence in the task and chain data up to the
block shown.

While you work on a task:

- Do not look up the wallet, the address or the transaction in this project's repository,
  in news articles, in incident write-ups or in social-media posts.
- Do not rely on name tags, warnings or other annotations that a block explorer may display.
  If you notice one, say so in your declaration.
- If you already recognise the wallet, the address or the transaction, say so in your
  declaration and continue.
- Choose "insufficient evidence" whenever the evidence shown does not support a decision.

Every option is acceptable. There is no target distribution of answers, and nothing about
your answer affects which tasks you receive next.

After each task, answer the four declaration questions below. Answer each with yes, no or
unknown. "Unknown" is a valid answer and is never read as "no".

| Field | Question |
|---|---|
| `prior_familiarity` | Before this task, had you seen or heard of this wallet, this address or this transaction? |
| `external_sources_consulted` | During this task, did you consult anything outside the task, such as news, incident reports, social media, or explorer name tags or warnings? |
| `repository_consulted` | During this task, did you open this project's repository, its reports or its data files? |
| `model_output_seen` | Did you see any score, rank or warning that a model or a tool produced for this item? |
<!-- reviewer-guidance:end -->

**Checking the guidance:**
- `guidance_findings` screens this section for prevalence hints and source-verdict wording; the
  tests require zero findings.
- The guide in the two prepared, unsent kits had 4 screen hits in 2 files. On reading, all four
  are benign:
  - two hits are the name of a decision option;
  - one is a sentence about the evidence panel;
  - one is a question asking whether the reviewer saw a source label, a payoff record or model
    output.
- Even so, the kits predate the declaration form. They must be rebuilt from this section before
  any use.

## 5. Declaration rules

**Declarations are given by the reviewer, per task:**
- They use the `ReviewerDeclaration` schema: reviewer id (an opaque code), task id, the four
  answers, and the time of the declaration.
- Nothing is filled in on the reviewer's behalf.

**How a review's exposure is set (`review_exposure`):**

| Declaration | Review exposure |
|---|---|
| missing | RU |
| any answer `unknown` | RU |
| familiarity, an external source or the repository `yes` on an R3 item | R4 |
| otherwise | the item's level |

`model_output_seen` is reported separately and never folded into the level.

## 6. Adjudication readiness

`adjudication_readiness` requires all of the following:
- two or more distinct reviewers (`label_policy.MIN_REVIEWERS`);
- one decision each;
- the same evidence SHA-256 as the task;
- a declaration from each reviewer that names this task.

A decision set is **confirmatory** only when every review's exposure is R1 or below. Missing
decisions are never replaced by a default.

## 7. Dispositions of the frozen cohorts (aggregates)

The frozen files are byte-identical before and after the audit (committed hashes verified).
They are not rewritten; dispositions are a separate local record.

| Cohort | Items | Combined level | Disposition |
|---|---|---|---|
| A (`review-sample/1`) | 60 | 60 × R3 (external: the public dataset labels each item's payoff victim) | not eligible for confirmatory blinded evaluation; exploratory or sensitivity only |
| B (`hard-negative-candidates/1`) | 35 | 4 × R3, 30 × R2, 1 × R1 | 4 not eligible; 30 sensitivity stratum with qualified blinding; 1 eligible for a qualified blinded review |

- **No replacement cohort is drawn in this phase.** The archive pools carry the public
  dataset's labels (R2 or R3 externally).
- **The recorded incident windows are public context (R2).** Only the unlabelled background
  windows and new recordings could supply R0 or R1 items; the second option needs a separately
  approved RPC budget.
- **A new cohort is therefore reported as blocked by data.**
