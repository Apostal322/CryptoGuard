# Wallet-centric poisoning dataset (task `poisoning-attempt/1`)

Status: **data model, parser, label protocol and quality gates are implemented; no dataset that
passes the gates exists yet.** No model is trained for this task. Numbers below come from
`cryptoguard ml poisoning-report` (tables: [ML_POISONING_TABLES.md](ML_POISONING_TABLES.md)).

This task is separate from the Phase 11 PTXPhish classifier (`ptxphish-transaction-phishing/1`,
[ML_EVALUATION.md](ML_EVALUATION.md)). That model asks whether a mined transaction belongs to
a phishing operation. Its labels are not poisoning-attempt labels and are not reused here.

## 1. Events that must not be confused

| Category | Meaning | Where it lives |
|---|---|---|
| Poisoning attempt | A planting transfer meant to put a lookalike into a victim's history | `PoisoningEvent` with a `LabelRecord` |
| Confirmed victim loss | Recorded evidence that the victim moved value to the lookalike | `OutcomeRecord.status = confirmed_direct_payment`, verified by `ml/payments.py` |
| Unresolved outcome | What happened next is unknown or incompletely observed | `OutcomeRecord.status` `unresolved` / `partial_coverage` / `not_evaluated` |
| Confirmed legitimate activity | Independent review found a legitimate interaction | `LabelRecord.tier = verified_legitimate` |
| Unlabelled background | Chain data without ground truth | no label, or tier `unknown` |

An attempt can be real when nobody loses money. An unobserved payment is not proof that no
payment happened. A victim who did not pay is never called "benign".

## 2. Prediction unit, target and cutoff

- **Unit:** `(chain_id, victim, candidate_event_id, observation_cutoff)`. A candidate event is
  one suspicious transfer seen by one wallet.
- **Target:** the poisoning-attempt status of that event (label tiers below). Whether the
  victim later lost money is a secondary outcome, stored apart, and never a feature.
- **Cutoff:** after the planting transaction executes, before any later transaction in the
  same block (`history` boundary `pre_execution`, with the event's own transaction
  excluded). When the transaction index is unknown, only earlier blocks are visible. The
  cross-wallet index (`PriorIndex`) sees only earlier blocks.
- **Output:** an experimental ranking or priority score with evidence and coverage. It is
  not a probability of theft, and it never creates or changes a finding.

## 3. Schema (`ml/events.py`, `poisoning-event/1`)

`PoisoningEvent` records:
- chain ID, victim, lookalike and imitated address;
- planting transaction, block, transaction index and log index;
- subtype, verified signer, log-emitting contract and token contract;
- candidate-generation method, evidence references, coverage status and dataset version.

Unknown values are `None`, never guessed. `LabelRecord` and `OutcomeRecord` are separate
models, each with its own source and availability time.

**Identity.**
- `planting_tx_id` = `chain:tx_hash`. One batched transaction can plant many victims.
- `victim_event_id` = hash of chain, victim, planting tx, lookalike and log index. Repeated
  victim-events are duplicates and are dropped (`deduplicate`).
- `campaign_groups` is a union-find over victims, lookalikes, planting transactions and
  signers. Reviewed public infrastructure (`ml/dataset.py: PUBLIC_INFRASTRUCTURE`, 15
  contracts) is exempt. High degree alone does not exempt an address.
- `grouped_temporal_split` keeps whole groups on one side, and the latest-starting groups
  form the test set.

## 4. Label tiers and protocol

| Tier | Use |
|---|---|
| `verified_attempt` | Trainable positive: independent review confirmed an attempt |
| `verified_legitimate` | Trainable negative: independent review confirmed a legitimate interaction |
| `weak_attempt` | A source pipeline says attempt. Positive-case reproduction and candidate recall only |
| `likely_legitimate` | Limited evidence. Not a training negative |
| `conflicting` | Verified disagreement, or weak versus likely |
| `unknown` | No usable evidence |

`resolve_labels` lets verified labels win over weak ones. Verified disagreement becomes
`conflicting`, and nothing is overwritten.

**Review workflow (`ml/review.py`).** Packets carry the evidence, the coverage limits and the
source labels, but **no model score**. Decisions are `confirmed_poisoning_attempt`,
`likely_poisoning_attempt`, `confirmed_legitimate_interaction`, `insufficient_evidence` or
`conflicting_evidence`. They are validated all-or-nothing and appended to the label history.

**Negatives.**
- Random unlabelled wallets are not confirmed benign. A verified negative needs a reviewed
  legitimate interaction that resembles a planting. Examples:
  - a first payment to a new counterparty that independent evidence ties to the wallet's
    owner;
  - a similar-looking address that turns out to be legitimate;
  - an unsolicited dust transfer from a known airdrop.
- Negatives should be matched to positives by period, transfer type, token, amount, wallet
  activity, coverage and candidate rule. Otherwise the source itself becomes a shortcut.
- None exist yet.

## 5. Poison-Hunter sample (`ml/poison_hunter.py`)

**Source.** `DS2L/Poison-Hunter` at commit `74ff6f7d`, file `phishing_transfers_sample.csv`
(SHA-256 `1de4bf2a…`, pinned in `ml/sources.py`). Guan and Li, CCS 2024. **No license:**
the raw file stays local and is never redistributed.

**Field identification.** Checked on all 150 rows; the full table is in the module
docstring.
- The 15-name header is aligned with fields 0–14, and each row carries 2 extra unnamed
  fields. An earlier note called the columns "shifted"; that was imprecise.
- Two names misdescribe their content:
  - `fake_token_address` holds the genuine USDC/USDT contract for `dust` and `zero` rows;
  - `is_batching` holds a batch size, not a flag.
- Field 15 (`from`/`to`) is read as the direction of the imitated transfer.
- Field 16 equals our prefix+suffix match count in 135 of 149 rows, so it is probably the
  source's own similarity count. This is inferred, not documented.
- Signers match the subtype: `dust` rows are signed by the lookalike itself, while `zero`
  and `fake` rows are signed by batch operators.

**Validation.**
- 149 rows are valid and 1 is quarantined.
- 123 victims, 128 lookalikes, 116 planting transactions (7 batched), 6 duplicate
  victim-events.
- Blocks 15,861,385–17,965,129.
- The similarity definition matters:
  - CryptoGuard's detector predicate accepts 139 rows;
  - Tsuchiya et al.'s definition (at least 3 leading and 4 trailing hex characters)
    accepts 105, because 31 `dust` rows share only 2 leading characters.

**Quarantined row (CSV line 3).**
- It is the only row with direction `to`.
- Its lookalike shares 2 leading and 1 trailing hex characters with the imitated address,
  below every published definition.
- Possible explanations:
  - the imitated address for direction `to` is recorded differently;
  - the row is a source error;
  - it is a non-lookalike subtype.
- None of these can be decided offline. The row is kept, marked quarantined, and is not
  called benign.

**Label status.** All 143 distinct victim-events are `weak_attempt`. They are useful for
positive-case reproduction, candidate recall and feature testing, not for binary training.

## 6. Quality gates (`quality_gates`)

| Gate | Current state |
|---|---|
| A: data validity | Passes. Events parse reproducibly, with no duplicate identities |
| B: label validity | **Fails.** 0 verified positives, 0 verified negatives (30 each needed) |
| C: temporal validity | Passes. Every event has a planting block; the cutoff is defined |
| D: split validity | **Fails.** No verified groups to split |
| License | **Fails** for redistribution. Raw rows stay local |
| E: baseline comparability | Not reached: needs a labelled population shared by the detector and a model |
| F: statistical adequacy | Not reached |
| G: deployment isolation | Passes. The shadow scorer serves only `ptxphish-transaction-phishing/1` cards; findings are unchanged with ML on or off (integration test) |

Training for this task is blocked until gates B and D pass.

## 7. External sources reviewed

These were checked from the source pages on 2026-11-02 by a research agent; details are in
ML_RESEARCH_PLAN.md §5.

| Source | What it offers | Blocker |
|---|---|---|
| Tsuchiya et al., USENIX Security 2025 (KiltHub DOI 10.1184/R1/29212703.v1) | Ethereum attempts (2.3 GB SQL dump) plus payoff-transfer CSVs (under 2 MB) | Licence CC BY-NC-ND 4.0. The Ethereum payoff CSV (§8) and the attempt archive (§9) are downloaded with approval; the BSC file is not |
| Poison-Hunter full data | Withheld; "contact us", with no address published | Request needed |
| Forta labelled datasets | MIT, Etherscan-derived address labels | No poisoning category, no loss transactions |
| Etherscan labels | Underlie Forta and Poison-Hunter ground truth | Terms require written permission for ML or dataset use |

## 8. Tsuchiya et al. payoff transfers (`ml/tsuchiya.py`, `tsuchiya-payoff/2`)

**Source.**
- `payoff_transfers_ethereum.csv` from KiltHub DOI 10.1184/R1/29212703.v1, CC BY-NC-ND 4.0.
- Downloaded once with your approval on 2026-11-02 into the git-ignored
  `data/external/tsuchiya2025/`. 482,397 bytes; the MD5 matches KiltHub's; the SHA-256 is
  pinned in the module.
- Not listed in `ml/sources.py`, because `fetch-sources` would download it unasked.
- The licence permits local non-commercial research use but no redistributed adaptations.
  Only aggregate counts and Poison-Hunter line numbers leave the module.

**Columns.** 11 named columns, each identified on all 1,738 rows:
- block and transaction;
- token contract (`addr`);
- payer, the victim (`topics_from_addr`);
- recipient, the lookalike (`topics_to_addr`);
- amount in base units, printed from a PostgreSQL `real` (float4), plus the source's
  historical USD valuation;
- `is_sender_victim` (always `True`);
- leading and trailing matched digits;
- the intended address.

**Validation.**
- 1,738 rows are valid and 0 are quarantined.
- Every row's declared affix counts equal `affix_match` on its addresses.
- One row per transaction: 1,502 payers and 1,551 lookalikes.
- Blocks 16,060,625–20,207,365.
- Tokens: USDT 1,154, USDC 543, DAI 36, other 5. None are native ETH.
- Amount precision (corrected in Phase 11.3; Phase 11.2 reported 41 inexact amounts
  using the float64 limit): float4 is exact only up to 2^24 base units, so 1,644 amounts
  are approximations and 94 are exact. Each record keeps the verbatim source text, a
  precision class, and a human amount only for tokens with known decimals (USDT, USDC,
  DAI). USD values stay the source's valuation and are never recomputed.
- Identity: `payoff_id` = chain, transaction, token, payer, recipient (the source has no
  log index); 0 duplicates.

**How it is used.**
- **As outcome evidence only: a victim paid a lookalike.** It contains no planting
  transactions, so it creates no `PoisoningEvent` and no label.
- **Absence is not a negative.** A victim missing from the file has not been shown to
  have avoided a loss. The file has no ETH, covers only lookalikes the study detected with
  at least 3 leading and 4 trailing matches, and ends in mid-2024.
- **Per-event attribution.** A payoff to a different lookalike of the same address (one
  case, line 74) is a loss for the victim, not an outcome of that Poison-Hunter event.

## 9. Tsuchiya et al. attempt archive (`ml/tsuchiya_archive.py`, `tsuchiya-archive/1`)

- `address_poisoning_ethereum.sql.gz`: a PostgreSQL dump of 34,905,969 token transfers
  (July 2022 to June 2024), each flagged intended, zero-value, tiny, counterfeit, payoff,
  unconfirmed payoff or uncategorized. It is streamed, never executed; only rows touching a
  target manifest are kept, in a local SQLite subset.
- Its categories are the source's heuristic labels. Every poisoning row meets the source's
  3+4 lookalike rule. They are not loaded as `LabelRecord`s.
- **Payoff-linked attempts** are the latest archive attempt by the paid lookalike against
  the victim before the payoff. They become `PoisoningEvent`s only inside review packets
  (`ml/reconcile.py`, coverage `unavailable`, `candidate_method`
  `tsuchiya-archive:latest-attempt-before-payoff`). A label comes only from an independent
  review decision.
- Full results, format and limitations: ML_CROSS_DATASET_VALIDATION.md.
