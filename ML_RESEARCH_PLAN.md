# ML research plan: wallet-centric poisoning detection (Phase 11.2)

Status: infrastructure done, gates B and D fail (no verified labels), and no model is trained
for this task. The Tsuchiya et al. payoff cross-check (§6) and the attempt-archive
reconciliation (§7, Phase 11.3) are done. The next experiment is in
[ML_CROSS_DATASET_VALIDATION.md](ML_CROSS_DATASET_VALIDATION.md) §25; its review sample of
60 is frozen (§26). Phase 11.4 verified it, audited its design and built the independent
annotation workflow; it now waits for two human reviewers
([ML_ANNOTATION_AUDIT.md](ML_ANNOTATION_AUDIT.md),
[ML_BENCHMARK_READINESS.md](ML_BENCHMARK_READINESS.md)). Phase 11.5 added a screened
pool of 8,877 unlabeled hard-negative candidates and a second frozen cohort of 35
([ML_HARD_NEGATIVE_STUDY.md](ML_HARD_NEGATIVE_STUDY.md)). Phase 11.6 made both cohorts
review-ready (evidence packets, protocol amendment 2, training cohort, handoff): status
REVIEW_READY: HUMAN ANNOTATION PENDING
([ML_HUMAN_VALIDATION_READINESS.md](ML_HUMAN_VALIDATION_READINESS.md)); Phase 11.7
completed the offline evidence and hardened the workflow
([ML_EVIDENCE_COMPLETION.md](ML_EVIDENCE_COMPLETION.md)). Data model and labels:
[ML_POISONING_DATASET.md](ML_POISONING_DATASET.md).
Pilot: [ML_PILOT_AUDIT.md](ML_PILOT_AUDIT.md). Generated numbers:
[ML_POISONING_TABLES.md](ML_POISONING_TABLES.md).

## 1. Issue register (Phase 11.2 audit)

| ID | Pri | Issue | Status |
|---|---|---|---|
| 1 | P0 | **Pilot data loss.** The pilot post-processing read `fixture.transactions` (the field is `wallet_transactions`). A broad `except` turned three completed recordings into "errors", and their contents were lost | Fixed: typed versioned records, schema errors raise, legacy migration marks lost values `None` (ML_PILOT_AUDIT.md §4) |
| 2 | P0 | **Invalid conclusion.** "At most 7% of candidate rows end in a payment" generalized a bound computed on a non-random subset (the least active victims) | Corrected in the proposal and the audit: the bound is conditional only |
| 3 | P1 | **Ledger lock race.** The stale-lock break (after 60 s) could let two processes hold the lock after a holder crashed | Fixed: OS file lock, fsync; process-level tests |
| 4 | P1 | **PSI blind spot.** `bisect_right` binning put a mostly-constant feature into one bin, so its shifts were invisible (PSI 0 for a 0→40 shift) | Fixed for new references (`closed="left"`). Phase 11 cards keep the old semantics so they show no false drift; the limitation is documented |
| 5 | P1 | **PSI on empty or missing input.** An empty batch gave a large number, and NaN fell silently into the first bin | Fixed: `None` for empty or all-missing; missing values excluded and reported (`missing_share`) |
| 6 | P1 | **Untyped pilot outside the package.** The pilot script was not under tests, mypy or review | Fixed: the pilot logic now lives in `ml/pilot.py`, tested. The scratch script stays out of the repository |
| 7 | P1 | **Payment check too weak.** The pilot accepted victim-signed `transfer()` calldata without checking the token or the receipt log | Fixed: `ml/payments.py` requires a reviewed token, success and a matching log; otherwise `unresolved` |
| 8 | P1 | **Task confusion risk.** A future poisoning model could be loaded by the transaction scorer | Fixed: cards carry `task`, and the registry refuses a task other than `ptxphish-transaction-phishing/1` |
| 9 | P2 | **Imprecise description of the CSV.** The Poison-Hunter header was described as "shifted"; it is aligned, with 2 unnamed trailing fields | Corrected in docs and the parser docstring |
| 10 | P2 | **Rows counted as events.** The pilot treated duplicate victim-events as separate observations | Reported (149 rows, 143 events); the event model deduplicates |
| 11 | P2 | **Phase 11 monitoring on sparse features** keeps the old binning until the model is retrained | Open (the model is research-only, so no live impact) |
| 12 | P2 | **A victim's loss is not the event's outcome.** In the Tsuchiya cross-check, a Poison-Hunter victim paid a *competing* lookalike of the same address (line 74) | Documented: `OutcomeRecord` is per event, and a loss to another lookalike is never credited to this event (ML_PILOT_AUDIT.md §7) |

## 2. Task definition

See ML_POISONING_DATASET.md §2:
- **Unit:** `(chain_id, victim, candidate_event_id, observation_cutoff)`.
- **Target:** poisoning-attempt status.
- **Cutoff:** after the planting transaction, before later transactions in the same block.
- **Losses** are a separate outcome, never a feature.
- **Output:** an experimental ranking with coverage, not a theft probability, never a
  finding.

## 3. Candidate generation (`ml/candidates.py`, `candidates/1`; now `candidates/2`)

**Rules.** The rules are structural and independent of the production detector and of any
model:
- `zero_value_in`;
- `spoofed_out` (a transfer out of the wallet that the wallet did not sign);
- `lookalike_in` (at least 6 matching affix characters, at least 3 trailing, against a
  counterparty the wallet chose before the event);
- `untrusted_token_in`;
- `dust_in` (a stablecoin transfer of at most 0.01).

**Results on recorded data (0 RPC requests).**
- **Incidents:** the harmful lookalike is a candidate before the theft in **4 of 4**
  incidents.

  | Incident | Candidate lead | Detector lead | Candidates in the 3-day window |
  |---|---|---|---|
  | eth-140 | 21,523 | 42 | 4 |
  | eth-4556 | 13,063 | 13,057 | 38 |
  | usdt-50m | 113 | 113 | 7 |
  | wbtc-1155 | 367 | 367 | 169 |

  (Leads are in blocks.)
- **Background:** 9 recorded background windows (27 wallet-days) produced 8 candidates,
  about 0.30 per wallet-day. They are unlabelled, so they are not false positives.
- **Resources:** generation takes milliseconds per window (at most 128 ms, 403 KiB peak),
  and the whole report takes under a minute.

**Limits on what this shows.**
- The incidents were used while developing the detector, so they are not untouched.
- The generator is loose by design: 169 candidates for one heavily targeted wallet. A
  longer lead time in eth-140 is not a better detector; it reflects a structural rule that
  fires on every spoofed transfer.
- Candidate recall on Poison-Hunter rows cannot be measured without the victims' histories.

## 4. Future collection architecture

`cryptoguard ml plan-collection` estimates a job and never collects. Its defaults are taken
from the pilot and are conservative: 90th-percentile 30 signed transactions per wallet-week
at 26 requests each, 10% retries, 4 requests/s.

| Scenario (120 wallets × 7 days) | Requests per wallet | Total | Hours |
|---|---|---|---|
| Free endpoint, 100-block logs | 1,978 | 237,360 | 16.5 |
| Provider with 2,000-block logs | 927 | 111,240 | 7.7 |

**What dominates the cost.**
- With larger log ranges, the cost is dominated by nonce bisection (about 26 requests per
  signed transaction), not by log scans.
- **Cheaper designs:**
  - **Event-first discovery.** Start from attempts already listed by a dataset (for
    example Tsuchiya et al.), so only the planting transaction and the following window
    are needed.
  - **Receipt reuse.** One planting transaction covers all victims of its batch.
  - **An indexed source.** An address-indexed source, which a paid service or a self-run
    archive indexer would provide, replaces bisection.
- None of this has been run, and none is authorized.

## 5. External data (checked on 2026-11-02)

| Source | Verified facts | Fit | Blocker |
|---|---|---|---|
| Tsuchiya et al., "Blockchain Address Poisoning", USENIX Security 2025. KiltHub DOI 10.1184/R1/29212703.v1 | Files: `payoff_transfers_ethereum.csv` (482 KB, **downloaded with approval, parsed**: 1,738 token payoffs, no ETH), `payoff_transfers_bsc.csv` (1.33 MB), `address_poisoning_ethereum.sql.gz` (2.32 GB, **downloaded with approval, streamed**: 34,905,969 transfers, publisher counts reproduced), README and notebook (downloaded). Licence CC BY-NC-ND 4.0 | Payoffs: independent confirmed losses. The archive: the source-labelled attempts behind them | NC-ND allows local research use only, with no redistributed derivatives. The BSC file is not downloaded |
| Poison-Hunter (Guan and Li, CCS 2024), `DS2L/Poison-Hunter` | 5 files in the repository, no licence; full data "available on request", with no contact address published | Weak attempt labels | A request is needed; a draft request exists, not sent |
| RMIT arXiv 2609.23405 | Claims 4,209 victim transfers; its artifact link showed no files | — | Unverified |
| Forta labelled datasets | MIT; Etherscan phish-hack/exploit/heist labels | Contamination checks only | No poisoning category |
| Etherscan labels | Terms require written permission for ML or dataset creation | — | Affects Forta and Poison-Hunter ground truth |

## 6. Done: cross-check with Tsuchiya et al.'s payoff list (0 RPC requests)

Details: ML_PILOT_AUDIT.md §7. Code: `ml/tsuchiya.py`, run by `cryptoguard ml poisoning-report`
whenever the file is present.

- **Deviation from the plan.** The hash is pinned in `ml/tsuchiya.py`, not `ml/sources.py`.
  `fetch-sources` downloads every source in that registry unasked, and this file needs a
  download decision each time.
- **Results against the three expected outcomes.**
  1. **Outcome evidence for the 97 unknown rows.**
     - The file has no payoff to the row's own lookalike for any of them. 76 of the 97 lie
       inside its definition and period.
     - One victim (line 74) paid a competing lookalike of the same address within 1.6 days.
     - None of the 52 complete-coverage rows is contradicted.
     - These absences rest on the file's coverage; they are not proof of no payment.
  2. **Label agreement on attempts: not measurable from the payoff file.** Attempts are in
     the 2.3 GB dump. One Poison-Hunter lookalike (line 87) appears as a payoff recipient
     from another victim, which independently corroborates that row.
  3. **Confirmed losses: 1,738 payoffs** (1,502 payers, 1,551 lookalikes). The planting
     transactions that preceded them are not in the CSV, so none is an event yet.
- **Labels unchanged, as stated in advance.** Line 87 is a candidate for the review
  workflow, not an automatic upgrade.
- **Consistency checks.**
  - The source's declared affix counts equal `affix_match` on all 1,738 rows.
  - Both CryptoGuard predicates accept all 1,738 lookalikes. The study's 3+4 selection
    implies this, so it is not recall.
  - ~~41 amounts are float-encoded beyond exact precision.~~ Corrected in Phase 11.3
    (issue 13): the source column is float4, so 1,644 of 1,738 amounts are approximations.
    Only `value_usd` is used.
- **Incidents.**
  - Three of the four are after the file's last block.
  - wbtc-1155 is inside the period but was paid in WBTC, and the file has no WBTC payoffs.
  - None appears in the file.

## 7. Done (Phase 11.3): payoffs turned into reviewable attempt events

Approved and run on 2026-11-02 as planned below; results in
[ML_CROSS_DATASET_VALIDATION.md](ML_CROSS_DATASET_VALIDATION.md):
- 1,635 of 1,738 payoffs link to an earlier attempt by the same lookalike;
- 89 of 105 in-definition Poison-Hunter rows match an archive attempt exactly;
- 1,469 payoff-linked attempt events are exported for review.

Issues 13–20 are in that document's §24. The plan as approved:

- **Needs:**
  - your approval to download `address_poisoning_ethereum.sql.gz` (2.32 GB, CC BY-NC-ND
    4.0, kept local and never committed);
  - about 2.4 GB of free disk.
- **Method.**
  - Stream-parse the dump (gzip, line by line, constant memory: no import into a database
    and no full decompression).
  - For each payoff, take the latest attempt by that lookalike against that victim before
    the payoff block: the planting transaction, its subtype and its block.
  - Build `PoisoningEvent`s for them, and for the Poison-Hunter rows that the dump also
    lists.
- **What it gives.**
  1. Attempt-level agreement between Poison-Hunter and Tsuchiya et al.: the first measured
     label-noise estimate.
  2. A pool of attempt events with an independently confirmed loss, ready for the review
     workflow (`verified_attempt` only after review).
  3. Whether Tsuchiya et al.'s pipeline detected each Poison-Hunter lookalike, which turns
     the absences above into evidence that rests on known coverage.
- **The RPC alternative is far costlier.** Finding each planting transaction on the free
  endpoint means scanning 7 days of logs per payoff: about 1,000 requests each at 100
  blocks per query, so about 100,000 requests per 100 payoffs.
- **Still missing afterwards:** verified negatives (gate B). They need a reviewed sample of
  legitimate lookalike-shaped interactions, which no public source provides. That remains
  the real blocker for supervised learning on this task.

## 8. Done (Phase 12.1): temporal and graph signals for lookalike prioritization

The study was pre-registered in `docs/ml/protocol-12.1.md` (`999794a`) and run offline,
with 0 RPC requests. Results are in
[ML_TEMPORAL_GRAPH_RESEARCH.md](ML_TEMPORAL_GRAPH_RESEARCH.md).

The task was retrospective: rank the lookalikes that had planted to a victim who later
paid one of them. The test split had 428 episodes. Top-1 against the production
similarity score (B0, 0.300):

| Signal | Top-1 | Decision |
|---|---|---|
| T0 recency | 0.618 | supported |
| H_fixed hybrid | 0.462 | supported, through its temporal part only |
| B3 recipient history | 0.247 | reversed |
| G1 graph reuse | 0.206 | reversed; equal to random |

- **Not a detection result:** no precision, FPR or recall was measured.
- **Next:** pre-register recency-first warning ordering on a population not used here.

