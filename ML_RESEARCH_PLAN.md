# ML research plan: wallet-centric poisoning detection (Phase 11.2)

Status: infrastructure done, gates B and D fail (no verified labels), and no model is trained
for this task. Data model and labels: [ML_POISONING_DATASET.md](ML_POISONING_DATASET.md).
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

## 2. Task definition

See ML_POISONING_DATASET.md §2:
- **Unit:** `(chain_id, victim, candidate_event_id, observation_cutoff)`.
- **Target:** poisoning-attempt status.
- **Cutoff:** after the planting transaction, before later transactions in the same block.
- **Losses** are a separate outcome, never a feature.
- **Output:** an experimental ranking with coverage, not a theft probability, never a
  finding.

## 3. Candidate generation (`ml/candidates.py`, `candidates/1`)

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

## 5. External data (checked on 2026-11-02; nothing downloaded)

| Source | Verified facts | Fit | Blocker |
|---|---|---|---|
| Tsuchiya et al., "Blockchain Address Poisoning", USENIX Security 2025. KiltHub DOI 10.1184/R1/29212703.v1 | Files: `payoff_transfers_ethereum.csv` (482 KB), `payoff_transfers_bsc.csv` (1.33 MB), `address_poisoning_ethereum.sql.gz` (2.32 GB). Licence CC BY-NC-ND 4.0 | Payoffs give independent confirmed-loss transfers (stablecoin, Ethereum, 2022-07 to 2024-06) | Download needs your approval; NC-ND allows local research use only, with no redistributed derivatives; columns not yet inspected |
| Poison-Hunter (Guan and Li, CCS 2024), `DS2L/Poison-Hunter` | 5 files in the repository, no licence; full data "available on request", with no contact address published | Weak attempt labels | A request is needed; a draft request exists, not sent |
| RMIT arXiv 2609.23405 | Claims 4,209 victim transfers; its artifact link showed no files | — | Unverified |
| Forta labelled datasets | MIT; Etherscan phish-hack/exploit/heist labels | Contamination checks only | No poisoning category |
| Etherscan labels | Terms require written permission for ML or dataset creation | — | Affects Forta and Poison-Hunter ground truth |

## 6. Next experiment (highest value, 0 RPC requests)

**Cross-check the Poison-Hunter rows against Tsuchiya et al.'s independent payoff list.**

- **Needs:** your approval to download `payoff_transfers_ethereum.csv` (482 KB, CC BY-NC-ND
  4.0, kept local under `data/external/`, never committed). It is a file download, so your
  standing rule requires an explicit yes.
- **Method.** Pin its hash in `ml/sources.py`, then parse it with a typed schema after
  inspecting the columns. Join it on victim and lookalike with the 143 Poison-Hunter
  victim-events and the 4 replay incidents.
- **What it gives.**
  1. Independent outcome evidence for the 97 rows the pilot could not resolve, at no RPC
     cost.
  2. Agreement between two independent pipelines on attempts, giving a first estimate of
     label noise.
  3. A list of confirmed-loss victims whose preceding attempts could become
     `verified_attempt` positives after review.
- **Success criterion, stated now.** Report the overlap counts and the disagreements as
  they are. Do not change the Poison-Hunter labels on the basis of the overlap alone;
  changes go through the review workflow.
- **Still missing afterwards:** verified negatives (gate B). They need a reviewed sample of
  legitimate lookalike-shaped interactions, which no public source provides. That is the
  real blocker for supervised learning on this task.
