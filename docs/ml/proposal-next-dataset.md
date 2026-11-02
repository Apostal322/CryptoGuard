# Proposal: wallet-history dataset for poisoning-payment detection

**Status: option A (pilot) approved and run on 2026-11-01; results in §11. Options B and C
are not approved.** The Phase 11 authorization (12,000 requests) is exhausted (11,953 used);
the pilot used 2,636 of its separate 3,000-request cap. Background:
ML_GENERALIZATION_AUDIT.md §16–17.

**Phase 11.2 audit (2026-11-02):** the pilot was reconstructed from its raw outputs and two
claims below were corrected: the 0.069 bound (§11.2) is conditional, not a population bound,
and the CSV header is aligned, not shifted. See ML_PILOT_AUDIT.md and ML_RESEARCH_PLAN.md.

**Phase 11.3 (2026-11-02):** Tsuchiya et al.'s attempt archive was reconciled offline (0 RPC
requests; ML_CROSS_DATASET_VALIDATION.md). It confirms that the pilot's sample lies mostly
inside a well-documented attempt population, and it yields 1,469 payoff-linked attempts for
independent review. It does not change §11, and it supplies no verified negatives. Any
collection for negatives still needs a new, separately approved RPC cap.

**Pilot verdict: option B as costed here is not viable.** Cost per wallet is about twice the
§7 estimate, the free endpoint's throughput is about a third of the Phase 11 figure, and no
positive was confirmed. See §11 before deciding on B, C or stopping.

## 1. Decision requested

| Option | Provider | Requests (estimate) | Wall time (estimate) | What it buys |
|---|---|---|---|---|
| **A. Pilot only** | free `eth.drpc.org` | cap **3,000** | ~5 min | Measured cost per wallet and positive yield; go/no-go for B or C |
| **B. Full, free endpoint** | free `eth.drpc.org` | cap **240,000** | ~5 h | The full dataset below |
| **C. Full, keyed endpoint** | your own provider key (e.g. a free tier with ≥2,000-block log ranges) | cap **30,000** | ~40 min | The same dataset, ~8× fewer requests |

Recommendation: **approve A now**; decide between B and C after its report. C needs you to
create a provider account and put the key in `.env` yourself: I cannot create accounts or
handle keys.

## 2. Prediction task

- **Unit:** one outgoing payment (ERC-20 transfer signed by the wallet, or an ETH send) from a
  wallet.
- **Question:** does this payment go to an address-poisoning lookalike?
- **Observation boundary:** *pre-signing* — only events in blocks before the payment's block
  (`ml/history.py`, `boundary="pre_signing"`). No receipt of the payment itself is used, so
  unlike Phase 11 a result would apply *before* the user signs.
- **Features:** the wallet-history features of `ml/history.py` (prior payments to the
  recipient, lookalike-of-known-counterparty, unsolicited events with the recipient,
  plantings observed, recent new-recipient share), plus nothing from the payment's own
  outcome.
- **Baselines (fixed in advance):** (1) CryptoGuard's existing rule — recipient imitates a
  counterparty the wallet chose and was never paid; (2) "first payment to this recipient";
  (3) majority class. The question the experiment answers: **does a learned model beat
  rule (1) on ordinary wallets?** If not, the rule stays and no model ships.

## 3. Labels and sources

| Role | Source | License | Independence from CryptoGuard |
|---|---|---|---|
| Positives (seed) | The 4 replay incidents (already recorded, 0 requests) | public reports, cited in manifests | independent (public incident reports) |
| Positive candidates | Poison-Hunter `phishing_transfers_sample.csv`: 150 planting transfers with victim, attacker address and block | none published: local use, never redistributed | labels from Etherscan and Forta |
| Positive confirmation | A candidate counts only if the **victim later paid the labelled attacker address** (on-chain fact) | — | uses the label list, **not** CryptoGuard's lookalike test |
| Negatives | Payments by randomly sampled ordinary wallets (§4) | public chain data | — |
| Contamination check | Forta and Poison-Hunter phishing lists (13,000+ addresses) | MIT / none | independent label lists |

Two rules keep the evaluation honest:

- **Positives are never defined by CryptoGuard's own lookalike test.** Otherwise rule (1)
  would score perfectly by construction.
- **Negatives are "no evidence of phishing", not "proven benign".** No synthetic labels are
  assigned. Any negative payment whose recipient appears on an independent phishing list is
  removed and counted; the report states the residual contamination risk (phishing is far
  rarer than 1% of random payments, so it is small but not zero).

## 4. Sampling design (frozen before collection)

**Negatives — ordinary wallets.**
- Period: blocks 18,000,000 to 19,300,000 (about Aug 2023 to Feb 2024), inside the
  Poison-Hunter labelling period (Nov 2022 to Feb 2024) so the contamination check is
  meaningful.
- Draw: seeded random blocks; from each, a random transaction's sender.
- Eligibility, fixed now: externally owned account (no code), 20 to 2,000 lifetime
  transactions (excludes bots, exchanges and empty wallets), at least one outgoing payment in
  its 7-day window.
- Target: **120 wallets** to reach **≥300 payments from ≥100 wallets** (the minimum for a 1%
  false-positive bound, audit §8). The draw continues until eligibility is met, within the cap.

**Positives.**
- 4 replay incidents (already recorded).
- From the 150 Poison-Hunter sample rows: each victim's outgoing payments in the 7 days after
  the planting; confirmed if any payment went to the labelled attacker address.
- **Expected yield is low** (most planting attempts fail): perhaps 0 to 15 confirmed
  positives. The pilot measures it. Recall will therefore be estimated on tens of incidents,
  with wide intervals; the primary endpoint is the false-positive rate (§6), which is what
  blocked deployment.

**Holdout, pre-registered.** Before any collection: the seed, the eligibility rules, the
sampled wallet list (written locally) and its SHA-256 (committed) are frozen. 30% of wallets
(both classes, chosen by wallet, latest-in-time first) form the holdout. It is not opened until
the model, features, threshold and baselines are fixed, and it is evaluated **once**. The
promotion record then gets the `holdout` entry that `shadow_approved` requires.

## 5. Stages, budgets and stop rules

| Stage | Work | Request cap | Stop rule |
|---|---|---|---|
| 0 (offline) | Validate the Poison-Hunter sample (aligned header, 2 unnamed trailing fields) (verify the field mapping on rows with known structure; reject if ambiguous); freeze the sampling plan and holdout hash | 0 | If the sample cannot be repaired unambiguously, positives fall back to the 4 incidents plus manually curated public reports |
| 1 = Option A (pilot) | As run (§11): payment check for all 149 candidate rows; 1-day recordings of random wallets. The original design (10 + 10 wallets, 7-day windows) needed ~25,000 requests and was replaced before collection | 3,000 | Report: requests per wallet, eligibility rate, positive yield. Stop for your decision |
| 2 = B or C | Remaining negatives and candidates | 240,000 (B) or 30,000 (C) | Stop at the cap; report what was reached |

All stages use the Phase 11.1 collector: every HTTP attempt, retries included, is reserved in
a locked ledger before it is sent, so the cap is hard and survives crashes (§14 of the audit).
A separate ledger is used per approved budget.

## 6. Evaluation plan (fixed in advance)

- **Primary endpoint:** false-positive rate on holdout negative payments at the operating
  point that flags the training positives, with Wilson and wallet-cluster bootstrap intervals.
- **Secondary:** recall on holdout positives (with the caveat of small counts); precision
  under assumed prevalences of 0.01% to 1% (arithmetic).
- **Comparison:** model versus rule (1) on the same holdout payments, paired by payment.
- **Success criteria, stated now:** the model is considered for `shadow_approved` only if its
  holdout false-positive upper bound (95%) is below rule (1)'s point estimate **and** it
  catches every positive that rule (1) catches. Otherwise the result is reported as negative
  and the rule remains.
- Training stays under 2 minutes per run on CPU (a few hundred rows); one job at a time.

## 7. Cost model and its evidence

- The 13 recorded replay fixtures cost **443 to 1,361 requests** for a 21,600-block (~3-day)
  window on the free endpoint, retries included. Most of it is `eth_getLogs` in ~100-block
  chunks for both transfer directions.
- A 7-day window is 50,400 blocks: about **1,000 to 1,300 requests per wallet** on the free
  endpoint, or **~110** where the provider allows ≥2,000-block log ranges.
- Positive candidates need two windows (7 days before for features, 7 days after the planting
  to confirm a payment): ~2× per wallet.
- Totals: B ≈ 120 × 1,300 + 150 × 2 × 1,300 × ≈ 0.6 (early stop when a victim has no payments)
  ≈ 390,000 at worst; capped at **240,000** by fetching the "after" window first and the
  "before" window only for confirmed positives. C ≈ one eighth of that, capped at **30,000**.
- Throughput measured in Phase 11: ~13.7 requests/s on the free endpoint, giving the wall-time
  estimates in §1.

These are estimates from recorded fixtures, not measurements of this design: the pilot
replaces them with measured numbers before any larger budget is used.

## 8. Storage, compute and privacy

- Raw records stay in the git-ignored `data/ml/` (estimated 50 to 300 MB for option B); only
  manifests, hashes and code are committed. Poison-Hunter-derived rows are never
  redistributed.
- Compute: CPU only, peak memory expected under 500 MB.
- The sampled wallets are public addresses, but a list of "wallets studied" is still
  personal-looking data: it stays local, and reports show aggregates only.

## 9. Risks

- **Too few positives** (likely): recall stays imprecise; the decision then rests on the
  false-positive rate alone, which is the deployment blocker anyway.
- **Repair of the Poison-Hunter sample fails:** fall back as in stage 0.
- **Free-endpoint limits change:** the collector stops at errors and caps; nothing is lost.
- **Selection of "ordinary" wallets:** the eligibility rules shape the population; they are
  fixed before collection and reported, not tuned.

## 10. What I need from you

1. Approve **option A (3,000 requests on `eth.drpc.org`)**, or not.
2. After the pilot report: choose **B**, **C** (you create the provider key), or stop.
3. Confirm the success criteria in §6 before any model is trained.

## 11. Pilot results (option A, 2026-11-01)

Endpoint `eth.drpc.org` (free plan). **2,636 requests used of the 3,000 cap**, retries
included, all reserved in a separate locked ledger. 364 were left unused. The plan was frozen
before the run (local `data/ml/pilot/plan.json`, SHA-256 `82ae27e0…`). Raw outputs stay in
the git-ignored `data/ml/pilot/`, and only aggregates appear here.

### 11.1 Changes from §5 made before collection

- **The original pilot did not fit the cap.** 10 victims plus 10 wallets with 7-day windows
  needed about 25,000 requests. It was replaced by the design below, which keeps the
  pilot's two measurements: cost per wallet and positive yield.
- **drpc's free plan rejects `eth_getLogs` ranges of 250 blocks or more.** 100 blocks
  works. The error message claims a 10,000-block limit, which is wrong. The limit was found
  with 8 probe requests. At 100 blocks, scanning one victim's 7-day window costs about 504
  requests, so the payment check uses the victim's own transactions instead:
  - compare the nonce at the start and end of the window (2 requests);
  - for victims who signed 1–8 transactions, locate each one by nonce bisection;
  - decode each transaction (ETH send, or `transfer(attacker, amount > 0)`).
- **"Zero" and "fake" plantings forge `Transfer(victim → attacker)` logs.** A log match
  would therefore confirm every such victim. Only transactions the victim signed are
  counted.
- **Stage 0 validated the Poison-Hunter sample.** Every row has 17 fields; the 15-name header
  is aligned with the first 15, and 2 trailing fields are unnamed (ML_POISONING_DATASET.md §5). Field types identify the mapping: [0] lookalike, [1] victim, [2] imitated address,
  [13] block. In 100 rows (types "zero" and "fake") the transaction sender is a batch
  operator, as expected for those attacks. 149 of 150 rows validate: 123 victims, blocks
  15.86M–17.97M. One row was rejected (no address similarity).
- 70 requests went to smoke tests and the range probes.

### 11.2 Positive yield

| | Rows | Victims |
|---|---|---|
| Candidate rows | 149 | 123 |
| Victim signed nothing in the 7 days after planting | 35 | — |
| Signed 1–8 transactions, all located and decoded | 17 | — |
| Signed 1–8, not reached before the phase cap | 51 | — |
| Signed 9–100 (not resolved in the pilot) | 33 | — |
| Signed more than 100 (bot- or exchange-like) | 13 | — |
| **Confirmed payment to the labelled attacker** | **0** | **0** |

- **Confirmed: 0 of 52 rows checked with complete declared coverage.**
  - *Corrected 2026-11-02 (ML_PILOT_AUDIT.md §3):* an earlier version gave a Wilson 95% upper
    bound of 0.069 "on the share of candidate rows that end in a payment". That bound holds
    only if the 52 checked rows were representative. They are not: they are the least active
    victims, and they include duplicate victim-events. It says nothing about the other 97
    rows or about Poison-Hunter victims in general.
- **Not covered:**
  - `transferFrom`, permit and router payments;
  - payments made after 7 days;
  - the 97 unresolved rows, which are the more active victims.
- 90 of 123 "victims" were active. 13 rows belong to addresses that signed more than 100
  transactions in a week, so the sample's victim list includes automated accounts.
- **Consequence:** the pilot cannot estimate how many of the 149 rows ended in a payment.
  Outcomes for the more active victims are unknown. The positive class cannot be built from
  this sample by on-chain checks at this cost.

### 11.3 Cost per wallet and eligibility (random wallets, blocks 18.0M–19.3M)

**Eligibility of 25 random draws** (a random transaction's sender):
- 14 ineligible: 5 had a nonce below 20; 9 had a nonce above 2,000, 7 of them in the
  hundreds of thousands to millions (exchange or bot scale). None had code.
- 11 eligible (44%). Of those, 6 signed more than 12 transactions in the drawn day and
  were not recorded in the pilot.

**Recorded: 3 wallet-days** (`replay.record_window`, 100-block chunks). They cost **216,
224 and 351 requests**: 3, 6 and 12 transactions signed.
- A 4th recording hit a rate limit after 170 requests.
- The 3 recordings completed, but a field-name bug in the pilot script dropped their
  contents afterwards. Their request counts are exact; their payment counts were not kept.

**Extrapolation (estimate, not measured):**
- Log scanning grows linearly with the window, and locating costs a median of about 26
  requests per signed transaction (17 victims: median 57, maximum 179 per row).
- A 7-day window is therefore about **1,500–2,500 requests per ordinary wallet**. That is
  about twice §7's 1,000–1,300.
- The figure is biased low, because the busier half of eligible wallets was not recorded.

**Throughput:** 2,566 requests in 646 s, **about 4 requests/s**, with one rate-limit
failure. Phase 11 measured 13.7.

### 11.4 What this means for the decision

- **Option B (free endpoint, 240,000 cap).** 120 negative wallets alone would need
  180,000–300,000 requests, about 12–21 hours at 4 requests/s, and it adds few or no
  positives. Not recommended.
- **Option C (keyed provider).**
  - Ranges of 2,000 blocks or more cut the log part about 20×.
  - Nonce bisection is unchanged.
  - Per wallet-week: about 150–400 requests. 120 wallets: 20,000–50,000 requests.
  - This still solves only the negatives.
- **Positives need another source:** victims with confirmed losses from public incident
  reports, or a labelled loss dataset that records the actual payment. Without one, the
  study can measure false positives on ordinary wallets but not recall.
- **Alternative: stop.** The existing rule stays, and the model stays research-only.
