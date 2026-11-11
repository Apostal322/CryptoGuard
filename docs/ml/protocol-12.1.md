# Phase 12.1 protocol: temporal and graph signals for lookalike prioritization

**Version:** `protocol-12.1/1`. Frozen in git before any outcome-based number was computed.

**Known before freezing:**
- the eligibility counts (§3) and the exclusions;
- the asymmetric coverage of the old subset (§4);
- the Phase 11.7 coverage results (§8.1);
- the published literature;
- the packets' text summaries of the *paid* lookalikes only.

No ranking metric had been computed. Anything not listed as primary below is exploratory.

## 1. Question

Do wallet history, timing and cross-victim infrastructure order known poisoning candidates
by the risk that the victim copies them better than the address similarity that
CryptoGuard's detector ranks by? A reproducible "no" is an acceptable result.

## 2. Tasks and what each can show

| Task | Population | Shows | Cannot show |
|---|---|---|---|
| 1. Candidate generation | P1-cov: payoff-linked source positives | which planting shapes `candidates/2` can emit from source-selected archive history | recall on real wallets (the source and generator share heuristics) |
| 2/3. Prioritization by outcome (`lookalike-prioritization/1`) | P1-rank: victims with a confirmed payoff and k >= 2 planted lookalikes | which point-in-time signals rank the lookalike the victim later paid above its rivals | detection, precision, recall, FPR, theft prevention; behaviour on victims who never paid |
| Availability and cost | P2: the 13 recorded wallet windows | which features exist in a production-like recording, runtime | anything about labels |
| Mechanism | P3: the 4 incident fixtures | whether the paid lookalike is reachable by each signal | independent validation (they are development cases) |
| Correctness | P4: synthetic cases | cutoff, missingness, leakage, invariance | real-world performance |

Results are reported per population and never pooled.

## 3. Prediction unit and eligibility (P1-rank)

The unit is one episode, `(chain 1, victim, first confirmed payoff block T, cutoff c)`, with
primary cutoff `c = T - 1`.

**Victims:** archive payoff victims, minus:
- the wallets of both frozen cohorts (91 wallets);
- the 4 incident victims.

**Candidates:** the distinct non-victim parties of the source's poisoning-flagged rows
(zero-value, tiny or counterfeit) between the victim and another address, at a block <= c.
- Same-block rows are counted, never used.
- **Outcome:** the receiver of the victim's first confirmed payoff (source-confirmed).

**An episode is eligible when:**
- exactly one lookalike was paid in block T;
- that lookalike planted at or before c;
- k >= 2.

**Counts at freezing:**
- 1,068 eligible episodes;
- excluded:
  - 60 protected review wallets (no incident victim is a payoff victim);
  - 96 with no confirmed payoff row;
  - 1 with several lookalikes paid in the payoff block;
  - 277 with a single candidate.
- Across all victims, 4 poisoning rows fall in a payoff block.

**Protected cohorts:**
- not one of the 95 frozen events, or any other event of their wallets, enters any
  computation;
- review keys and manifests are never read.

Cohort A's 1,335 reserves are archive events of other victims. They are used here only in
aggregate, and no item is inspected.

## 4. Data and coverage

**Victim rows: `archive_subset.sqlite`.** It holds every archive row touching a payoff
victim: all of the source's poisoning, intended and payoff rows, but no ordinary activity.
"No earlier payment to address X" is therefore `not_observed`, not zero.

**Cross-victim rows: `research/graph_context.sqlite`.** One new offline archive pass
stores every row touching any of the 13,418 candidate lookalikes or 26,816 planting
transactions.

The old subset covered only the 1,551 *paid* lookalikes. Any cross-victim count read from
it would have been complete for the outcome and partial for its rivals: a leak by
selection. The new pass covers both alike.

**Not available anywhere locally:**
- transaction signers, so H3's shared-signer edges are untestable here;
- receipts;
- contract code.

## 5. Features at cutoff c

Each feature uses only rows with block <= c.

- **Missing values** are `not_observed` (`None`), never 0. `0` means observed and none.
- **R_c:** the receivers of the victim's own non-poisoning outgoing rows.
- **Reference of l:** the r in R_c that passes the production detector's `is_lookalike`
  (default `PoisoningConfig`) with the largest prefix+suffix, ties to the most recent use.

| Id | Family | Definition |
|---|---|---|
| B0 | production similarity | prefix+suffix of l vs its reference; 0 if R_c is non-empty but nothing passes; `None` if R_c is empty |
| B1 | source similarity | max prefix+suffix of l vs the source-claimed `intended` of its plantings; `None` if absent |
| B2 | transaction semantics | type of l's latest planting: tiny (real token) 3 > counterfeit 2 > zero-value 1 |
| B3 | recipient history (H1) | number of the victim's outgoing rows to l's reference; 0 if no reference; `None` if R_c is empty |
| T0 | temporal (H2) | recency: `-(c - block of l's latest planting)` |
| T1 | temporal | distinct planting transactions by l to the victim |
| T2 | temporal | exposure: `sum over l's planting txs of exp(-(c - block) / 7200)` (7,200 blocks is about a day) |
| T3 | temporal x history | 1 if l's latest planting is later than the victim's latest payment to l's reference, else 0; `None` without a reference |
| T4 | temporal | burst: l's plantings to the victim in `(c - 7200, c]` |
| G1 | graph (H3) | distinct other victims l planted to |
| G2 | graph | distinct other victims with a confirmed payoff to l (source-labelled) |
| G3 | graph | largest number of distinct victims in one of l's planting transactions to this victim |
| NC | negative control | distinct study victims planted in the same token contract as l's latest planting |

**Abstention.** A method abstains on an episode when any candidate's value is `None`. It
then ties all candidates, so it scores exactly at random. Abstentions are reported per
method. Missing evidence is never ranked as risk or as safety.

## 6. Methods

- **Single-feature rankings:** B0–B3, T0–T4 and G1–G3, higher is riskier. Ties are kept.
- **Random:** all candidates tied.
- **H_fixed (B6, H5):** the mean of within-episode normalized average ranks (0 lowest, 1
  highest) of B1, B3, T2 and G1, one per hypothesis family. Components that abstain are
  left out. If every component abstains, all candidates tie.
- **Learned (exploratory only):** a conditional logit fitted as an L2 logistic regression
  (C = 1, no intercept) on paid-minus-rival feature differences.
  - Data: development episodes only.
  - Features: B0–B3, T0–T4, G1–G3; `None` becomes 0 plus an indicator.
  - Standardized on the development set; seed 0.
  - Evaluated once on the test split.

No method has a tuned parameter. The constants 7,200 and the B2 order are fixed here.

## 7. Metrics, split and inference

**Metrics:**
- Top-1 (primary): `1/m` if the paid lookalike is among the m candidates tied for the top
  score, else 0.
- MRR (secondary): the expected reciprocal rank under random tie-breaking.
- Random reference: `1/k` and `H_k/k`.

**Groups:** a union-find over episodes sharing a candidate lookalike or a planting
transaction. If the largest group exceeds 20% of episodes, episodes are linked only by
shared candidate lookalikes. Both group counts are reported.

**Split:**
- Groups are ordered by their earliest payoff block. The latest go to *test* until it holds
  at least 40% of episodes; the rest are *development*.
- Confirmatory tests use test only.
- Development is used only to fit the learned model.

**Primary comparisons:** paired top-1 differences on the test split, against B0, Holm at
0.05 over four tests.

| Test | Hypothesis | Comparison |
|---|---|---|
| P-H1 | recipient history | B3 − B0 |
| P-H2 | temporal | T0 − B0 |
| P-H3 | graph | G1 − B0 |
| P-H5 | hybrid | H_fixed − B0 |

**Inference:**
- p-values: a group-level sign-flip permutation (10,000 draws, seed 20261102).
- Intervals: a 95% group bootstrap (2,000 draws, same seed).

**Decision.** A signal is *supported* when all three hold:
- Holm p < 0.05;
- the interval excludes 0;
- the difference is at least 0.05.

It is *null* when the interval lies within ±0.05, and *inconclusive* otherwise.

## 8. Exploratory analyses (no confirmatory claims)

1. **Coverage (Task 1):** `candidates/2` in strict and optimistic signer modes. Lookbacks
   of 7 days (as in Phase 11.7), 30 days and all archive history. Emitted share per subtype,
   and the rule that blocked each miss.
2. **Every method against random and B0**, on development, test and all episodes; MRR.
3. **Strata:** year (2022 / 2023 / 2024+), the paid lookalike's subtype, and k (2, 3–5, 6+).
4. **Robustness:**
   - cutoff lag `c = T - 1, T - 300, T - 7200`;
   - victim-history lookback limited to 7 days, 30 days or all;
   - 50% of the victim's outgoing rows dropped (seed 0);
   - graph rows limited to the last 30 days, or 50% dropped (seed 0).
   - Reported: top-1, the share of episodes whose top-1 set changes, abstention.
5. **Leakage checks:** rows after c are added, and every feature must be unchanged.
   - Within-episode shuffle of G1 across candidates (expected: random).
   - Global shuffle of graph rows between lookalikes (expected: no signal if G1 carries
     lookalike-specific information).
6. **Negative control NC.** Public tokens (USDT, USDC, DAI) are expected to make it
   uninformative.
7. **Ablations of H_fixed:** each component removed in turn, and the missingness
   indicators removed from the learned model.
8. **Source-shift:** feature distributions by year and subtype, and paid versus rival.
9. **Errors:** H_fixed misses on test, by category. Aggregate only.
10. **P2 availability and runtime; P3 mechanism.**

## 9. Budgets

- **Archive pass:** one, offline, about 25 minutes, under 512 MiB.
- **Each experiment:** under 2 minutes and under 1 GB RAM, CPU only.
- **No new RPC requests and no downloads.**
- **Outputs:** aggregate JSON under `data/ml/research/` (git-ignored, derived from
  CC BY-NC-ND data). The report holds aggregates only.

## 10. Known limitations, fixed in advance

- **The population is conditioned on a payoff.** It says nothing about victims who never
  paid, or about attempts in general.
- **Source-defined candidates and outcome.** The source flags the candidates and confirms
  the payoff with its own heuristics, which may use information after c. The candidate
  set may therefore depend on the outcome. Features never read flags beyond selecting
  plantings, except G2, which reads the source's payoff flag on earlier rows.
- **Archive history is source-selected.** B0, B3 and T3 see only the payments the source
  kept.
- **Multiplicity.** Many methods and strata are reported. Only the four primary tests are
  confirmatory.
