# Temporal and graph signals for address-poisoning prioritization (Phase 12.1)

This study is retrospective. Its population is conditioned on a payoff, and its candidates
and outcomes come from the source's flags. It measures which signals put the paid
lookalike first among lookalikes the source had already flagged. It is **not** a detection
benchmark. It estimates no precision, false-positive rate, recall, real-world AP or
theft-prevention effect, and every number below is an aggregate.

| Item | Value |
|---|---|
| Protocol (frozen) | [`docs/ml/protocol-12.1.md`](docs/ml/protocol-12.1.md), commit `999794a` |
| Deviations and fixes | [`docs/ml/protocol-12.1-deviations.md`](docs/ml/protocol-12.1-deviations.md); F1, F2, D1 and D2 were committed before any outcome (`12f09a1`) |
| Code | `ml/lookalike_ranking.py`, `ml/lookalike_study.py`; command `cryptoguard ml lookalike-study` |
| Output (git-ignored) | `data/ml/research/lookalike-study.json`, `data/ml/research/recency-gap-posthoc.json` |
| RPC requests | 0. No downloads. Nothing paid. |
| Production detector | unchanged; nothing here is wired into it |

## 1. Summary

The task: rank the k ≥ 2 lookalikes that had planted transfers to a victim, at the block
before the victim's first confirmed payoff. The outcome is which one was paid. Results on
the test split (428 episodes, 427 groups) follow. **B0 is the unchanged production
similarity score.**

| Method | Top-1 | MRR |
|---|---|---|
| random | 0.199 | 0.403 |
| **B0** production similarity | 0.300 | 0.501 |
| B3 recipient history | 0.247 | 0.458 |
| **T0 recency** | **0.618** | **0.764** |
| G1 graph reuse | 0.206 | 0.407 |
| H_fixed (B1, B3, T2, G1) | 0.462 | 0.631 |

| Primary test (Holm over 4) | Top-1 difference vs B0, 95% CI | Holm p | Decision |
|---|---|---|---|
| P-H1 recipient history, B3 − B0 | −0.053 [−0.096, −0.014] | 0.007 | reversed |
| P-H2 temporal, T0 − B0 | **+0.318 [0.262, 0.372]** | 0.0004 | **supported** |
| P-H3 graph, G1 − B0 | −0.094 [−0.132, −0.057] | 0.0004 | reversed |
| P-H5 hybrid, H − B0 | +0.162 [0.123, 0.203] | 0.0004 | supported |

Holm p = 0.0004 is the resolution floor of 10,000 permutations times 4 tests.

- **Positive:** recency of the lookalike's latest planting is a strong ordering signal. It
  holds a day before the payoff, in every year and every k bin, and among episodes whose
  paid lookalike last planted more than 30 days earlier.
- **Negative:**
  - The cross-victim graph (G1, G2, G3) does not beat random.
  - Recipient-history counts (B3) do worse than the production score.
  - The source's intended-address similarity (B1) adds nothing over B0.
  - The hybrid is supported only because it contains a temporal component, and it is
    worse than recency alone.
- **Caveat:** the candidates and the outcome are source-defined. The recency effect is a
  property of payoffs that the source confirmed, not yet of wallets in general.

## 2. Question and scope

The central question asks whether three things improve detection or prioritization over
the existing poisoning rules:
- temporal wallet context;
- historical recipient relationships;
- graph-based attacker infrastructure.

**This phase answers prioritization only, for one retrospective task.**
- **Task 2:** within-victim ranking (`lookalike-prioritization/1`), the confirmatory task.
- **Task 1:** candidate-generation coverage. Exploratory, carried over from Phase 11.7.
- **Outcome research:** the payoff-conditioned framing itself.

No detection task is evaluable here. The background rows are unlabeled, and unknown is
not benign.

## 3. Retrospective ranking versus prospective detection

| | This study (retrospective) | Prospective detection (not measured) |
|---|---|---|
| Population | victims who later paid a flagged lookalike | every wallet, most never poisoned or never paying |
| Candidates | source-flagged plantings only | everything a wallet receives |
| Outcome | which flagged lookalike was paid | whether a transfer is an attack, and whether a warning prevents loss |
| Metrics | top-1, MRR within an episode | precision, FPR, recall, prevented loss |
| Supports | "among flagged lookalikes, rank recent ones first" | none of the prospective claims |

T0 needs only the wallet's own history, so it is computable prospectively (§21). Whether
recency-first ordering prevents a single loss is untested.

## 4. Pre-registration and deviations

- **Frozen before analysis:** the protocol at `999794a`. Its hypotheses, metrics, split,
  groups, tests and decision rule were not changed.
- **Recorded before any outcome was computed** (`12f09a1`, pushed before the study ran):
  - **F1, defect:** rows of the 91 frozen wallets entered the graph index. Fixed with
    `GraphIndex(exclude=...)`.
  - **F2, defect:** the archive scanner maintained its three indexes during inserts. The
    first pass wrote about 5 GB of journal, reached 32% in about two hours and ended with
    the session. The indexes are now built after the load, with the same schema. The
    partial output was discarded (§23).
  - **D1:** entity and campaign overlap with the 95 frozen items. Sensitivity tests were
    added, and the learned model is not fitted on overlapping episodes.
  - **D2:** a coverage-symmetry audit.
- **Added after the results:**
  - **D3:** the runtime budget was overrun (§23). It does not affect any value.
  - **D4:** the post-hoc recency-gap diagnostic (§20). It is labelled post-hoc, and no
    primary result depends on it.

## 5. Data and sources

All data is local and derived from Tsuchiya et al. (USENIX Security 2025), *Ethereum
address poisoning* archive. The archive is CC BY-NC-ND 4.0, so it is kept local and only
aggregates are committed.

- **`archive_subset.sqlite`:** every archive row touching a payoff victim. It holds the
  source's poisoning, intended and payoff rows, but no ordinary activity.
- **`research/graph_context.sqlite`** (new): one offline pass over all 34,905,969 archive
  rows. It stored 1,306,648 rows touching any of the 13,418 candidate lookalikes or 26,816
  planting transactions. It was built from a hashed target manifest, and the audit checks
  that hash.
- **Not available locally:** signers, receipts and contract code. Shared-signer edges (H3)
  are untestable.

## 6. Populations

Each population is reported separately and never pooled.

| Id | Population | Use here |
|---|---|---|
| P1-cov | payoff-linked attempts (1,409, protected wallets removed) | Task 1 coverage (§21) |
| P1-rank | eligible episodes (1,068) | confirmatory ranking |
| P2 | background windows (unlabeled) | availability only: 9 windows, 2 with k ≥ 2 |
| P3 | incident windows | availability only: 4 windows, all with k ≥ 2 |
| P4 | frozen review cohorts (95 items) | **excluded** from every computation |

## 7. Eligibility and exclusions

From the archive's payoff victims, the study keeps **1,068 eligible episodes**. Excluded:

| Reason | Victims |
|---|---|
| protected review wallet | 60 |
| no confirmed payoff row | 96 |
| several lookalikes paid in the payoff block | 1 |
| single candidate (k = 1) | 277 |

These counts equal the protocol's figures at freezing. k has mean 12.6 and median 5.

## 8. Protected cohorts and overlap

- The 91 wallets of both frozen cohorts are excluded as episodes. Their rows never become
  graph edges (F1, tested).
- Review keys and manifests were never read. Overlap uses the blinded sheets only.
- **Overlap (D1):** 1 episode, in the test split, shares an entity or a linkage group with a
  frozen item.
  - Without it (427 test episodes), all four primary decisions are unchanged. The
    differences are −0.054, +0.318, −0.095 and +0.162.
  - The learned model was fitted on 640 development episodes. None of them overlaps.
- Frozen cohort files, hashes, packets and selection procedures were not modified.

## 9. Coverage symmetry: the outcome leak, audited

The earlier subset targeted payoff lookalikes only. Any cross-victim count read from it
would have been complete for the paid candidate and nearly empty for its rivals.

| | Paid (1,068) | Rival (12,367) |
|---|---|---|
| Targeted by the new manifest | 100% | 100% |
| Planting rows present in the graph database | 100% | 100% |
| Planting transactions targeted | 100% | 100% |
| Covered by the old subset | 100% | **0.2%** |
| Median archive rows at the cutoff | 2 | 1 |

- The scan used this exact manifest (hash match), so the audit's verdict is
  **symmetric**.
- The remaining difference in rows observed is a difference in activity, not in coverage.

## 10. Features and missingness

All features use only rows at or before the cutoff c = T − 1.
- **B0:** the production detector's prefix+suffix against the victim's own recipients.
- **B1:** source intended-address similarity.
- **B2:** transaction semantics.
- **B3:** payments to the reference.
- **T0:** recency.
- **T1:** distinct planting transactions.
- **T2:** decayed exposure.
- **T3:** planting later than the last real payment.
- **T4:** one-day burst.
- **G1 / G2:** other victims and other payers.
- **G3:** batch size.
- **NC:** token-level negative control.

**Missingness:**
- `None` means not observed, and `0` means observed and none.
- A method abstains, scoring exactly at random, when any candidate is `None`.
- At the primary cutoff, only T3 abstains (1.4%). Missingness indicators therefore change
  nothing in the learned model (§17).
- Under the 7-day victim lookback, B0 and B3 abstain on 29% of episodes.

## 11. Methods

- Single-feature rankings, with ties kept.
- Random.
- **H_fixed:** the mean normalized rank of B1, B3, T2 and G1, one per hypothesis family,
  with fixed weights.
- **Learned (exploratory):** a conditional logit, L2 with C = 1, fitted on development
  pairs.

No method has a tuned parameter.

## 12. Metrics, groups, split, inference

- **Metrics:** top-1 is tie-averaged, and MRR is the expectation under random
  tie-breaking.
- **Groups:**
  - Linking by shared transactions gave 600 groups with an oversized largest group, so
    the protocol's fallback applied: linkage by shared candidate lookalikes.
  - That gives 1,059 groups; the largest has 6 episodes.
- **Temporal split by group:**
  - development: 640 episodes, 632 groups;
  - test: 428 episodes, 427 groups.
- **Inference:**
  - paired group bootstrap, 95% CI, 2,000 draws;
  - group sign-flip permutation, 10,000 draws, seed 20261102;
  - Holm over the four primary tests;
  - margin 0.05.

## 13. Primary results

These are the four tests in §1, run once on the test split.

- **"Reversed" is the protocol's term for significantly worse than B0.** It does not mean
  the signal points the wrong way:
  - **B3 vs random:** +0.038 [0.026, 0.051] on all episodes. B3 is weakly informative,
    but less so than B0.
  - **G1 vs random:** +0.005 [−0.007, 0.018], p = 0.39. There is no evidence that G1
    carries information.
- **The production score B0 is only modestly better than random:** +0.076 [0.055, 0.096]
  on all episodes.

## 14. Exploratory: every method against B0

These are paired top-1 differences on all 1,068 episodes, with no multiplicity control.

| Method | vs B0 | 95% CI |
|---|---|---|
| T2 decayed exposure | +0.373 | [0.340, 0.406] |
| T4 one-day burst | +0.096 | [0.068, 0.124] |
| T3 planted after last real payment | +0.046 | [0.023, 0.069] |
| T1 planting count | +0.037 | [0.006, 0.066] |
| B1 source similarity | −0.002 | [−0.004, 0.000] |
| B2 semantics | −0.013 | [−0.038, 0.012] |
| G2 other payers | −0.075 | [−0.096, −0.055] |
| G3 batch size | −0.092 | [−0.122, −0.061] |
| NC negative control | −0.109 | [−0.135, −0.086] |

Development and test agree on which side of B0 each method falls, except B2 and T3, which
flip:
- T0 scores 0.730 on development and 0.618 on test;
- B0 scores 0.305 and 0.300.

## 15. Temporal analysis

Recency (T0) and decayed exposure (T2), which is dominated by the latest planting, are
the only strong signals.

- **Paid versus rival gap** (from the cutoff to the lookalike's latest planting):
  - paid: median 19,709 blocks, about 2.7 days;
  - rival: median 472,545 blocks, about 66 days.
- **Robustness:** with the cutoff a day earlier (T − 7,200, 745 evaluable episodes), T0
  scores 0.649 against B0's 0.310 and random's 0.220.
- **Burst and count** (T4, T1) add little beyond recency.

**Mechanism.** 96% of paid lookalikes (1,025 of 1,068) last planted a spoofed transfer
that shows the victim as sender, so it appears in the victim's own outgoing history. The
pattern fits a victim copying the newest matching entry from that history. This is an
interpretation, not a tested causal claim.

## 16. Graph analysis and controls

| Check | Result | Expected |
|---|---|---|
| G1 top-1 | 0.233 (all) | — |
| G1 within-episode shuffle | 0.223 | random (0.228) ✓ |
| G1 global shuffle | 0.227 | random ✓ |
| Rows after the cutoff added, features compared | 0/100 mismatches | 0 ✓ |
| Graph lookback 30 days | G1 0.244 | — |
| Graph rows 50% dropped | G1 0.235 | — |
| NC (token negative control) | **0.194 < random 0.228** | random ✗ |

- **G features:** the paid and rival medians are both 0 for G1 and G2. The cross-victim
  reuse of a lookalike does not distinguish the one that gets paid. G2 and G3 are slightly
  *below* random.
- **The negative control is not null.** It is anti-informative:
  - paid lookalikes' latest plantings are in tokens planted to fewer study victims
    (median 127 against 359);
  - 55% of all plantings are in USDT, USDC or DAI.
  - So token choice correlates with the outcome, and that confounds any token-level
    signal.
  - The bias runs against NC, so it does not inflate any positive claim here. It shows
    that paid and rival lookalikes differ in campaign structure as well as timing.

## 17. Hybrid, ablations and learned model

| Test split | Top-1 |
|---|---|
| H_fixed | 0.462 |
| H without T2 | 0.322 |
| H without B1 | 0.469 |
| H without B3 | 0.475 |
| H without G1 | 0.477 |
| T0 alone | 0.618 |
| Learned, with or without indicators | 0.591 |

- **H_fixed is carried by T2.** Removing any non-temporal component *improves* it, so the
  supported P-H5 is a temporal result diluted by the other families.
- **Learned model** (exploratory; 640 development episodes, 10,878 pairs):
  - largest standardized weights: T0 2.00, T3 1.00, B3 0.63, B2 0.34; G1 −0.02;
  - against B0 on test: +0.291 [0.245, 0.339];
  - it does not beat T0 alone, so no learned model is justified.
- Removing the missingness indicators changes nothing (§10).

## 18. Strata

Top-1 on all episodes.

| Stratum | n | random | B0 | T0 | H |
|---|---|---|---|---|---|
| 2022 | 62 | 0.404 | 0.441 | 0.718 | 0.629 |
| 2023 | 891 | 0.221 | 0.298 | 0.684 | 0.483 |
| 2024+ | 115 | 0.186 | 0.266 | 0.678 | 0.457 |
| k = 2 | 205 | 0.500 | 0.512 | 0.781 | 0.676 |
| k = 3–5 | 339 | 0.274 | 0.370 | 0.757 | 0.591 |
| k ≥ 6 | 524 | 0.091 | 0.178 | 0.601 | 0.350 |
| spoofed transfer | 1,025 | 0.230 | 0.305 | 0.687 | 0.494 |
| tiny transfer | 40 | 0.167 | 0.265 | 0.625 | 0.350 |

- The fake-token (n = 1) and zero-value (n = 2) paid subtypes are too small to read.
- 2022 and the tiny subtype are small strata.

## 19. Robustness

Each variant is computed on the episodes evaluable under it. The last column is the share
of episodes whose T0 top set changed.

| Variant | Evaluable | B0 | T0 | H | T0 top set changed |
|---|---|---|---|---|---|
| primary (T − 1) | 1,068 | 0.303 | 0.685 | 0.489 | — |
| cutoff T − 300 | 922 | 0.304 | 0.667 | 0.504 | 3.2% |
| cutoff T − 7,200 | 745 | 0.310 | 0.649 | 0.521 | 5.7% |
| victim history 7 days | 1,068 | 0.361 | 0.685 | 0.524 | 0% |
| victim history 30 days | 1,068 | 0.346 | 0.685 | 0.517 | 0% |
| victim rows 50% dropped | 1,068 | 0.310 | 0.685 | 0.483 | 0% |
| graph 30 days | 1,068 | 0.303 | 0.685 | 0.491 | 0% |
| graph 50% dropped | 1,068 | 0.303 | 0.685 | 0.489 | 0% |

**Restricting the victim's history to the last 7 or 30 days *raises* B0.** This is more
evidence that recency is what matters. It is exploratory and not a tuned improvement.

## 20. Source shift and the recency check

- **Feature availability:** every feature is 100% available in every year, except T3
  (§10).
- **Shifts by year:** k grows in later years, so random top-1 falls from 0.40 (2022) to
  0.19 (2024+). T0 stays at 0.68–0.72.
- **Post-hoc diagnostic (D4, not pre-registered).** If the source matched payoffs only
  within a time window, recency would be built into the label.
  - **No narrow window:** paid gaps reach 1.70M blocks, about 236 days. 11.1% of paid gaps
    exceed 30 days.
  - **Recency keeps its edge on long gaps:** among the 119 episodes whose paid gap exceeds
    30 days, T0 scores 0.487 against random's 0.205.
  - **A soft cap cannot be excluded:** no paid gap exceeds 365 days, while 1.9% of rival
    gaps do.

## 21. Task 1 coverage, and prospective availability

**Candidate generation** (`candidates/2`) on the 1,409 payoff-linked attempts:

| Window | Strict signer | Optimistic signer |
|---|---|---|
| 7 days | 6 (0.43%) | 51 (3.6%) |
| 30 days | 6 (0.43%) | 54 (3.8%) |
| all history | 6 (0.43%) | 54 (3.8%) |

- 1,355 misses are spoofed outgoing transfers that need the signer, which the archive
  lacks. Longer windows do not help.
- Dust is emitted on 50 of 50 under the optimistic mode.

**Computable prospectively, from a wallet's own signed history:** B0, B3, T0–T4.
- B1 is not: it needs the source's intended address.
- G1–G3 are not: they need a cross-wallet index at the cutoff.

**Where the ranking task arises:**
- P2: 2 of 9 background windows have k ≥ 2.
- P3: all 4 incident windows do (k = 3, 9, 5, 18).

## 22. Error analysis

On test, H_fixed misses or ties in 244 of 428 episodes, 29 of them tied at the top.
Categories overlap:

| The paid lookalike was not… | Misses |
|---|---|
| the most similar (B1) | 177 |
| the most reused (G1) | 131 |
| the most recent (T0) | 119 |
| tied to the most-used reference (B3) | 116 |

On all episodes, H's top-1 falls from 0.68 at k = 2 to 0.35 at k ≥ 6 (§18). No item was
inspected; the numbers are aggregates only.

## 23. Resources and cost

| Step | Wall | Peak RSS | Notes |
|---|---|---|---|
| First archive pass (failed) | ~2 h | ~210 MiB | 32% done, ended with the session; partial file not used (F2) |
| Archive pass (fixed scanner) | 58 min (scan 45 min) | 344 MiB | 34.9M rows; 1.02 GB peak spill, cleaned; 596 MB output |
| Study | 2 h 16 min | 744 MiB | primary features 1 h 47 min, almost all graph lookups |
| Post-hoc diagnostic | < 1 min | — | no graph |

- **The protocol's budget of 2 minutes per experiment was overrun (D3).** The cause is SQLite
  lookups for 13,435 candidates on one HDD shared with other projects' jobs, at 0% idle.
- The memory limits held: under 512 MiB for the pass, under 1 GB for the study.
- **G features are the most expensive and add nothing.**
- CPU only. 0 RPC requests.

## 24. Limitations

1. **The population is conditioned on a payoff.** Nothing here concerns victims who never
   paid, or attempts in general.
2. **The candidates and outcome are source-defined.**
   - The source's heuristics may use information after c.
   - Recency could partly reflect how the source matched payoffs (§20).
3. **The history is source-selected.** B0, B3 and T3 see only the payments the source
   kept. That may handicap B0 relative to a wallet with full history.
4. **The data is dominated by one mechanism.** 96% of paid lookalikes used spoofed
   transfers, so the results speak mostly to that subtype.
5. **One source.** There is no independent dataset of ranking outcomes, so external
   validity is untested.
6. **The negative control failed to be null** (§16). Campaign structure differs between
   paid and rival lookalikes in ways not modelled here.
7. **Multiplicity.** Only the four primary tests are confirmatory.
8. **No human labels exist.** The 95 frozen items are unreviewed.

## 25. Conclusions, blockers and next experiment

**Positive (confirmatory, retrospective).** Among source-flagged lookalikes that planted
to a victim who later paid one, recency picks the paid lookalike first 62% of the time on
test. That is twice the production similarity score (30%) and three times random (20%).
The result holds a day before the payoff, across years and k, and on long-gap episodes.
P-H5 is also supported, but only through its temporal component.

**Negative (confirmatory).**
- Cross-victim graph reuse (P-H3) gives no ranking signal.
- Recipient-history counts (P-H1) do worse than the production score.
- In exploratory comparisons, intended-address similarity, transaction semantics, batch
  size and prior payers add nothing.
- A learned combination does not beat recency alone.

**Source-selection limitations.** These are the limitations in §24, items 1–6. They bound
every claim to "payoffs confirmed by this source".

**Not claimed.**
- No precision, FPR, recall, AP, detection improvement or prevented loss.
- No change to the production detector, and no deterministic warning suppressed.

**Blockers.**
- Human review of the 95 frozen items: waiting on two reviewers; no labels anywhere.
- No signer data: spoofed transfers stay outside `candidates/2`'s strict coverage.
- No prospective population with outcomes.
- G features would need a cross-wallet index that production does not have. They are not
  worth building, on this evidence.

**Next experiment** (to pre-register; not started):
- **What:** test recency-first ordering of lookalike warnings, B0-passing candidates
  ordered by T0, as a fixed rule.
- **Where:** a population not used here, such as a later archive release or independently
  reviewed incidents.
- **Measure:** the share of losses in which the paid lookalike was the top warning, not
  detection accuracy.
- **Constraint:** no RPC beyond a newly approved budget.
