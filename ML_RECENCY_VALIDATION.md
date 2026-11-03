# Recency validation and operational warning ranking (Phase 12.2)

| Item | Value |
|---|---|
| Protocol (frozen before any 12.2 outcome) | [`docs/ml/protocol-12.2.md`](docs/ml/protocol-12.2.md), commit `03f1c1d` |
| Analysis code (committed before it ran) | `623b36d`: `ml/recency_validation.py`, `ml/warning_rank.py`, `cryptoguard ml recency-validation` |
| Outputs (git-ignored, aggregates) | `data/ml/research/phase12.2/`: `recency-validation.json`, `exactness.json`, `lookalike-study-preloaded.json` |
| Phase 12.1 outputs | preserved unchanged in `data/ml/research/phase12.1/` |
| RPC requests / downloads | 0 / none |
| Production detector | unchanged; nothing is wired into it |

**Scope.** This phase re-examines the archive episodes whose outcomes Phase 12.1 already
saw. Every archive result below is therefore a **retrospective internal sensitivity
analysis, not independent validation**. "Top-1" means the paid lookalike ranked first among
the candidates of a retrospective episode. It is not detection accuracy, precision, recall,
an FPR or a prevented loss.

## 1. Executive summary

**Result: a source-conditional retrospective effect, which fails the independence gate.**

Q1 asked whether recency is an artifact of how the source confirmed payoffs. The source says
it confirmed a payoff by checking that a "poisoning transfer exists between the intended and
the payoff transfer". Applying that rule to rivals as well removes almost nothing (H1):

| H1 | Recency (T0) | Production similarity (B0) | Difference [95% CI] |
|---|---|---|---|
| Rule as written (primary) | 0.682 | 0.300 | +0.382 [0.347, 0.417] |
| Stricter reading: latest planting after the latest intended transfer | 0.671 | 0.332 | +0.339 [0.300, 0.379] |

- Primary: 1,059 episodes, Holm p = 0.0002, decision *survives*.
- Under the rule as written, the restriction attenuates the effect by 0.2%. 99.4% of rivals
  also satisfy the rule, so it is not selective and cannot explain recency.
- The stricter reading is selective (95.9% of paid lookalikes, 61.1% of rivals), yet recency
  still survives on its 910 episodes.

Q2 asked whether the candidates were available at the cutoff. All candidates and features
are taken at or before the cutoff.
- When the unchanged production detector runs on the archive rows at the cutoff, it warns
  on 99.2% of paid and 99.2% of rival lookalikes.
- So the candidate sets are, to that extent, what CryptoGuard itself would raise from this
  stream.

Q3 asked about generalization. There is **no untouched outcome dataset**.
- The only external data are the 4 recorded incidents, and 3 of them have at least 2
  warnings.
- In all 3, recency ordering puts the stolen-funds recipient first. Production order does
  so in 1 of 3.
- This is descriptive, n = 3.

Q4 asked about operational use. Ordering production warnings by severity tier, then
recency, puts the paid lookalike first more often than ordering by severity, then
similarity (H2):

| H2 (1,057 episodes) | Top-1 |
|---|---|
| OP1: severity, then recency | 0.502 |
| OP0: severity, then similarity | 0.267 |
| Difference [95% CI] | +0.235 [0.208, 0.263], Holm p = 0.0002 |

The ranker never removes or re-tiers a warning. It stays experimental and off by default.

**Engineering.** The Phase 12.1 study now reproduces exactly (same result hash) in 179 s
instead of 8,157 s, and at 485 MiB instead of 744 MiB. The whole Phase 12.2 study runs in
38 s.

## 2. Phase 12.1 baseline, verified

The saved report, SHA-256 `94734a71…`, is reproduced exactly (§17–18).

| Test split, 428 episodes | Top-1 |
|---|---|
| random | 0.199 |
| B0 | 0.300 |
| T0 | 0.618 |

- T0 − B0 = +0.318 [0.262, 0.372].
- On all 1,068 episodes, T0 scores 0.685 and B0 scores 0.303.

## 3. Phase 12.2 pre-registration

`03f1c1d` fixed every element before any analysis ran:
- the populations R, R-SR, O-arch, X-inc and P2, with their classifications;
- the frozen scorers T0, B0, OP0 and OP1;
- the symmetric confirmation rule (SR_any primary, SR_latest sensitivity) and a
  manipulation check;
- H1 and H2 with Holm, and H3 as descriptive;
- the exploratory list E1–E14;
- the decision rules, the exactness gate and the budgets.

The analysis code was committed (`623b36d`) before it ran.

**Deviation.** H2 was not repeated without the 1 protected-overlap episode, although
§7 says it should be. One episode can move H2's mean by at most 1/1,057 ≈ 0.001.

## 4. Dataset independence audit

| Source | Unit and label mechanism | Outcomes examined before? | Overlap with Phase 12.1 | Classification |
|---|---|---|---|---|
| Tsuchiya archive, confirmed payoffs (1,634 rows; 1,068 eligible episodes) | source heuristics plus manual Etherscan confirmation | **yes, all** (12.1 development and test) | the same episodes | previously examined development data |
| Tsuchiya unconfirmed payoffs (13,683 rows) | the same heuristics, without confirmation | no | the same collection and rules; 143 rows touch study victims | not used: label-uncertain, needs about 2 h of offline passes (§25) |
| Tsuchiya BSC payoffs | the same method, another chain | no | none | **not local**; a download needs approval |
| Poison-Hunter | flagged poisoning transfers and addresses | partly (Phase 11.3) | 89 of 105 in-definition rows are archive attempts | not usable: no paid-versus-rival outcome |
| PTXPhish | phishing transactions | yes (Phase 11) | none | not usable: no rival candidates |
| Recorded incidents (4) | public post-incident reports; complete recorded wallet streams with signers | the ranking outcome was not examined before; the detector was developed with these fixtures in view | none (incident victims are not archive payoff victims) | **external source with limitations**, n = 4 (3 rankable) |
| Recorded background windows (9) | none | — | none | operational diagnostics only |
| Frozen review cohorts (95) | awaiting human review | — | — | **excluded** |

**Independence gate: no genuinely independent outcome population exists locally.**

## 5. Frozen recency definition

`lookalike-features/1` T0 was verified in code (`candidate_features`) and is unchanged.

| Question | Answer |
|---|---|
| Definition | `-(c - b)`, where b is the block of the candidate's latest source planting (zero-value, tiny or counterfeit; either direction) to the victim at or before c |
| Unit | blocks, not wall-clock time |
| Same-block order | not used |
| Ties | tie-averaged (`1/m`); random-order ties, not deterministic |
| Missing planting time | impossible in the archive: every row has a block |
| Repeated plantings | only the latest counts |
| Cutoff | inclusive, c = T − 1; rows in the payoff block are counted but never used |
| Deduplication | exact duplicate rows cannot change T0 (E11) |
| Future rows | excluded by construction, and tested (§6) |

No defect was found, so no new version was made.

## 6. Observation cutoff

- **Archive analyses:** c = T − 1.
- **Robustness (Phase 12.1):** T − 300 and T − 7,200.
- **Operational replays:** `detector_outputs(fixture, cutoff)`, which reads only records at
  or before the cutoff.
- **Tests** check that the following leave the candidate sets, the confirmation rule and the
  rankings unchanged:
  - rows after the cutoff;
  - a later intended transfer;
  - trimming a recorded incident's future transfers.

## 7. Operational candidate availability

The candidate lifecycle (brief §9) on O-arch:

1. **Archive observation:** the source-selected rows at or before c. This means no ordinary
   activity, no signers, and values known only as zero or nonzero.
2. **Generated by CryptoGuard:** the unchanged `detect_poisoning`, run on those rows:
   - paid: 99.16% warned;
   - rival: 99.23% warned.
   - The paid and rival shares agree to within 0.1 percentage point, so warning generation
     is not outcome-asymmetric.
3. **Eligible for H2:** 1,057 episodes in which the paid lookalike is among at least 2
   warnings.
4. **Never used to build candidate sets:** the payoff, or the source's "paid" label.

The cutoff stream is **reconstructed and source-selected**, not a genuine recorded wallet
stream. Only the 4 incidents and 9 background windows are genuine recordings.

## 8. Symmetric evidence verification

From Phase 12.1, reproduced exactly here:
- paid and rival lookalikes were 100% targeted by the same manifest;
- 100% of their planting rows are present;
- the scan hash matches.

For this phase:
- the same cutoff, filters and deduplication apply to both;
- features never read the outcome;
- SR uses only rows at or before c, and is computed identically for paid and rival.

**Residual asymmetry.**
- SR_latest is satisfied by 95.9% of paid lookalikes and 61.1% of rivals. That is
  outcome-associated, and expected if the latest planting is what gets copied.
- Restricting every candidate to SR_latest-true leaves the effect (§1).

## 9. Negative-control investigation

These are the pre-registered controls (E1, E2, E10).

| Control | Null | What is fixed | Expected | Observed |
|---|---|---|---|---|
| E1, within-episode permutation of T0 (200 repeats) | T0 values carry no candidate information | candidate counts, value multiset | random (0.2275) | 0.2273 ✓ |
| E2, oldest first | — | everything | below random if recency is real | 0.057 |
| NC overall | token co-usage is uninformative | — | random | 0.194 < 0.228 |
| NC, paid's token public stablecoin (551) | — | — | random (0.249) | 0.313 |
| NC, paid's token other (517) | — | — | random (0.204) | 0.067 |
| NC, all candidates share a token class (501) | — | token class | random (0.306) | 0.289 |
| Within-episode Spearman of NC and T0 (623 episodes, k ≥ 3) | — | — | — | median −0.44 |

**Interpretation.** NC's below-random score is largely explained by two things, but not
proven:
- it mixes token classes, and its sign flips between them;
- it is strongly anti-correlated with recency. Lookalikes whose latest planting used a token
  shared by many study victims are older.

Within a single token class it is close to random (−0.017).

What remains open: why "other" tokens give NC its strongly anti-informative value. One
candidate explanation is a campaign-specific counterfeit contract. That is a hypothesis.

## 10. Temporal matching bias

| What the source documents | |
|---|---|
| The rule | a confirmed payoff needs a poisoning transfer between the intended transfer and the payoff (`guidance.ipynb`) |
| Not documented | a maximum lookback; nearest-event assignment; rounding; ordering inference |

- **Manipulation check:** 100% of paid lookalikes satisfy SR_any, so our reading reproduces
  the rule. 99.4% of rivals satisfy it too, so as written it barely selects.
- **Stricter reading:** recency survives SR_latest (§1).
- **Symmetric maximum lookbacks** (E7; a candidate is dropped when its latest planting is
  older than the window):

| Window | Episodes | T0 | B0 | random |
|---|---|---|---|---|
| 30 days | 827 | 0.667 | 0.332 | 0.307 |
| 90 days | 987 | 0.675 | 0.316 | 0.264 |
| 180 days | 1,050 | 0.683 | 0.306 | 0.239 |

- **Without immediate copies** (E8; paid gap ≥ 300 blocks; stratified on an outcome
  attribute): 877 episodes, T0 0.660, B0 0.306.
- **Phase 12.1 post-hoc check, verified:**
  - paid gaps reach 1.70M blocks, about 236 days;
  - 11.1% exceed 30 days;
  - on those, T0 scores 0.487 against random's 0.205.

**Unresolved.** Payoff candidates may have been flagged with an outcome-dependent temporal
rule that the source does not document, upstream of confirmation. These data cannot test
that (§21).

## 11. Confounder analyses

E5 and E9. Every comparison below is on all episodes, with n and groups reported.
- **Victim activity**, by the victim's outgoing rows at or before c:

| Tertile | n | T0 | B0 | random |
|---|---|---|---|---|
| low | 364 | 0.717 | 0.384 | 0.351 |
| mid | 364 | 0.692 | 0.302 | 0.206 |
| high | 340 | 0.643 | 0.218 | 0.118 |

- **The newest candidate's age**, which uses no outcome: T0 stays between 0.673 and 0.697 in
  every bin (under 1 hour, 1 hour to 1 day, 1 to 7 days, over 7 days). Recency is therefore
  not only "the attacker who planted minutes before".
- **Token class:**
  - paid's latest planting in a public stablecoin (551): T0 0.708 against B0 0.313;
  - other (517): T0 0.661 against B0 0.293;
  - candidate sets restricted to public-stablecoin plantings (522): T0 0.763 against
    B0 0.351.
- **Campaign concentration:** the largest linkage group holds 6 episodes (0.56%). No single
  campaign dominates.

## 12. Subgroup robustness

| Stratum | n (groups) | T0 | B0 | random |
|---|---|---|---|---|
| 2022 | 62 (62) | 0.718 | 0.441 | 0.404 |
| 2023 | 891 (886) | 0.684 | 0.298 | 0.221 |
| 2024+ | 115 (113) | 0.678 | 0.266 | 0.186 |
| k = 2 | 205 (205) | 0.781 | 0.512 | 0.500 |
| k = 3–5 | 339 (339) | 0.757 | 0.370 | 0.274 |
| k ≥ 6 | 524 (516) | 0.601 | 0.178 | 0.091 |
| spoofed transfer | 1,025 (1,016) | 0.687 | 0.305 | 0.230 |
| tiny | 40 (40) | 0.625 | 0.265 | 0.167 |

- The fake-token (n = 1) and zero-value (n = 2) subtypes are too small to read.
- **96% of episodes are spoofed transfers.** The result is essentially about that mechanism.

## 13. History truncation and perturbations

| Perturbation | Evaluable | T0 top-1 |
|---|---|---|
| none | 1,068 | 0.685 |
| planting blocks jittered ±1 day | 1,068 | 0.605 |
| jittered ±7 days | 1,068 | 0.555 |
| blocks coarsened to 1-day buckets (ties) | 1,068 | 0.590 |
| coarsened to 7 days | 1,068 | 0.516 |
| each candidate's latest planting dropped (a missed observation) | 420 | 0.720 |
| exact duplicate rows injected | 1,068 | 0.685 (unchanged) |
| line order shuffled within blocks | 1,068 | 0.685 (unchanged) |

Phase 12.1's variants reproduce exactly:
- cutoff T − 7,200 (745 episodes): T0 0.649;
- victim lookback of 7 days: B0 rises to 0.361.

**Reading the perturbations:**
- Recency degrades gracefully with timestamp noise, and stays well above B0 even at
  7-day precision.
- Dropping the latest planting leaves only episodes where every candidate had at least two
  plantings, which is a different population. That 0.720 is not comparable to 0.685.

## 14. Source-domain limitations

- **One source:** Ethereum, mostly 2023, and 96% spoofed-transfer mechanisms.
- **Candidate sets are source-flagged plantings.**
- **History is source-kept rows only.** B0 sees only the intended transfers the source
  recorded.
- **No BSC data, and no unconfirmed payoffs.**

## 15. Operational warning ranking

`ml/warning_rank.py`, `poisoning-warning-rank/1`, is research only and not imported by any
production path.

- **Input:** production `PoisoningCase`s at a cutoff.
- **Output per warning:**
  - rank;
  - severity, unchanged;
  - similarity;
  - basis (`latest_planting_signal` or `no_recency_basis`);
  - basis block and transaction;
  - blocks before the cutoff;
  - cutoff;
  - algorithm version;
  - explanation. For example: "Within severity elevated_risk, ordered by its latest planting
    signal at block … (… blocks before cutoff …), against 3 other warning(s). Ordering only:
    not a probability."
- **Order:**
  1. severity tier;
  2. latest planting signal (zero-value, spoofed outgoing, unsolicited incoming; the
     wallet's own sends never count);
  3. similarity;
  4. address.
- **Without a basis:** a warning keeps its baseline order behind its tier's warnings that
  have a basis.
- **Tested:**
  - the warning set is always preserved;
  - a lower tier never outranks a higher one;
  - inputs are not mutated;
  - ties are deterministic under every permutation;
  - rows after the cutoff are ignored on a real incident;
  - single-block resolution is exact.

**Results:**

| Population | Warnings / episodes | Rankable (≥ 2 warnings) | Result |
|---|---|---|---|
| O-arch (H2) | 1,057 eligible episodes | 1,057 | OP1 0.502 vs OP0 0.267, +0.235 [0.208, 0.263] |
| X-inc (H3) | 4 incidents | 3 | paid recipient ranked 1st by OP1 in 3 of 3 (OP0: 1 of 3; random: 1/3, 1/7, 1/4); the 4th incident has 1 warning |
| P2 background | 9 windows, 5 warnings | 2 | order changed in 1 window; warning set preserved in 9 of 9; 0 warnings without a basis; 8 ms |

**OP1 is weaker than T0.** OP1 scores 0.502 against T0's 0.685 on its population because
severity tiers come first. The safety constraint therefore costs ranking power on this
retrospective task. That cost is accepted by design.

## 16. Statistical uncertainty

- **Clustering:** paired top-1 differences are clustered on 1,059 shared-lookalike linkage
  groups. Every episode is a distinct victim (1,068).
- **Intervals:** group bootstrap, 2,000 draws.
- **p-values:** group sign-flip permutation, with 10,000 draws for H1 and H2 and 2,000 for
  exploratory analyses.
- **Multiplicity:** Holm over H1 and H2.
- **Effect sizes:** H1 +0.38 and H2 +0.24 on top-1, against a random baseline of about 0.23.
- **What the intervals cover:** sampling variation over victims in *this* source population
  only. They say nothing about other populations.

## 17. Performance optimization

**Profile** (300 seeded lookups each):
- query plans were correct: index searches, including a multi-index OR;
- per lookalike lookup: 96 ms mean, 271 ms p95, median 2 rows;
- per planting-transaction lookup: 512 ms mean, 1.87 s p95, median 20.5 rows;
- a sequential scan of all 1,306,648 rows took 13 s;
- the 596 MB file has 145,416 pages with a 2 MB cache.
- **The cost is one random page read per matched row on a shared HDD.**

**Fix:** `preload_graph`, a single ordered pass that builds every typed edge with the lazy
index's own per-row rules (factored into shared functions). Edge-level keep filters
reproduce the 50% drop and the cutoff filters. `coverage_symmetry` now uses one pass
instead of two lookups per candidate.

| Phase 12.1 study | Lazy (12.1) | Preloaded |
|---|---|---|
| Total wall time | 8,157 s | **179 s** |
| Graph build plus primary features | 6,429 s | 11 s + 9 s |
| Peak RSS | 744 MiB | 485 MiB |
| Disk read | not measured | 1,317 MiB, 340k operations |
| Result hash (all non-timing keys) | `1dbc763f7058f8c4` | `1dbc763f7058f8c4` |

- Both runs took place on the same machine, with other projects' jobs present in both.
- The whole Phase 12.2 study took 38 s at 311 MiB peak, including 13 s for the production
  replay.

## 18. Exact-output equivalence

- **Tests:**
  - on random synthetic rows (duplicates, unknown victim side, exclusions; 3 keep filters;
    6 cutoff/since combinations), the preloaded and lazy indexes return identical
    prior-victim, prior-payer and transaction-victim sets;
  - an out-of-set query raises;
  - the synthetic end-to-end study gives an identical report in both modes.
- **Real data:** `exactness.json` records that every key of the saved Phase 12.1 report,
  apart from timing fields, is identical. The post-hoc recency-gap diagnostic is identical
  too.

## 19. Positive findings

1. Recency is not explained by the source's documented confirmation rule, applied
   symmetrically (H1, attenuation 0.2%). It also survives the stricter, selective reading.
2. Recency survives:
   - symmetric 30-, 90- and 180-day lookbacks;
   - removal of immediate copies;
   - every year, k bin, victim-activity tertile, newest-candidate-age bin and token class;
   - ±7-day timestamp noise.
3. Recency ordering of the production detector's own warnings, within severity tiers,
   improves on similarity ordering on the archive replay (H2). It ranks the paid recipient
   first in 3 of 3 rankable recorded incidents (descriptive).
4. The research pipeline is about 45× faster, with exactly reproduced results.

## 20. Negative findings

1. **No independent validation is possible with local data.** All archive evidence comes
   from previously examined episodes.
2. The external check has only 3 rankable incidents, too few for inference.
3. The severity-first operational ordering loses about a quarter of the retrospective
   advantage (0.502 against 0.685).
4. The ranking is almost entirely about spoofed-transfer poisoning. The tiny-transfer
   stratum has 40 episodes, and the others have fewer than 3.
5. The negative control is not cleanly null. Its anomaly is explained only in part.

## 21. Unresolved methodological issues

- **How payoff candidates were first flagged.** The source flagged unconfirmed payoff
  candidates before confirming them, and that step is undocumented. If it favoured
  lookalikes that planted recently, recency would be partly built in at a stage these data
  cannot see.
- **NC in "other" tokens** (§9).
- **Mechanism.** "The victim copies the newest matching history entry" is consistent with
  the data but untested. No interface or behavioural data exist.
- **O-arch fidelity.** Signers are unknown, values are only zero or nonzero, and in-block
  order is arbitrary. Production warnings on a live wallet could differ.

## 22. Production safety

- Since `3153dcf`, there are no changes under `detectors/`, `services/` or `risk/`.
- `warning_rank` is not imported by the API, services or CLI scoring paths.
- There is no new dependency and no model artifact. A rule-based scorer needs neither.
- No warning is suppressed, re-tiered or modified; tests enforce this.
- The frozen cohorts pass `ml verify-research`: 60 + 35 items, with selection and
  evidence hashes unchanged.

## 23. Reproducibility

```bash
uv run --offline cryptoguard ml lookalike-study --out data/ml/research/phase12.2/lookalike-study-preloaded.json
```

```bash
uv run --offline cryptoguard ml recency-validation
```

- The inputs are the hash-verified local archive and the derived databases. Their hashes
  are checked by `ml verify-research`.
- The seeds are fixed: 20261102 for Phase 12.1 and 20261103 for Phase 12.2.

## 24. Data and licensing constraints

- **Tsuchiya et al. data (CC BY-NC-ND 4.0):** stays local. Only aggregates are committed.
- **Poison-Hunter and PTXPhish:** have no licence, so nothing derived from them is
  committed.
- **Not committed:** row-level records, frozen review material and answer keys.

## 25. Recommended next experiment

Pre-register and run recency on the archive's **13,683 unconfirmed payoff rows**:
- Their victims are disjoint from the study, apart from 143 rows.
- They were never examined.
- They were *not* subjected to the confirmation step.

**What it tests.** If recency also orders lookalikes there, the confirmation step is ruled
out as its cause, and with it the documented selection mechanism. If recency is much
weaker there, the confirmation step is implicated.

**Limitations:**
- the labels are uncertain by the source's own account, so results must be reported per
  confirmation status;
- it is the same collection, so it still is not independent of the source's flagging
  rules.

**Cost:**
- two offline archive passes, about 2 hours on this disk, under 512 MiB;
- 0 RPC requests, no download;
- then the preloaded study, about 5 minutes.

A genuinely independent test needs **newly recorded incidents**. That requires an approved
RPC budget, or the BSC payoff file, which requires download approval.

## Research output table

| Analysis | Population | Episodes (groups) | Cutoff | Candidate set | Baseline | New | Difference [95% CI] | Status | Main bias limitation | Runtime |
|---|---|---|---|---|---|---|---|---|---|---|
| Phase 12.1 primary | R test | 428 (427) | T − 1 | source plantings | B0 0.300 | T0 0.618 | +0.318 [0.262, 0.372] | source-conditional retrospective result | outcome seen; source-defined | 179 s (rerun) |
| H1 | R-SR (SR_any) | 1,059 (1,050) | T − 1 | source plantings satisfying SR | B0 0.300 | T0 0.682 | +0.382 [0.347, 0.417] | exploratory sensitivity analysis (pre-registered) | re-examined data; SR barely selective | 38 s (all of 12.2) |
| H1, SR_latest | R-SR | 910 (901) | T − 1 | stricter SR | B0 0.332 | T0 0.671 | +0.339 [0.300, 0.379] | exploratory sensitivity analysis | re-examined data | — |
| H2 | O-arch | 1,057 (1,049) | T − 1 | production warnings | OP0 0.267 | OP1 0.502 | +0.235 [0.208, 0.263] | operational replay diagnostic | source-selected stream, no signers | 13 s |
| H3 | X-inc | 3 rankable | harm − 1 | production warnings, recorded streams | OP0: 1/3 first | OP1: 3/3 first | — | external source, descriptive (n = 3) | tiny n; detector developed on these fixtures | < 1 s |
| E14 | P2 | 9 windows | window end | production warnings | — | — | warning set preserved 9/9 | operational diagnostic | no labels | 8 ms |
| Independent validation | — | — | — | — | — | — | — | **unsupported due to missing data** | — | — |

## Decision gates

| Gate | Status | Evidence |
|---|---|---|
| A. Source independence | **BLOCKED BY DATA** | no untouched outcome population (§4); 3 rankable incidents only |
| B. Temporal correctness | PASS WITH LIMITATIONS | everything at or before the cutoff, tested; archive candidate sets are source-defined |
| C. Selection-bias control | PASS WITH LIMITATIONS | symmetric extraction, warning generation and confirmation rule; the source's upstream flagging is unobservable |
| D. Negative-control validity | PASS WITH LIMITATIONS | E1 at random, E2 far below; NC anomaly mostly explained by token-class mixing and its correlation with recency |
| E. Recency robustness | PASS | every pre-registered sensitivity analysis keeps T0 at least 0.17 above B0 |
| F. Statistical adequacy | PASS WITH LIMITATIONS | grouped paired inference with Holm; but re-examined data, one source |
| G. Operational relevance | PASS WITH LIMITATIONS | operates on production warnings; archive replay is approximate; incidents n = 3 |
| H. Engineering efficiency | PASS | 179 s (from 8,157 s), 485 MiB; Phase 12.2 in 38 s |
| I. Production isolation | PASS | no production change; ranker isolated, tested non-suppressing |
| J. Reproducibility | PASS WITH LIMITATIONS | regenerable from hash-verified local inputs; the data cannot be redistributed |
