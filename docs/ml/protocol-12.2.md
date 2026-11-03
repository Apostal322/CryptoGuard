# Phase 12.2 protocol: is the recency result a source-selection artifact?

- **Task:** `recency-validation/1`.
- **Operational scorer:** `poisoning-warning-rank/1`.
- **Written and committed before** any analysis below was computed. Phase 12.1 outputs
  (`data/ml/research/phase12.1/`, SHA-256 `94734a71…` for `lookalike-study.json`) are
  preserved and not recomputed in place.

## 0. What is already known, and what that rules out

Phase 12.1 examined the outcomes of **every** eligible archive episode: 1,068 episodes in
total, 640 in development and 428 in test. Any further analysis of these episodes is
therefore **retrospective internal sensitivity analysis**, never independent validation. A
new split or seed does not change that.

The source's documentation (`data/external/tsuchiya2025/guidance.ipynb`) describes how
payoffs were confirmed. For each candidate payoff, the authors checked whether "the
poisoning transfer exists between the intended and the payoff transfer". This rule
constrains the time of the paid lookalike's planting, and only the paid lookalike's: rivals
were never subjected to it. It alone could produce a recency advantage. Testing that is
the main purpose of this phase.

## 1. Populations and their classification

| Id | Population | Candidate set | Classification |
|---|---|---|---|
| R | the 1,068 Phase 12.1 episodes (protocol 12.1 eligibility, protected wallets excluded) | source plantings at or before c | previously examined development data |
| R-SR | R, each candidate set restricted by the symmetric confirmation rule (§3) | source plantings that satisfy SR | retrospective internal sensitivity analysis |
| O-arch | R, with the production detector run on the archive rows at or before c | production poisoning warnings | retrospective operational replay on a source-selected stream |
| X-inc | the 4 recorded incident fixtures (`replay/cases`) | production warnings from complete recorded wallet streams | external source, operational replay; n = 4, descriptive |
| P2 | recorded background windows | production warnings | operational diagnostics only; no outcome labels |
| P4 | the 95 frozen review items | — | excluded from everything |

**Ruled out as validation data:**
- the BSC payoff file: not available locally, and downloading it is not authorized;
- Poison-Hunter: 89 of its 105 in-definition rows are the same archive attempts, and it
  has no record of which lookalike was paid;
- PTXPhish: phishing transactions, with no candidate rivals;
- the archive's 13,683 unconfirmed payoff rows: their labels are uncertain by the source's
  own account, and using them would take two more full archive passes. They are listed as
  a future opportunity (§10).

## 2. Frozen scorers

**T0** is Phase 12.1 recency, `lookalike-features/1`, unchanged:
- definition: `-(c - b)`, where b is the block of the candidate's latest source planting
  to the victim at a block <= c;
- plantings are the source's zero-value, tiny and counterfeit rows between the victim and
  the candidate, in either direction;
- rows in the payoff block are excluded;
- the unit is blocks; same-block order is not used;
- ties are scored tie-averaged (`1/m`).

**B0** is the unchanged production similarity: prefix+suffix of the candidate against its
reference among the victim's own outgoing rows (Phase 12.1 §5).

**OP0, the operational baseline.** Production warnings are ordered by:
1. severity tier (critical_evidence > elevated_risk > review_recommended > informational
   > unknown);
2. then prefix+suffix, descending.

Remaining ties are tied.

**OP1, `poisoning-warning-rank/1`.** The same severity tier first, then the recency of the
warning's latest *planting* signal at or before the cutoff:
- planting signals are `zero_value_transfer`, `spoofed_outgoing_transfer` and
  `unsolicited_incoming_transfer`;
- the wallet's own sends never count;
- remaining ties are tied in the metric. The displayed order breaks them by prefix+suffix
  descending, then by address.

A warning without a planting signal has no recency basis. It is placed after the warnings
of its tier that have one, in OP0 order, and marked `no_recency_basis`. No warning is ever
removed or re-tiered.

No parameter of T0, B0, OP0 or OP1 is tuned in this phase.

## 3. The symmetric confirmation rule (SR)

For candidate l of episode e at cutoff c:
- `A(l)`: the non-null source `intended` addresses of l's plantings at or before c, other
  than l.
- `I`: the victim's source-flagged *intended* rows at or before c.

**SR_any(l)** (primary) is True when some planting p of l, with intended address a, has an
intended row i to a with `i.block < p.block`. Same-block pairs do not count, because their
order is unknown. SR_any is `None` when `A(l)` is empty, and False otherwise.

**SR_latest(l)** (sensitivity) is True when the latest planting of l is later than the
victim's latest intended row to any a in `A(l)`.

**Manipulation check** (reported first): the share of paid and of rival candidates with
SR_any True. If the paid share is far below 1, this reading of the source's rule does not
reproduce it, and H1 is reported as weakened.

**R-SR episodes:** candidates with SR_any True. An episode is eligible when the paid
candidate is among them and at least 2 remain. SR `None` candidates are excluded, and
their inclusion is a sensitivity analysis.

## 4. Hypotheses and decision rules

| Test | Population | Comparison | Null |
|---|---|---|---|
| **H1** (primary) | R-SR, all eligible episodes | top-1(T0) − top-1(B0) | recency has no advantage once rivals face the same confirmation rule |
| **H2** (secondary) | O-arch: episodes where the paid lookalike is among at least 2 production warnings | top-1(OP1) − top-1(OP0) | recency does not improve the ordering of production warnings |
| H3 (descriptive) | X-inc | the paid recipient's rank under OP0 and OP1 | none tested |

**Inference** (H1, H2):
- paired top-1 differences, clustered on the Phase 12.1 linkage groups (shared candidate
  lookalikes), computed once on all of R;
- p-values from a group sign-flip permutation, 10,000 draws;
- intervals from a group bootstrap, 2,000 draws;
- seed 20261103;
- Holm over H1 and H2.

**Decision for each test:**
- **survives:** Holm p < 0.05, the CI excludes 0, and the difference is at least 0.05;
- **explained / null:** the CI lies within ±0.05, or the difference is at most 0 with the
  CI excluding positive values above 0.05;
- **inconclusive:** otherwise.

For H1, the attenuation `(Δ_R − Δ_R-SR) / Δ_R` is also reported, where `Δ_R` is
recomputed on the same episodes.

**Phase classification:**

| Outcome | Classification |
|---|---|
| H1 survives | source-conditional retrospective effect |
| H1 explained | selection-artifact result |
| otherwise | inconclusive |

With only 4 external cases, the phase cannot be classified as independently supported.

## 5. Exploratory analyses (no confirmatory claims)

E1. **C1, within-episode permutation of T0 values** (200 seeded repeats). Expected: random.

E2. **C6, reversed time order (oldest first).** Expected: below random if recency carries
information.

E3. **C3, timing perturbation.** Planting blocks are jittered uniformly by ±1 day and
±7 days (seeded). Reported: T0 top-1.

E4. **Timestamp coarsening** to 1-day and 7-day buckets, which creates ties.

E5. **C4, token strata.**
- The token class of the paid candidate's latest planting: a public stablecoin (USDT,
  USDC, DAI) or other.
- Candidate sets restricted to candidates whose latest planting is in a public stablecoin.

E6. **C5, k bins** with group counts.

E7. **Symmetric maximum lookback** of 30, 90 and 180 days. Candidates whose latest
planting is older than the window are dropped, applied to all candidates alike.

E8. **Without immediate copies:** episodes are dropped when the paid gap is under 300
blocks, about an hour. This stratifies on an outcome attribute and is labelled so.

E9. **Strata:**
- year;
- paid subtype;
- victim activity tertile, by the number of victim outgoing rows at or before c;
- the age of the most recent candidate (under 1 hour, 1 hour to 1 day, 1 to 7 days, over
  7 days), which uses no outcome;
- the largest group's share.

E10. **Negative-control investigation:**
- NC within token class;
- the within-episode Spearman correlation of NC with T0;
- NC on episodes whose candidates' latest plantings all share one token class.

E11. **History perturbations:**
- drop each candidate's latest planting (a missed observation);
- inject exact duplicate rows;
- shuffle line order within blocks.

E12. **Errors:** a 2×2 of T0 against B0 success (top-1 = 1), with aggregate categories.

E13. **Operational coverage (O-arch):**
- the share of source candidates the production detector warns on at c, paid against
  rival;
- the share of episodes eligible for H2.

E14. **P2 diagnostics:**
- warnings and windows with at least 2 warnings;
- the share of windows whose order changes between OP0 and OP1;
- that the warning set is identical under both orders;
- runtime;
- invariance when rows after the cutoff are added.

## 6. Missing data

`None` means not observed, never 0.
- T0 is always observed in R.
- B0 abstains as in Phase 12.1.
- SR `None` excludes a candidate from R-SR.
- OP1 without a basis is handled as in §2.

Abstentions are reported per analysis.

## 7. Protected entities

- The 91 frozen wallets are excluded as episodes, and their rows never become graph
  edges.
- The overlap set (wallets, addresses under review, transactions, linkage groups) is read
  from the blinded sheets only. Overlap counts are reported, and H1 and H2 are repeated
  without overlapping episodes.
- Frozen cohort files are not modified, and their hashes are re-verified at the end.

## 8. Engineering gate: exactness before speed

Phase 12.1 spent 1 h 47 min in lazy per-address SQLite graph lookups.
- **Before any 12.2 result is produced:** a single-pass preloaded graph index must
  reproduce the saved Phase 12.1 report exactly. Every key except `resources` must be equal
  as JSON.
- **If it differs:** the optimization is not used, and the difference is investigated.
- **Profiling** (query plan, rows per lookup, time per lookup, I/O) is measured on a sample
  before the change.

## 9. Budgets

| Run | Wall time | Memory |
|---|---|---|
| Full 12.2 study | under 15 min | under 1 GB RSS |
| Graph preload | under 5 min | — |

0 RPC requests and no downloads. Outputs are aggregates under `data/ml/research/`
(git-ignored).

## 10. Limitations fixed in advance

1. R is previously examined. Nothing here is independent validation.
2. SR is our reading of a rule the source describes in one sentence, and the
   manipulation check bounds how well it reproduces it.
3. O-arch runs the production detector on a source-selected stream with no signers and
   unknown same-block order. Its warnings are not what a live wallet would have shown.
4. X-inc has 4 cases. Its results are descriptive and were not used to choose T0. The
   candidate generator and detector were, however, developed with these fixtures in view.
5. **Future validation data:**
   - the 13,683 unconfirmed archive payoffs: label-uncertain, and they need about 2 hours
     of offline passes;
   - the BSC payoff file: needs download approval;
   - newly recorded incidents: need an approved RPC budget.
