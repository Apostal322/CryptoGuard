# ML-driven candidate discovery and evidence-aware ranking (Phase 12.5)

| Item | Value |
|---|---|
| Protocol (frozen before any new outcome) | [`docs/ml/protocol-12.5.md`](docs/ml/protocol-12.5.md), `16586a5` |
| Code (committed before the outcome run) | `0dd8a23`; performance fix `8fbc3a1` (outputs identical) |
| Study output (git-ignored) | `data/ml/research/phase12.5/candidate-research.json` (`cryptoguard ml candidate-research`) |
| RPC requests / downloads | **0** / none |

## 1. Executive summary

**Does machine learning add information beyond complete observations and transparent deterministic rules? On the data available, no.** The results:
- **Primary pre-registered ML test (RQ8): not supported.** It predicts a victim's next planting mechanism from their planting history, on 1,067 archive episodes, as a self-supervised proxy task.
  - A fixed logistic regression is far worse than simple baselines on test log loss: **1.945** against **0.200** for the victim-prefix frequency.
  - The reason is temporal covariate shift. Later campaigns plant far more intensively: the 90th-percentile planting history is 2,481 in test against 163 in training, and the model's count features extrapolate.
  - Its macro-F1 is higher (0.323 against 0.284), so some minority-class structure is learnable, but it is not calibrated under shift.
- **Exploratory semantics (RQ2): no gain.** Ranking by the semantic channel of the latest planting changes top-1 by **−0.009** [−0.022, +0.005] against recency, on 640 development episodes in 632 groups. Recency reproduces Phase 12.1's development score exactly (0.730).
- **Temporal anomaly (H3a): analytically null, as predicted.** A median/MAD-normalized recency orders candidates identically to recency in 1,056 of 1,056 definable episodes.
- **The two development cases disagree.** Recency puts the later-paid address 2nd of 6 in the pilot and **3rd of 3** in the native-dust case. Similarity puts it 1st there but 5.5th of 6 in the pilot. No ordering is consistent on n = 2. This is descriptive, not evidence.
- **Engineering.** The feature schema and an offline shadow ranking exist. A **quadratic-scan defect** was found and fixed: ranking 1,000 flood candidates went from 424 s to 0.27–2.2 s, with identical outputs.
- **Robustness.** Losing transaction-signer information removes every spoofed-transfer candidate. Signer lookups are a critical observation, not an optional feature.

**Classification:**
- a negative ML finding (RQ8, RQ2, H3a);
- a source-dependent result (recency);
- a confirmed candidate-discovery improvement on controlled tasks (C1/C2, re-verified);
- blocked by data for wallet-centric ML: there are no labels and only 3 real recordings.

## 2. Research hypotheses

Defined in the protocol (§2): RQ1–RQ8.

- **Primary test:** H8 (§4 of the protocol).
- **Exploratory:** RQ2 and H3a.
- **Not re-run:** archive ranking (Phase 12.1 answered it, and its test split is used) and graph models (12.1 null).

## 3. Data audit, and 4. research populations

| Population | Source | Size | Labels | Use |
|---|---|---|---|---|
| P1 | synthetic fixtures | tests | oracle, by construction | correctness, coverage, robustness, cost |
| P2 | 4 packaged incident fixtures | 4 windows | known outcome | **excluded** (frozen Cohort B overlap) |
| P3 | 2 Level I cases: `observation/1` ×2, plus the blind `observation/2` replay of one | 3 recordings, 2 wallets | known outcome | development description only |
| P4 | Tsuchiya archive subset (`archive_subset.sqlite`, 146 MB; CC BY-NC-ND, local only) | 1,068 payoff episodes → **1,067** after protected-overlap removal; 1,058 linkage groups; development 640 / test 427 (12.1 split) | the source's payoff confirmation, plus mechanism flags (source heuristics) | RQ8 primary; RQ2 exploratory |
| P5 | background windows, `observation/1` | 9; **6 eligible** (3 hold frozen items) | none (unlabelled) | volume |
| Reference only | Poison-Hunter ground truth | 5,890 addresses | — | overlap checks |

**These populations are never pooled.** P4 is source-selected: every candidate is a source-flagged planting toward a victim who later paid. P5 and P3 are wallet-centric recordings. P5 has no native observations, so it cannot estimate native volume.

## 5. Observation completeness

| Recording | Schema | Native inbound | ERC-721 | Internal |
|---|---|---|---|---|
| 6 P5 + 2 P3 (`observation/1`) | `observation/1` | not collected | not collected | unsupported |
| blind replay (P3) | `observation/2` | complete (2 transfers) | complete (0) | unsupported |

Only **one** real `observation/2` window exists.

## 6. Protected data exclusions

- **Cohorts:** the Cohort A and B sheet and key hashes are unchanged: `a0ec4b6e…`, `407b412f…`, `121c112d…`, `f333386d…`, with files untouched since 2026-11-02.
- **Archive:** episodes of the 60 review wallets are removed, plus **1 more** that shares an entity or linkage group with a frozen item.
- **Background:** 3 P5 windows are excluded (`touches_frozen_any`).
- **Cohort data:** no cohort file or answer key was read.

## 7. Candidate-generation baselines

| Variant | Definition |
|---|---|
| C0 | the frozen `candidates/2` rules |
| C1 | the same rules on every observed class |
| C2 | lookalike-gated native candidates, one per lookalike, plus abstention |

| Baseline | Definition | Phase 12.1 equivalent |
|---|---|---|
| B3 | similarity | B0 |
| B4 | recency | T0 |
| B5 | semantic channel | — |
| B6 | familiarity, i.e. recency of the reference payment | B3 |
| B7 | MAD temporal anomaly | ≡ B4 (H3a) |
| B8 | graph | G1–G3, null |

## 8. Feature definitions (`poisoning-candidate-features/1`)

Every feature is a `(value, status)` pair, with status `observed`, `zero_observed`, `unknown` or `not_applicable`. Unobserved never means zero.

| Family | Features |
|---|---|
| Address | `affix_prefix`, `affix_suffix`, `matched_references`, `reference_paid_before`, `blocks_since_reference_payment` |
| Semantics | `kind`, `channel`, `zero_value`, `signer_role` (wallet / foreign / lookalike itself / unknown), `emitter_reviewed`, `receipt_status` |
| Temporal | `first_seen_block`, `last_seen_block`, `events`, `events_last_day`, `median_interarrival` |
| Graph | `signer_reuse_in_window` (in-window only: no cross-wallet index exists for these windows) |
| Completeness | coverage of ERC-20 logs, native inbound and signers (status, never risk) |

The proxy task uses `proxy-features/1` (protocol §4).

## 9. Temporal features

- **Recency (B4/T0):** the only temporal signal with large-sample support. It is source-conditional: 12.1 test top-1 0.618 against B0's 0.300, and 0.730 on development, reproduced here.
- **H3a:** a wallet-normalized MAD score is a strictly increasing transform of recency within an episode, so it adds nothing. The check found 1,056 identical orders, 0 differing, and 11 undefined (MAD = 0).
- **The 12.1 burst, count and decay features** (T1–T4) added little beyond recency.
- **The proxy task** shows that planting *intensity* drifts strongly over time (§19).

## 10. Transaction semantics

- **Paid lookalikes:** the latest planting is `spoofed_out` for **97.0 %** (development).
- **Rivals:** the same share is **92.9 %**.
- **Result:** the channel barely separates them, and B5 adds nothing to top-1 (§20).
- **Where semantics do matter:** for **validity**. Without the signer, spoofed transfers can't be told apart from wallet payments (§23).

## 11. Graph features

Not re-run:
- Phase 12.1 found G1 at random and G2/G3 slightly below it.
- Its token negative control was anti-informative.
- Graph features cost about 1 h 47 min of HDD lookups.
- The wallet-centric data have **0** cross-wallet signer links.

**Status: blocked by data.** No new hypothesis justifies a graph model.

## 12. Unsupervised methods, 13. self-supervised feasibility, 14. PU feasibility

- **Unsupervised anomaly detection (M1):** an Isolation Forest or similar on wallet windows would score about 11 real candidates, with no labels. That answers no hypothesis, so **none was trained**. The one temporal anomaly with a defined role (MAD) is analytically equivalent to recency (H3a).
- **Self-supervised learning on wallet histories:** **blocked by data.** The eligible wallet-centric recordings hold about 100 events across 9 windows, against the protocol's threshold of 1,000. Instead, the self-supervised task ran on **attacker planting sequences** (P4: 12,803 training and 18,710 test events), which is legitimate for an event-pattern question (§19).
- **PU learning: not viable.**
  - Positives are the paid candidates, exactly one per episode, chosen by the source's payoff-confirmation rule.
  - The unlabelled set is the rival plantings.
  - The class prior is fixed by construction (1/k), not a population prior, and SCAR is violated, because labelling depends on the victim's later payment.
  - No PU risk or calibrated probability can be identified. A within-episode ranking, such as 12.1's conditional logit, is the right formulation. It did not beat recency.

## 15. Training design, and 16. evaluation protocol

**RQ8** (protocol §4):
- **Unit:** one planting with at least one planting in a strictly earlier block. Same-block predecessors are never inputs.
- **Target:** five mechanism classes.
- **Split:** 12.1's temporal group split.
- **Baselines:** global, victim-prefix and Markov, fit on training only.
- **Model:** a fixed multinomial logistic regression (standardized, C = 1, seed 20261109). No search.
- **Primary metric:** test log loss.
- **Secondary metric:** macro-F1.
- **Uncertainty:** a 95 % group-bootstrap CI over 426 test groups (2,000 draws).

## 17. Candidate coverage, and 18. candidate volume

| Window (population) | C0 events / distinct | C1 | C2 | C2 dedup | Per wallet-day (C2) |
|---|---|---|---|---|---|
| pilot (P3, `/1`) | 9 / 6 | 9 / 6 | 6 / 6 | 3 | 2.0 |
| Scam Sniffer (P3, `/1`, frozen) | 2 / 2 | 2 / 2 | 2 / 2 | 0 | 0.67 |
| Scam Sniffer blind (P3, `/2`) | 2 / 2 | **3 / 3** | 3 / 3 | 0 | 1.0 |
| 6 × P5 (`/1`) | 0 | 0 | 0 | 0 | 0 (2 windows abstain: no reference) |

**Synthetic (P1):**
- C1 recovers native-dust and ERC-721 lookalikes that C0 can't see.
- A flood of 10,000 zero-value strangers plus 1,000 lookalikes gives C1 11,000 events and **C2 1,000** (one per lookalike).

**Native volume on unlabelled wallets is unknown:** P5 is `observation/1`. These counts are not a false-positive rate.

## 19. Temporal experiments: RQ8 results (primary, pre-registered)

Test split: 18,710 events, 426 groups. Training: 12,803 events, 631 groups.

| Method | Test log loss | Macro-F1 | Recall: spoofed / tiny / counterfeit / zero |
|---|---|---|---|
| Global frequency | 0.2146 | 0.245 | 1.00 / 0 / 0 / 0 |
| Victim-prefix frequency | **0.1997** | 0.284 | 0.999 / 0 / 0.108 / 0 |
| Markov (last class) | 0.2005 | 0.245 | 1.00 / 0 / 0 / 0 |
| Logistic regression | **1.9451** | **0.323** | 0.796 / 0.446 / 0.118 / 0 |

- **LR minus the best baseline:** **+1.745** [−0.021, +3.837]. That is far worse on the point estimate. The decision rule requires a lower loss than every baseline, with the CI excluding 0. **H8 is not supported.**
- **Class balance:** `spoofed_out` is 96 % of events (17,931 of 18,710 in test).

**Post-hoc diagnostic** (exploratory; it does not change the decision):
- **Median LR loss:** 0.021.
- **The tail:** 3,242 test rows with loss above 5 carry **91 %** of the total loss, and 3,084 of them are `spoofed_out` predicted as a minority class.
- **Covariate shift:** prefix length at p50 / p90 / p99 is 28 / 163 / 320 in training against **60 / 2,481 / 4,165** in test. 4,207 test rows exceed the longest training prefix.
- **Interpretation:** planting intensity grew sharply over time, and unbounded count features extrapolate. Robust frequency statistics are the better choice under this shift.

## 20. Semantic experiments: RQ2 (exploratory, development split only)

| | Top-1 (640 episodes, 632 groups) |
|---|---|
| T0 recency | 0.730 (identical to 12.1's development figure) |
| B5 channel, then recency | 0.720 |
| B5 − T0 | **−0.009** [−0.022, +0.005] |

The semantic channel adds no ranking information beyond recency.

## 21. Graph experiments

None. See §11.

## 22. Model comparisons

The only trained model is RQ8's logistic regression. It loses to the victim-prefix frequency baseline on the primary metric, and wins only on macro-F1.

**Phase 12.1's conditional logit** did not beat recency either. No learned ranking is justified on the available labels.

**Development-case ranks** (C2 candidates; descriptive, outcome known):

| Case | Candidates | B3 similarity | B4 recency | B5 channel | B6 familiarity |
|---|---|---|---|---|---|
| pilot (`/1`) | 6 | 5.5 | **2** | 2 | 1.5 |
| Scam Sniffer blind (`/2`) | 3 | **1** | 3 | 3 | 3 |
| Scam Sniffer frozen (`/1`) | 2 | paid not observable | — | — | — |

## 23. Robustness (C2; controlled information loss)

Each cell shows candidates kept / removed / added.

| Transform | pilot (6) | Scam Sniffer `/1` (2) | Scam Sniffer blind `/2` (3) |
|---|---|---|---|
| no native | 6/0/0 | 2/0/0 | 2/**1**/0 (the paid lookalike is lost) |
| signer unknown | 4/**2**/0, abstains | 0/**2**/0 | 1/**2**/0 |
| last day only | 6/0/0 | 2/0/0 | 3/0/0 |
| no reference history | 6/0/0, abstains | 2/0/0, abstains | 2/1/0, abstains |
| receipts unknown | 6/0/0 | 2/0/0 | 3/0/0 |

**No transform ever adds a candidate:** no evidence is invented. Without references, C2 abstains, and it says history before the window is unobserved. **Signer loss is the most damaging gap.**

## 24. Source-shift diagnostics, and 25. negative controls

- **Within P4:**
  - mechanism shares are stable (96 % spoofed in both splits);
  - planting intensity shifts strongly across time;
  - recency holds across years in 12.1's strata.
- **Across populations:** wallet-centric candidates number 11, so no feature-distribution test is meaningful.
- **12.1's negative controls** still apply: the within-episode G1 shuffle sits at random, and the token control is anti-informative.
- **The public-token-reuse control:** a shared token contract never links wallets. The synthetic case J test passes.

## 26. Ablations

- **Proxy model:** ablations are meaningless here. It already loses to frequency baselines, and dropping features can't make it valid.
- **Ranking ablations:** 12.1's apply. Removing any non-temporal component improved its hybrid.
- **The informative ablation here is observational:** removing native observations or signers removes candidates (§23).

## 27. Operational cost

| Step | Wall | Peak |
|---|---|---|
| Archive episode cache, built once | 279 s | 86 MiB RSS (disk-bound) |
| Full study rerun (cache present) | **27 s** | 336 MiB RSS |
| Proxy task (training plus evaluation) | 20 s | — |
| Flood: C1 / C2 / ranking, 11,000 observations | 0.73 / 0.64 / 2.2 s | ≤ 12 MiB traced |
| Shadow ranking before the fix | 424 s | — |

## 28. Statistical uncertainty

- **RQ8:** a group bootstrap over 426 test groups.
- **RQ2:** a group bootstrap over 632 development groups.
- **Development cases:** n = 2, exact ranks only, and no inference.
- **Multiple comparisons:** there is one primary test, H8. Everything else is labelled exploratory.

## 29. Production isolation

**Unchanged:** the detector, the risk engine and C0. Detector output is byte-identical (tests).

**The shadow ranking `poisoning-candidate-ranking/1`:**
- runs only through `cryptoguard ml candidate-ranking`, a research CLI;
- is never called by the scanner;
- carries no probability, severity, suppression or deletion.

## 30. Reproducibility

`cryptoguard ml candidate-research [--rebuild-cache]` regenerates everything from local artifacts. Its output records:
- the git SHA, the protocol and the seed;
- the episode-cache SHA-256 (`c0fa1f6f…`);
- the versions of every component;
- the step timings and peak RSS.

**Required local inputs:** `data/ml/poisoning/archive_subset.sqlite` and `archive_targets.json` (CC BY-NC-ND, never committed), the review sheets, which are used only to exclude entities, and the fixtures. If any is absent, the command fails and names it. There are no downloads and no RPC.

## 31. Tests and CI

| Check | Command | Result |
|---|---|---|
| Lint | `uv run ruff check .` | clean |
| Format | `uv run ruff format --check .` | 286 files formatted |
| Types | `uv run mypy src` | clean (151 files) |
| Tests | `uv run pytest -q` | **924 passed**, 4 deselected (`gpu`/`slow`), 0 failed, 0 skipped |

There are 15 new tests in `tests/test_ml_candidate_research.py`. The CI run is recorded in the PR #1 description.

## 32. Positive findings

1. The C1/C2 coverage gains and C2's volume bound hold on controlled cases, and on the one real `observation/2` window.
2. The features never turn unobserved data into zeros, and they are point-in-time correct under metamorphic tests.
3. The quadratic-scan defect is fixed, about 200× faster with identical outputs.
4. Recency's development score reproduces exactly (0.730).

## 33. Negative findings

1. H8 is not supported: the learned model is far worse than frequency baselines under temporal shift.
2. The semantic channel adds no ranking information.
3. The temporal anomaly is equivalent to recency.
4. No learned ranker is justified.
5. Recency, the strongest archive signal, fails on the one native-dust development case.

## 34. Unsupported claims (none made)

**Not claimed:**
- any precision, recall, false-positive rate or theft-prevention rate;
- any calibrated probability;
- ML superiority over production;
- generalization of recency to wallet-centric `observation/2` data.

## 35. Remaining data requirements

1. **Untouched incidents**, recorded blind with `observation/2` from the start: at least 10, with harm-transaction hashes from public write-ups.
2. **`observation/2` background windows**, for unlabelled native volume under C2.
3. **Independent labels** for rival candidates, which would require human review of the frozen cohorts. None has been submitted.

## 36. Recommended next experiment

**Question:** on untouched `observation/2` incident windows, does recency (B4) put the later-paid lookalike first more often than similarity (B3)?

| Element | Specification |
|---|---|
| Data | At least 10 untouched incidents, user-sourced, each with a harm-transaction hash, recorded with `replay record-window --observation 2` |
| Labels | The paid address, taken from the harm transaction and used only to score |
| Cost | About 700–1,300 RPC requests per window (measured 703, plus rate-limit retries). A cap of about 15,000 for 10 windows. Offline analysis takes seconds. |
| Pre-registration | Before any recording. A cluster-level sign test (amendment 12.3-A1). |
| Falsification | B3 better than B4 in more planting-signer clusters than worse. Under the pre-registered rule, B4 not better in at least 6 untied clusters. |

Phase 12.6 is not started.

## Decision gates

| Gate | Status | Evidence |
|---|---|---|
| A. Data quality | PASS WITH LIMITATIONS | Exact inventory (§3). P4 is source-selected, P5 has no native data, and P3 is n = 2. |
| B. Observation correctness | PASS WITH LIMITATIONS | Phase 12.4 audit and tests, plus 1 real blind `observation/2` window |
| C. Candidate coverage | PASS WITH LIMITATIONS | Synthetic mechanisms, plus 1 real development case: C1 recovers the native-dust lookalike |
| D. Candidate-volume control | PASS WITH LIMITATIONS | Synthetic flood bounded by distinct lookalikes (§18). Real native volume unknown. |
| E. Temporal research | PASS WITH LIMITATIONS | Recency is informative, but source-conditional (12.1). No new temporal method adds information (H3a; RQ8). |
| F. Semantic research | FAIL (ranking) | B5 − T0 = −0.009 [−0.022, +0.005]. Semantics are needed for candidate validity (signer), not for ranking. |
| G. Graph research | BLOCKED BY DATA | 12.1 null; 0 wallet-centric links |
| H. ML validity | PASS | RQ8 is a properly specified proxy with a temporal group split, fixed model and baselines. The result is negative. |
| I. Missingness robustness | PASS | Transforms never add candidates. Abstentions and unknown statuses, never zeros (§23, §8). |
| J. Generalization | FAIL | The proxy model breaks under temporal shift, and recency fails on the native-dust development case |
| K. Production isolation | PASS | Detector and C0 unchanged. Shadow ranking reachable only through the research CLI. |
| L. Reproducibility | PASS | One command from local artifacts, with hashes, seed and versions (§30) |
