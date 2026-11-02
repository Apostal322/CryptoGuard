# Hard-negative study (Phase 11.5)

Status: **offline groundwork done; nothing is labelled.**
- 8,877 hard-negative *candidates* were extracted and screened.
- A 35-item review cohort is frozen.
- No human has reviewed it.
- No model was trained. 0 RPC requests. 0 downloads.

Generated numbers: [ML_HARD_NEGATIVE_TABLES.md](ML_HARD_NEGATIVE_TABLES.md). Regenerate with:

```bash
cryptoguard ml hard-negative-extract   # two offline passes over the local archive (~50 min)
cryptoguard ml hard-negative-study     # pool, screen, matching, diagnostics, cohort (~2 min)
cryptoguard ml inventory               # hashes and provenance of every local data file
```

## 1. Executive summary

- **The question.** Can CryptoGuard tell real address-poisoning attempts from legitimate
  activity that looks like poisoning, using only information available before harm? It
  cannot be answered yet, because no independently labelled legitimate example exists.
- **What exists now:**
  - a reproducible candidate pool;
  - a screen that removes known attacks;
  - a matching design;
  - a frozen, blinded review cohort;
  - evaluation code that refuses unsupported metrics.
- **Finding 1: "uncategorized" is not "benign".** The archive's 8,651 uncategorized
  lookalike transfers are the closest local frame to legitimate look-alike activity.
  **3,632 of them (42%) overlap known attacks:**
  - 2,136 share the victim and the lookalike with a source-labelled attempt;
  - 1,495 come from a lookalike known as an attacker elsewhere;
  - 1 is the same event.
- **Finding 2: naive negatives would be a shortcut.** Source positives and archive
  candidates are separable by data source alone:
  - transfer value separates them perfectly (AUC 1.000);
  - direction alone gives 0.982;
  - everything except value gives 0.993.

  The source defined its categories by these very covariates. Training on them would
  learn the source's rules, not malice (hypothesis H5).
- **Finding 3: strict matching finds almost no support.** Matching on transaction shape
  pairs only 17 of 1,409 positives. Matching on period and similarity alone pairs 806.
  "Hard negatives that look like positives" barely exist in this archive, by
  construction.
- **Random wallets.** On 9 randomly drawn recorded wallets (27 wallet-days), the generator
  emits 8 candidates (296 per 1,000 wallet-days, unlabeled). Most look like real
  fake-token spoofs rather than legitimate activity.

## 2. Scientific objectives

| Hypothesis | Testable now? | What this phase adds |
|---|---|---|
| H1 Similarity alone is insufficient | no (needs labels) | 8,651 similarity-matched, uncategorized transfers across 4,190 wallets, 42% attack-linked: a frame in which to test it |
| H2 Wallet history helps | no | history exists only for the recorded windows (226 candidates) |
| H3 Transaction semantics matter | descriptively | categories A-H; frames differ sharply by value, token and direction |
| H4 Graph context helps | no | typed grouping and contamination edges give the needed relations |
| H5 Hard negatives are necessary | **supported descriptively** | separability diagnostics (§19): naive negatives are trivially separable |

## 3. Existing data inventory

- **Coverage.** `cryptoguard ml inventory` hashes and describes every file under `data/`
  and the recorded fixtures (`data/ml/inventory.json`, local).
- **Provenance.** Every file maps to a declared source, and no file is unregistered.

| Source | Files (examples) | Records | Licence | Redistributable | Label status |
|---|---|---|---|---|---|
| Tsuchiya et al. 2025 | `address_poisoning_ethereum.sql.gz` (2,316,354,530 B, SHA-256 `270211ac…`), payoff CSV (1,738) | 34,905,969 rows | CC BY-NC-ND 4.0 | no | source heuristics |
| Poison-Hunter sample | `phishing_transfers_sample.csv` | 150 (149 valid) | none published | no | source detections (weak) |
| PTXPhish | `PTXPHISH.xlsx` | 18,555 transactions | none published | no | separate task (Track A) |
| Forta labels | 3 CSVs | 15,259 | per its LICENSE | per licence | address labels, separate task |
| Recorded incident fixtures | 4 `fixture.json` (committed) | 411 transfers | public chain data | yes | case studies (used in development) |
| Recorded background wallets | 9 `fixture.json` (committed) | 27 wallet-days | public chain data | yes | `unlabelled_background` |
| Derived (local) | archive subset, context subset, review cohorts | 301,370 / 210,478 rows | derived from CC BY-NC-ND | no | source-derived / unlabeled |

- **Missing:** none of the files the docs mention. The Phase 11 pilot's three cost-phase
  wallet-days were lost earlier (ML_PILOT_AUDIT.md §4).

## 4. Candidate-generation rules (`candidates/2`)

**Audit findings:**
- **Inputs.** Recorded transfers and wallet transactions only. No production findings, no
  labels, no scores.
- **Rules.** `zero_value_in`, `spoofed_out`, `lookalike_in` (6 or more prefix+suffix
  characters, of which at least 3 suffix), `untrusted_token_in`, `dust_in`.
- **Cutoff.** Strictly earlier positions only; no future information.
- **Dependence on the source.** The generator's lookalike rule is looser than the source's
  3+4 rule. The source rule is a subset of it (ML_CROSS_DATASET_VALIDATION.md §16).

**Changes:**

| ID | Pri | Finding | Fix |
|---|---|---|---|
| 31 | P2 | **Unverified choices.** `candidates/1` counted outgoing transfers with an *unknown* signer as counterparties the wallet chose. Under partial coverage, a spoofed transfer to a lookalike could become the "imitated" address | `candidates/2` requires a verified wallet signature. No recorded transfer has an unknown signer, so the output on all 13 windows is identical (tested), and ML_POISONING_TABLES.md is unchanged |
| 32 | P2 | **Quadratic scan.** The history was rescanned per transfer | Single forward pass; a property test checks equality with the per-transfer definition on 30 random fixtures |

**Documented breadth (not defects):**
- `spoofed_out` also fires on legitimate pulls by an approved spender: routers, Permit2,
  settlement contracts.
- `dust_in` fires on genuine small test payments.
- A reverted ETH send still counts as a chosen counterparty, because it appears in the
  wallet's history.
- Duplicate logs get distinct identities (the log index is part of the identity).

All of these are tested.

## 5. Candidate eligibility

- **What enters the frame.** Every candidate enters the pool. The review frame excludes
  only `known_positive_overlap` (§7).
- **Potential overlaps stay in**, as their own stratum.
- **No candidate was dropped for being hard.**

## 6. Source overlap

| Known-positive source | Records indexed |
|---|---|
| Tsuchiya archive (poisoning rows touching the targets) | 198,903 |
| Tsuchiya archive, unconfirmed payoffs | 1,113 |
| Tsuchiya payoffs | 1,738 |
| Poison-Hunter | 149 |
| Incidents | 4 |

- **Coverage counts only where absence means something.** Only the archive is chain-wide
  for its block range (15,053,226–20,208,032). Poison-Hunter is a sample and the incidents
  are single cases: they can confirm an overlap, never vouch for its absence.
- **Consequence.** A candidate outside the archive range is `insufficient_information`,
  not "no known overlap".

## 7. Positive contamination

**Match levels** (`ml/contamination.py`), strongest first:
1. exact event;
2. exact transaction;
3. same victim and lookalike;
4. shared attack infrastructure: a known lookalike, or a counterfeit token contract;
5. related campaign: the same victim and the same imitated counterparty;
6. weak similarity;
7. none.

| Frame | Known positive | Potential | No known overlap | Insufficient information |
|---|---|---|---|---|
| archive uncategorized (8,651) | **3,632** (exact event 1, victim–lookalike 2,136, shared infrastructure 1,495) | 79 | 4,940 | 0 |
| recorded incident wallets (218) | 13 (victim–lookalike) | 32 | 168 | 5 |
| recorded background wallets (8) | 0 | 0 | 0 | 8 (2026 blocks: no chain-wide screen) |

- **Known-positive overlaps** (3,645) are excluded from review and from any future negative
  set.
- **Potential overlaps** (111) are kept as a stratum.
- **"No known overlap" and "insufficient information"** are not benign.
- **A common token never counts as infrastructure:** shared USDT is not an overlap (tested).

## 8. Hard-negative candidate categories

The categories are structural, multi-label and never labels:

| Category | Archive (8,651) | Background (8) | Incident wallets (218) |
|---|---|---|---|
| A lookalike, genuine token, ordinary value | 8,651 | 0 | 1 |
| B first-time counterparty in the window | n/a (no history) | 6 | 35 |
| C low value | 0 | 0 | 3 |
| D token ambiguity (zero-value genuine, or untrusted token) | 0 | 8 | 46 |
| E moved out by a transaction the wallet did not sign | 0 | 7 | 213 |
| F signed by public infrastructure | 0 | 0 | 0 |
| G incomplete observation | 8,651 | 0 | 0 |
| H within one character of the similarity threshold | 6,070 | 2 | 5 |

- **Category F is empty.** No recorded candidate was signed by a listed router.
- **Category E is not mostly spoofs.** 168 of its 213 incident candidates are non-zero,
  genuine-token transfers out of the WBTC victim's wallet, in transactions it did not
  sign (33 distinct signers in all). That is the shape of approved-spender pulls such as
  solver-settled swaps.
  - They are the most plausible *legitimate* look-alikes in the local data, and the cohort
    samples from them.
  - The rest of E is zero-value or untrusted-token spoofs (45).
- **Background candidates have attack shapes.** 7 of the 8 are attack-shaped: 6
  untrusted-token spoofs and 1 zero-value `transferFrom` spoof.
- **The WBTC wallet dominates** the incident frame: 169 of its 218 candidates.

## 9. Matching design

**Method.** Coarsened exact matching (`cem/1`), 1:1, deterministic keyed-hash order,
explicit unmatched units.
- **Positives:** the 1,409 payoff-linked source positives, excluding the 60 reserved review
  items.
- **Candidates:** the 5,019 archive candidates not known to overlap a positive.

| Design | Keys | Matched positives | Candidates without support |
|---|---|---|---|
| strict | year, direction, token class, value bin, similarity bin | **17** | 1,121 |
| relaxed | year, similarity bin | 806 | 0 |

**Balance before matching** (standardized mean difference):

| Covariate | SMD |
|---|---|
| victim sends (direction) | 7.22 |
| log value | −6.13 (745 positives have no USD value) |
| block | −2.48 |
| token class | −1.51 |
| similarity | 0.48 |

**Reading.**
- Strict matching fails by design. The source's categories (zero, tiny, counterfeit) are
  the shape covariates, so its positives and its uncategorized rows almost never share a
  cell.
- Relaxed matching balances period and similarity, but not shape.
- Neither yields negatives. They show which comparisons the data can support. Outcomes,
  labels and scores are refused as covariates by name (tested).

## 10. Historical feature availability

| Frame | Wallet history | Features available |
|---|---|---|
| recorded windows (226) | complete within a 21,600-block window; earlier history not recorded | all `event-features/1` |
| archive (8,651) | none (the archive keeps only source-selected rows) | similarity, value, token, block only |

**Point-in-time guarantees, all tested:**
- future events, losses, labels and same-block later transactions do not change past
  features;
- input order does not matter;
- unknown history is `partial`/`unavailable`, never zero;
- known-empty history gives real zeros.

The contract keeps missing values as `None` with a `missing` list. Features may not carry
label, outcome, payoff or score fields (`ml/evaluation.py`).

## 11. Sampling frame

- **Eligible frame:** 5,232 items in 2,664 typed groups.
  - Archive frame: one representative per typed campaign group (victim, lookalike, tx,
    signer, imitated and counterfeit-token edges).
  - Recorded-wallet frames: one stratum per wallet, with victim edges excluded (the wallet
    is already the stratum).
- **Typed grouping never links through USDT, USDC, DAI or a listed router** (tested with
  the cases the brief lists).

## 12. Frozen candidate sample (`hard-negative-candidates/1`)

**Design** (fixed before the draw):
- 24 items from the archive frame, allocated across period × potential-overlap strata;
- 2 per recorded wallet;
- seed `cryptoguard-hard-negative-candidates/1`.

**Result:** 35 items:
- 24 from the archive;
- 3 from background wallets;
- 8 from incident wallets.

| Item | SHA-256 |
|---|---|
| eligible frame | `881f2faebdf3669d659cfb2a3fbbd87f27a50cd71e92c6889e34427c2ef3feea` |
| selection | `ae9df36ab99750a35e884bf487e117e1f5c99f555a2beaf5ab2f30c11f6ddb57` |
| `reviewer_sheet.jsonl` | `121c112d291e5397c378cddd2a27b2e081404aa8a57b5d73325556b7d94ca108` |
| `unblinding_key.jsonl` | `f333386d20ce327df27c2747aef317e96e030c61650f3f20b60d06f038802ad9` |
| `sample_manifest.json` | `05dc1b1679f9fdce7560ff5da1f9a869fd84c8617646410e56aa3cbce59e3868` |

- **Frozen** at commit `c68d3a4` on a clean tree. The files are local
  (`data/ml/poisoning/hard_negative/cohort_v1/`) and the hashes are registered in
  `review_sample.COHORTS`.
- **First draw, set aside.** It was frozen minutes earlier on an uncommitted tree. Weak-
  similarity candidates outside the screened block range were then marked "no known
  overlap" instead of "insufficient information" (3 items).
  - It was set aside to `superseded/cohort_v1_first_draw/` before any package was issued.
  - The redraw selected **the same 35 items**, and the reviewer sheet is byte-identical.
    Only the answer key's screening statuses changed.
- **"2024" in the strata names means "2024 or later".** The year boundaries stop at 2024.
- **The Phase 11.4 sample is unchanged:** all five hashes re-verified.

## 13. Human-review protocol

- **Same rules as the first sample:** the protocol (with amendment 1) and the review app
  are reused.
- **What reviewers see:**
  - a neutral title, "Candidate for independent security review";
  - a coverage note;
  - for recorded wallets, the last 25 pre-cutoff observations.
- **What they never see:** the frame, categories, screening result, cohort name or any
  score. The package's info file names no cohort; the server identifies it by the sheet's
  hash.
- **Every decision stays possible**, including "confirmed poisoning attempt".
- **Primary quantity:** the share of items both reviewers mark
  `confirmed_legitimate_interaction`, design-weighted within the frame. The attempt
  share and agreement are also reported (`ub.analyse`).

## 14. Label validity

| Have | Status |
|---|---|
| Independent human labels | **0** |
| Candidates | `unlabeled_candidate` |
| Overlaps | known-positive, used only to exclude |

Nothing here is a negative.

## 15. Statistical limitations

- **Small cohort.** 35 items across 14 strata. Several recorded-wallet strata have one
  item, and archive strata carry weights up to 197.5. Archive-frame estimates will be
  wide; recorded-wallet results are case-level.
- **No population rate.** Neither frame is a random sample of Ethereum activity, so no
  population false-positive rate can follow.

## 16. Source-selection bias

- **The archive frame is the source's leftover category.** It is selected by the source's
  pipeline (lookalike rule, payoff-linked victims and their counterparties), then
  restricted to what the source did not categorize.
- **The recorded-wallet frame is not representative either.** Four of its seven wallets
  are publicly reported theft victims, and three are random wallets.
- **Consequence.** Proportions from either frame describe that frame only.

## 17. Operational candidate volume

| Measure | Value |
|---|---|
| Recorded random wallets | 9 (27.0 wallet-days) |
| Candidates | 8, on 3 of the 9 wallets |
| Rate | 296.3 per 1,000 wallet-days, unlabeled |

These are not false alerts and not an Ethereum-wide rate. `ml/evaluation.py` labels
alert-volume results as *unlabeled* or *reviewed*, and *representative* or not, and marks
prevalence scenarios as hypothetical.

## 18. Model-evaluation design

**Ready:** `ml/evaluation.py`.
- The `benchmark-example/1` contract keeps seven layers apart: observation, generation,
  features, source label, human label, outcome and prediction.
- **Metrics:** precision, recall, FPR, AP, ROC-AUC, recall at an FPR budget, and precision
  at a review capacity. Candidate recall is a separate function.

**Refusals:**
- no `verified_legitimate` examples means no precision, FPR or AUC;
- weak, unknown and unlabeled examples are never negatives;
- an ineligible candidate cannot enter a split.

**Splits:** the split report checks entity overlap with the typed grouping.

**Baselines ready to plug in:** the deterministic detector (replay), the similarity rule
and the generator. Logistic regression and LightGBM only once labels exist.

## 19. Experiment results

**Source separability:** predicting which *frame* a row came from. This is not fraud
detection.

| Covariate or family | AUC |
|---|---|
| value (univariate / LR) | 1.000 / 1.000 |
| direction (victim sends) | 0.982 |
| block (time) | 0.943 |
| token class | 0.766 |
| similarity | 0.629 |
| everything except value (LR, 5-fold) | 0.993 |

The cross-validation is not grouped by campaign, so these values are optimistic. The
conclusion does not depend on that: almost every shape covariate alone nearly separates
the frames.

## 20. Negative results

- **Similarity does not separate the frames** (0.63), so it is not a shortcut here.
- **No usable hard negatives** exist under strict matching: 17 pairs.
- **The background frame looks like real attacks.** 7 of its 8 candidates have attack
  signatures, so it is a poor source of legitimate examples. The plausible legitimate
  shapes sit in one incident wallet (category E), which limits how far any result
  generalizes.
- **The pool contains no candidate with a router signer** (category F is empty), so router
  false positives cannot be studied locally.

## 21. Resource usage

| Step | Runtime | Peak RSS | Disk |
|---|---|---|---|
| Extraction pass 1 (uncategorized rows) | 734 s | 46 MiB | 4.0 MB of rows |
| Extraction pass 2 (context scan) | 2,350 s | 280 MiB | 102.5 MB SQLite (210,478 rows) |
| Study (pool, screen, matching, diagnostics, cohort) | 120 s | 418 MiB | 3.0 MB key + 0.03 MB sheet |

RPC requests: **0**. Downloads: **0**.

## 22. Data licensing

**Kept local** (git-ignored):
- the archive-derived rows, context subset, cohort key and sheet;
- the study JSON.

**Committed:** only code, tests and aggregate tables.

**Open question:** whether per-item review labels or a matched benchmark built from
CC BY-NC-ND rows would be an adaptation. It remains unresolved, so everything per-item
stays local. This is not legal advice.

## 23. Benchmark readiness

See [ML_BENCHMARK_READINESS.md](ML_BENCHMARK_READINESS.md) §8.

| Gate | Status |
|---|---|
| A candidate validity | pass |
| B historical correctness | pass for implemented features |
| C positive provenance | blocked by missing evidence |
| D negative-label validity | blocked by missing evidence |
| E source independence | pass (shortcuts identified, not resolved) |
| F leakage-safe splitting | blocked by missing evidence |
| G statistical adequacy | fail |
| H baseline comparability | blocked by missing evidence |
| I operational relevance | not yet evaluated |
| J deployment safety | pass |

**Supervised training is not justified.**

## 24. Remaining blockers

| Blocker | Kind |
|---|---|
| No independent positive review (60 frozen items) | needs human reviewers |
| No confirmed legitimate examples (35 frozen candidates) | needs human reviewers |
| No wallet history for the archive frame | historical evidence (explorer at review time; no RPC authorized) |
| CC BY-NC-ND adaptation question | restricted source data |
| 95 review items cannot support per-subtype precision claims | statistical power |
| Engineering defects | none open (one test flaked once under load, see the final report) |

## 25. Next scientific experiment

**Experiment.** Two independent human reviewers review both frozen cohorts: the 60
source positives and the 35 hard-negative candidates. They use the existing local app.
Packages: `cryptoguard ml review package --cohort … --reviewer A|B`.

**Evidence it adds:**
- the first independently reviewed positives;
- the first independently reviewed legitimate look-alikes, if any exist;
- inter-reviewer agreement on both;
- how often the generator and source frames hold real attacks.

**Cost:** 95 items × 2 reviewers at about 5 minutes each, about 16 reviewer-hours. 0 RPC
requests, no download.

**What it cannot do:** reach gate G's 30 verified negatives on its own. If fewer than 30
legitimate examples come back, the next step is a negative-only cohort drawn from the
4,940 unscreened archive candidates, using the same frozen procedure. That also needs no
RPC.
