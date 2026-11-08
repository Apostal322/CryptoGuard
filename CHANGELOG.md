# Changelog

All notable changes. Versions follow semantic versioning; 0.x means interfaces may change.

## Unreleased (branch `feature/ml-pipeline`)

### Experimental machine learning (shadow mode, `ml` extra)
- Pinned, hash-verified external label sources (PTXPhish, Poison-Hunter, Forta); the two
  without a license are fetched locally, never redistributed (`aee2bf4`).
- Budgeted, resumable collection of point-in-time chain data for a deterministic
  stratified sample; validated feature table with an input-hash manifest (`aee2bf4`).
- Study window, time-ordered splits and per-account purge against reused attacker
  infrastructure; trivial, rule and learned baselines; run ledger; promotion gate;
  hash-pinned model registry; shadow scoring API and CLI; PSI drift monitoring
  (`e9b49f1`). Results in ML_EVALUATION.md, data card and decision log in ML.md.

### ML generalization audit (Phase 11.1)
- Baseline reproduced exactly (metrics, model bytes) and frozen in
  `docs/ml/baseline-phase11.json`; its test split reclassified as a development benchmark.
  The model is now research-only: the API refuses to score with it (`c11e5fb`).
- Fixed: scoring skipped chain verification; a missing receipt was scored; the request
  budget could be lost on a crash or overspent by concurrent collectors; the registry
  trusted a path from its JSON file; intervals resampled rows despite account clustering.
- Added: `cryptoguard ml audit` (recomputed metrics, cluster intervals, prevalence arithmetic,
  shortcut experiments, hub-policy sensitivity, calibration, errors), approval levels,
  LightGBM text serialization, wallet-history features (infrastructure, no accuracy claim).
  Report: ML_GENERALIZATION_AUDIT.md; tables: ML_AUDIT_TABLES.md.

### Phase 12.5: ML-driven candidate discovery and evidence-aware ranking (no RPC requests)
- **Protocol 12.5** (`docs/ml/protocol-12.5.md`) was frozen before any new outcome. The code was committed before the outcome run.
- **Primary pre-registered ML test** (`planting-mechanism-next/1`, a self-supervised proxy on 1,067 archive episodes): **not supported.**
  - The fixed logistic regression's test log loss is 1.945, against 0.200 for victim-prefix frequency, because of strong temporal covariate shift.
  - Its macro-F1 is higher (0.323 against 0.284).
- **Semantic channel** (exploratory, development split): no gain over recency, at −0.009 [−0.022, +0.005].
- **MAD temporal anomaly:** analytically equivalent to recency (1,056 of 1,056 episodes).
- **Development cases:** recency and similarity disagree; descriptive only.
- **Added:** `poisoning-candidate-features/1` (value/status pairs, never zero for unobserved), and an offline shadow ranking `poisoning-candidate-ranking/1` (research CLI only).
- **Fixed:** a quadratic scan in candidate features. Ranking 1,000 flood candidates went from 424 s to about 2 s, with identical outputs.
- **Report:** `ML_CANDIDATE_DISCOVERY_RESEARCH.md`.

### Phase 12.4 final validation of observation/2 (no RPC requests)
- **Balance-bisection audit:**
  - **Fixed:** with matching sums, success was inferred. A reverted inbound plus an internal credit of exactly the same value in the same block would be misattributed. `observation/2` now reads a receipt for every nonzero inbound.
  - **Adversarial tests:** several inbound transfers in one block, an inbound followed by an equal spend, an internal credit beside an external inbound, reverted and successful inbound together, a missed own-transaction block, truncation, own transactions at the window edges, a self-transfer, outside-window inbound, the minimum cost, and a seeded randomized oracle.
- **C2, the warning-facing shadow variant:** a native observation is a candidate only when its sender imitates one of the wallet's own references, and there is one candidate per lookalike, with an event count. In a test, 1,000 zero-value strangers produce 0 C2 candidates. C1 stays a coverage measurement. The production detector reads no native inbound.
- **Added `replay record-window`:** outcome-blind recording, taking only the wallet, chain, block window and settings; it never overwrites.
- **Blind replay** (1,299 of an approved 2,500 RPC requests; one rate-limited attempt plus the one restart): `replay record-window` was given only the victim, chain and window. It independently recorded the native dust planting, with its identity, sender, value, block and success read from the receipt.
  - **C0:** 2 lookalikes.
  - **C1:** adds exactly the paid address, 357 blocks before the theft.
  - **Production detector:** unchanged.
  - **V1–V5:** all passed.
  - **Classification:** a development-case regression, not validation.
  - **Decision** (`ML_OBSERVATION_COMPLETENESS.md` §35): `observation/2` is sufficient for offline research within its scope. Production integration needs untouched incidents, a volume study and a separately approved detector change.

### Observation completeness and candidate discovery, Phase 12.4 (no RPC requests)
- **Protocol 12.4** (`docs/ml/protocol-12.4.md`) was frozen before the code and the study.
- **Audit:** `observation/1` never observed inbound native ETH, zero-value native transactions, internal transfers or ERC-1155. It also fetched ERC-721-shaped and malformed `Transfer` logs and discarded them, without keeping their counts.
- **Added `observation/2`** (opt-in: `replay record --observation 2`):
  - native ETH received, by balance bisection;
  - unattributed credits;
  - ERC-721 records and malformed-log counts;
  - per-category coverage (`replay/observation.py`).

  Existing fixtures keep their bytes and hashes.
- **Added shadow `poisoning-candidate-discovery/1`** (`ml/candidate_discovery.py`):
  - C0 is frozen;
  - C1 applies C0's rules to every observed class;
  - C2 adds abstention and a payment-time screen;
  - `wallet-history/2-scoped` never reports unobserved inbound as zero (109 false zeros under `/1`; no published number used them).
- **Study:** `cryptoguard ml observation-study`. Report: `ML_OBSERVATION_COMPLETENESS.md`.
- **Q1** (2 approved RPC requests): the Stage 2a paid address signed exactly one transaction before the theft, inside the window.
- **Q1b** (17 approved RPC requests): that transaction was a **native ETH dust transfer, 10¹² wei, to the victim**, 357 blocks before the theft.
  - The Stage 2a miss is a confirmed recorder omission, the class `observation/2` adds.
  - In a development reconstruction (in memory), C1 flags the paid address 357 blocks early.
  - Not validation: the record was found by an outcome-directed query.
- **Unchanged:** the production detector and its findings.

### Incident recording, Stage 2a (1,433 RPC requests of an approved 6,000)
- **Case 1, `scamsniffer-763k-2025-02-20`:**
  - resolved on chain by the frozen rule, recorded, and frozen by test;
  - Level I, but the detector **missed** it. The theft recipient never appears in the recorded stream before the harm, while two other lookalikes were warned.
- **Case 2, `webacy-6.88m-usdt-2025-09`:** *not evaluable: RPC* (rejected twice; stop rule).
- **Level I:** warned 1 of 2; Gate H DESCRIPTIVE. Report: `docs/ml/incident-benchmark/stage2a-result.md`.

### Incident recording, Stage 2 Step 0 (no RPC requests)
- **Amendment 12.3-A1** (`docs/ml/amendment-12.3-A1.md`), frozen before any Stage 2 request:
  - **R1, identifier resolution:** a frozen on-chain rule, with no similarity scoring.
  - **R2, Gate H:** DESCRIPTIVE below 6 untied clusters; clusters are cases sharing a planting signer.
  - **R3, added measures:** normalized ranks, the censoring flag, and cases not recorded.
  - Level I is also summarized without resolved cases.
- **Added:**
  - `replay find-transfers`: capped; finds block bounds by header timestamps; reads receipts of the first 10 matches.
  - `ml incident-benchmark resolve`;
  - multi-manifest `verify` and `prepare`.
  - All are tested on mock nodes only. The detector, OP0 and OP1 are unchanged, and the Stage 1 case reproduces exactly.
- **Pre-registered:** Stage 2a (`docs/ml/incident-benchmark/preregistration-stage2a.md`):
  - 2 cases;
  - caps of 2,400 / 3,600 per case, 6,000 total;
  - not approved.

### Incident recording, Stage 2 preparation (no RPC requests)
- **Stage 1 audit:**
  - CI passed for `0aa1892`;
  - the lead time is measured from header timestamps (576 s);
  - the pilot case is frozen by a hash-and-result regression test;
  - the Gate G and Gate H labels are corrected to the frozen §10 rule.
- **Bounded public discovery** (8 searches, 12 reads) and an offline deduplication:
  - no fully eligible new case;
  - 3 near-misses are assessed in `docs/ml/incident-benchmark/stage2-candidates.json`.
- **Shortlist, budget and statistical review:** `docs/ml/incident-benchmark/stage2-shortlist.md`.

### Incident recording, Stage 1 pilot (475 RPC requests of an approved 2,000)
- The Aug 2026 counterfeit-USDT case was recorded as pre-registered, in
  `docs/ml/incident-benchmark/cases/`:
  - **Verified:** the harmful transaction and the planting are confirmed on chain.
  - **Detector:** it warned 48 blocks before the theft.
  - **Ranks:** OP1 2.0, OP0 4.0, random 3.5, with 6 warnings.
- This is descriptive only; no gate is decided. Report:
  `docs/ml/incident-benchmark/pilot-result.md`.

### Incident recording, Stage 0 (no RPC requests)
- **Fixed:** the replay recorders (`replay record`, `sample-background`, `record-background`)
  had no total request cap. They now reserve every attempt, retries included, in the durable
  request ledger, and need `--ledger` and `--cap`. A run that reaches the cap writes no
  fixture. The ledger moved to `cryptoguard.blockchain.budget`, and `ml.collect`
  re-exports it.
- **Added:**
  - `replay locate`, a capped receipt lookup;
  - `replay record --cases-dir`;
  - `ml incident-benchmark prepare`, which builds a case manifest by rule from located
    receipts and refuses identifiers the chain does not confirm;
  - Level I bookkeeping in `verify` and `run`, with an on-chain identifier check and
    per-level summaries.
- **Plan and pre-registration:** `docs/ml/incident-recording-budget-plan.md` and
  `docs/ml/incident-benchmark/preregistration-pilot.md`.

### Independent incident benchmark (Phase 12.3)
- **New command:** `cryptoguard ml incident-benchmark verify / run / report`. It runs
  offline and is bound to a protocol:
  - a provenance, tier and overlap audit of discovered incidents;
  - tier A replay with candidates, warnings, both orderings, lead time and perturbations.
  The result is data-limited: no Level I or II case is evaluable without RPC.
- **Fixed:** recorded replay windows holding frozen Cohort B items were used by Phase 12.1
  availability and by Phase 12.2's H3 and E14. Those results are withdrawn, and the
  exclusion is now enforced everywhere. See docs/ml/amendment-12.2-cohort-overlap.md.
- **Audit of the 12.2 follow-up:** the attrition is a complete partition, and the exact
  p-value is 0.0625. See docs/ml/amendment-12.2-unconfirmed-audit.md.

### Recency validation and experimental warning ordering (Phase 12.2)
- **Follow-up** `cryptoguard ml unconfirmed-recency`: two offline passes, then a
  pre-registered test on the source's 13,683 unconfirmed payoffs. The result is
  inconclusive, with only 7 rankable episodes. In 488 of the 499 excluded victims, the paid
  address never planted to the victim at all. `episode_from_rows` now takes the payoff
  flag; its default behaviour is unchanged.
- **Pre-registered study** `recency-validation/1`, run with
  `cryptoguard ml recency-validation`. It produces aggregate output and makes 0 RPC
  requests.
- **H1:** recency survives when every rival faces the source's own payoff-confirmation rule.
  Top-1 is 0.682 against 0.300, and the rule attenuates the effect by 0.2%.
- **H2:** on the production detector's own warnings, ordering by severity then recency beats
  ordering by severity then similarity: 0.502 against 0.267.
- **Status:** retrospective sensitivity analysis of previously examined data. No independent
  validation was possible. Report: ML_RECENCY_VALIDATION.md.
- **Experimental ranker** `ml/warning_rank.py` (`poisoning-warning-rank/1`):
  - orders warnings by severity tier, then by the latest planting signal;
  - never removes or re-tiers a warning;
  - is not wired into any production path.
- **Performance:** the graph is preloaded in one sequential pass, which reproduces Phase 12.1
  exactly (same result hash).
  - The Phase 12.1 study drops from 8,157 s to 179 s, and from 744 to 485 MiB.
  - The lazy per-address SQLite lookups are kept as `--lazy-graph`.

### Temporal and graph lookalike prioritization (Phase 12.1)
- Pre-registered study `lookalike-prioritization/1`, run with
  `cryptoguard ml lookalike-study` (aggregate output, 0 RPC requests). It ranks the
  lookalikes that planted to a victim before a source-confirmed payoff, using
  point-in-time features with typed missingness and a typed cross-victim graph.
- A symmetric offline archive pass covers paid and rival lookalikes alike. The earlier
  subset covered 0.2% of rivals, which would have leaked the outcome into graph features.
  The coverage audit passes.
- Results on test, against the production similarity score (top-1 0.300):
  - recency, 0.618: supported;
  - graph reuse, 0.206: equal to random;
  - recipient-history counts, 0.247: below the production score.
- These are retrospective ranking results, not detection metrics. Report:
  ML_TEMPORAL_GRAPH_RESEARCH.md.
- Fixed:
  - rows of frozen review wallets entered the graph index;
  - the archive scanner maintained indexes during inserts. It now builds them after the
    load, and the schema is unchanged.

### Evidence completion and review hardening (Phase 11.7)
- An offline recovery pass over the local archive gives all 19 Cohort B archive items
  that had no local wallet history some pre-cutoff rows (still source-selected).
- Evidence packets v2, registered as amendment 3 before any review:
  - same-block rows of unknown order are counted, never dropped silently;
  - coverage-specific wording, so missing history never reads as novelty.
- The review server refuses negative or non-numeric `Content-Length` and foreign browser
  `Origin`s.
- Added `ml verify-research`: an offline PASS/FAIL/MISSING/BLOCKED report on sources,
  derived files, frozen cohorts, evidence and reviews.
- Added `ml diagnostics`:
  - source-positive candidate coverage, 0.4% strict, because the archive has no signer;
  - evidence availability;
  - generator invariance;
  - scalability.
- Added `ml experiment-spec`: a JSON export with fairness, label provenance,
  label-count stages and a source-proxy-free ablation.
- Added exact FPR bounds by sample size: 35 negatives cannot show FPR below about 8%.
- Cross-check: 207 of 214 PTXPhish poisoning transactions are Tsuchiya payoffs, and the
  attack methods agree on 81.5% of those linked to an attempt.
- Tests: an independent reference implementation of `candidates/2`, an end-to-end
  synthetic review workflow with failure injection, and a corrupt lease database.
- Docs: ML_EVIDENCE_COMPLETION.md, amendment 3, and reviewer-guide wording and problem
  procedure.

### Human validation readiness (Phase 11.6)
- Both frozen cohorts re-verified byte for byte, and the history of Cohort B's superseded
  first draw audited. No reviewer, package or submission exists: state REVIEW_READY.
- Added offline pre-cutoff evidence packets (`ml review build-evidence`).
  - They are deterministic, read no key and contain no source flags, payoffs or
    similarity scores.
  - They are tested so that future rows and labels never change them.
  - They are registered by hash and shown in the review page.
- Protocol amendment 2, before any review:
  - later-payment and third-party-label exposure, offline-panel use, reason codes and
    evidence citations;
  - pre-specified exposure sensitivity analyses;
  - a synthetic training cohort (`ml review training-package`) that can never be
    unblinded;
  - review sessions that expire.
- Added submission checks and a key-free agreement report (`ml review check-submission`,
  `ml review agreement`).
- Added a label policy with seven statuses and strict binary eligibility.
- Added an inactive, pre-registered experiment spec; it needs 30 reviewed labels per class
  from 5 campaign groups each.
- Added FPR power planning; the contract now also refuses source and dataset identifiers
  as features.
- Fixed: a locked lease table raised a raw database error. It now raises the retryable
  `LeaseBusyError`, and the contention test reports each child's outcome.
- Faster: `candidates/2` buckets counterparties by suffix (exact). 10,000 transfers take
  0.13 s instead of 13 s.
- Docs: ML_HUMAN_VALIDATION_READINESS.md, docs/ml/reviewer-handoff.md, and an updated
  reviewer guide and protocol.

### Hard-negative discovery and benchmark contract (Phase 11.5)
- `candidates/2`: a counterparty counts as chosen only with a verified wallet signature,
  and generation is a single pass. The output is identical on all 13 recorded windows and
  the published tables are unchanged.
- Added `ml hard-negative-extract` and `ml hard-negative-study` (offline, 0 RPC):
  - 8,651 uncategorized archive transfers (the publisher's count) plus 226 recorded-window
    candidates, every one `unlabeled_candidate`;
  - a contamination screen against every local known positive. 3,632 archive candidates
    (42%) overlap known attacks; none is called benign;
  - typed campaign grouping that never links through common tokens or routers;
  - coarsened exact matching with balance diagnostics (strict: 17 of 1,409 positives
    matched);
  - source-separability diagnostics: value alone separates the frames, AUC 1.0.
- Added a second frozen review cohort (`hard-negative-candidates/1`, 35 items) in the same
  review app. Packages name no cohort, and the page shows a neutral title and pre-cutoff
  context.
- Added the `benchmark-example/1` contract and metrics that refuse unverified negatives
  (`ml/evaluation.py`), plus a data inventory (`ml inventory`).
- Docs: ML_HARD_NEGATIVE_STUDY.md, generated ML_HARD_NEGATIVE_TABLES.md, and readiness gates
  A-J in ML_BENCHMARK_READINESS.md §8.

### Independent annotation and benchmark validation (Phase 11.4)
- Verified the frozen review sample against its committed hashes (`ml review verify`) and
  audited its design (`ml review audit`). Every uniqueness, separation, allocation, weight
  and reserve check passes; nothing was regenerated. The 1,401 versus 1,395 group count is
  explained: an exploratory count without the imitated-address link.
- Protocol amendment 1, written before any review:
  - campaign-level primary estimand; attempt level as bounds only;
  - design-based intervals (the earlier 0.94 and 0.86 assumed simple random sampling; the
    all-confirmed design bound is 0.929);
  - a pre-specified collapse rule for single-item strata;
  - structured evidence and exposure fields.
- Added the review workflow:
  - per-reviewer packages holding only the blinded sheet;
  - a local review app (loopback only, session token, Host check, strict CSP, no data in
    static files);
  - a hash-chained, atomically written reviewer store with finalization;
  - replacements in frozen reserve order;
  - agreement statistics (kappa undefined rather than 0; Gwet's AC1);
  - an unblinding gate with no override, and a key-access log.
- Added benchmark readiness (`ml/benchmark.py`): versioned benchmark manifest, a guard that
  refuses training data touching the review holdout, and the ten criteria. Not a benchmark
  yet: no human decisions and no verified negatives. The negative-data collection plan
  needs a separately approved RPC cap.
- Docs: ML_ANNOTATION_AUDIT.md, ML_BENCHMARK_READINESS.md, docs/ml/reviewer-guide.md, and
  protocol amendment 1.

### Cross-dataset validation of poisoning research data (Phase 11.3)
- Added a verified, resumable downloader for one approved file at a time
  (`ml fetch-file`). Resume needs a matching `206`, the file is renamed only after size,
  MD5, SHA-256 and gzip checks, and a disk reserve is kept. It has no default caller.
- Added a safe streaming reader for Tsuchiya et al.'s PostgreSQL attempt archive
  (`ml scan-archive`). It never executes the dump, whitelists statements, checks the schema,
  bounds line lengths, counts distinct values exactly with bounded memory, and stores only a
  target subset (renamed only after a complete pass). On the real archive: 34,905,969 rows,
  0 malformed, all ten publisher counts reproduced, peak RSS 279 MiB.
- Added the reconciliation (`ml cross-dataset-report`): match levels for Poison-Hunter
  rows, payoff-to-attempt linkage, separate attempt/victim/address/campaign outcomes,
  temporal categories, competing-lookalike analysis, decision gates and a local review
  queue of 1,469 payoff-linked attempts.
- Fixed: payoff amounts are float4 in the source, so 1,644 of 1,738 are approximations
  (Phase 11.2 reported 41). Payoffs now carry a stable identity and provenance.
- Fixed: a killed scan's stale SQLite journal is removed before a rescan.
- Review packets (v2) carry competing lookalikes and payment evidence.
- Added `ml freeze-review-sample`. Before any review, it draws a stratified sample of 60 of
  the 1,469 payoff-linked packets, one per campaign group. It writes a blinded reviewer
  sheet, a separate unblinding key and a hash-committed manifest, and refuses to draw
  again. The protocol and analysis plan are in docs/ml/review-protocol.md.
- Docs: ML_CROSS_DATASET_VALIDATION.md, ML_CROSS_DATASET_TABLES.md.

### Wallet-centric poisoning research platform (Phase 11.2)
- Fixed: the option A pilot lost three wallet recordings because its post-processing read a
  non-existent field (`transactions`, not `wallet_transactions`) inside a broad exception
  handler. Pilot records are now typed and versioned (`ml/pilot.py`). Schema mismatches
  raise instead of reading as zero, and lost values are migrated as unknown.
- Corrected: the pilot's 0.069 payment-rate bound applies only to the 52 least active,
  completely checked rows, not to all candidates (ML_PILOT_AUDIT.md).
- Fixed: the request ledger used a lock file broken after 60 s, which two processes could
  both break; it now uses an OS file lock with fsynced writes, tested across processes.
- Fixed: PSI hid shifts of mostly-constant features (new references only), returned a large
  value for empty batches, and binned NaN silently.
- Added:
  - a typed Poison-Hunter parser with provenance and quarantine;
  - the poisoning event schema, with identity, campaign groups, grouped temporal splits,
    label tiers and quality gates;
  - an offline payment verifier;
  - a structural candidate generator and point-in-time event features;
  - a label review export and import;
  - a collection cost planner;
  - `cryptoguard ml poisoning-report` and `ml plan-collection`;
  - a task identifier on model cards.
- Docs: ML_POISONING_DATASET.md, ML_PILOT_AUDIT.md, ML_RESEARCH_PLAN.md,
  ML_POISONING_TABLES.md.
- Added: an offline cross-check with Tsuchiya et al.'s payoff transfers
  (`ml/tsuchiya.py`; the file stays local under CC BY-NC-ND). No complete-coverage pilot
  row is contradicted. One victim the pilot did not evaluate paid a competing lookalike
  (ML_PILOT_AUDIT.md §7).

## 0.1.0 — 2026-10-28 (first release candidate, not independently audited)

### Detection and monitoring
- Point-in-time address inspection with chain verification, finality and EIP-7702
  delegation detection (`6f4d523`).
- ERC-20 approval discovery from `Approval` logs with pinned-block allowance verification
  and a `min(balance, allowance)` exposure bound (`ce24d3d`).
- Wallet security timeline: snapshots, deterministic deltas, versioned ruleset `cg-rules`,
  finding lifecycle that never resolves on unverifiable data, reorg rebase (`09c06cf`).
- Address-poisoning detector with full-address similarity, poisoning context signals and
  false-positive guards (`be093bf`); exclusive rule groups so an escalation supersedes
  rather than resolves (`5b85540`).
- Wallet-signed transactions (native-ETH payments) located by nonce search in snapshots
  and scans (`5b85540`).

### Interfaces
- REST API with rate limiting, body limits, restricted CORS and safe errors; CLI.
- Web UI: dashboard, wallet overview, permissions, timeline, findings, poisoning view,
  threat graph (Cytoscape), replay page; strict CSP in production builds (`c77267f`,
  `264d76c`, `15f06cd`).

### Evaluation
- Historical incident replay: publicly sourced manifests, recorded mainnet fixtures,
  point-in-time engine with leakage checks, generated `EVALUATION.md` (`15f06cd`); now 4
  incidents and 9 randomly sampled background wallets (`810c50b`).

### Experimental (off by default, shadow mode only)
- Graph propagation, spectral features and activity-rate statistics, evaluated against the
  existing detector: no measurable gain (`810c50b`).
- Cross-wallet poisoning campaign analysis with budgeted expansion, conservative clustering
  and `CAMPAIGN_EVALUATION.md`: real shared-signer links found, no earlier theft warning
  (`3fde4a8`).

### GitHub CI and cross-platform validation
- First GitHub-hosted CI runs (private repository): backend, frontend and packaging on
  Windows and Ubuntu, backend also on Python 3.13, browser tests on Ubuntu (`4705389`).
- Fixed, found by Linux CI: the mobile header and finding titles overflowed narrow screens
  with wider fonts; layout tests now cover 320 px and a wide font (`8053537`, `95c5856`).
- Experimental analysis libraries load at API start when enabled, not on the first request
  (`95c5856`).
- Actions pinned to verified commit SHAs, Dependabot cooldown, uv and pip-audit pinned;
  packaging job on both OSes with a full clean-install smoke test; sdist checked against the
  tracked files after a local untracked file leaked into a locally built sdist (`4705389`).

### Release candidate validation (phase 10.1)
- Browser end-to-end suite (Playwright, Chromium): the real backend against a fictional test
  chain behind the production UI build; user journeys, error handling, browser security,
  layout and accessibility checks.
- Fixed: a superseded finding was labelled "resolved at block"; the timeline said "No
  security-relevant change observed" above new findings; a shared-signer campaign showed a
  contradictory "single points" warning; mobile timeline overflow; stretched snapshot button;
  stale "native ETH not analyzed" dashboard text; garbled campaign explanation.
- Fixed: SQLite DDL autocommitted, so an interrupted migration left partial changes; SQLite
  connections now let SQLAlchemy start transactions.
- Fixed a timing-dependent lease test.
- CI: concurrency, timeouts, `persist-credentials: false`, Windows + Ubuntu for backend and
  frontend, browser E2E job, packaging job with artifact inspection and clean install.
  Local equivalents: `scripts/check.ps1`, `scripts/check.sh`.

### Release validation (phase 10)
- Local API hardened against DNS rebinding (host allow-list) and CSRF (JSON-only POSTs,
  Origin check).
- Snapshots (per wallet) and campaign runs single-flight across processes via fenced
  database leases; concurrent same-wallet snapshots no longer fail with 500.
- Reverted ETH payments are recognised (receipt status) and never treated as funds sent to
  a lookalike; all recorded fixtures re-checked on-chain (all executed).
- Versioned, reversible schema migrations with startup verification; upgrade from the
  `7fe824a` schema tested.
- Metamorphic point-in-time tests on real fixtures; clean-environment wheel install tested.
  See RELEASE_AUDIT.md.

### Release review
- Security, dependency (pip-audit, npm audit), reproducibility and packaging review; stale
  threat model updated; campaign runs made single-flight. See SECURITY.md.
- Machine learning (brief phase 8) deliberately deferred: too few labelled cases.

### Known limitations
- Native ETH received by a wallet, internal transfers and funding sources are not visible
  over standard JSON-RPC.
- No scheduled monitoring loop; snapshots run on request.
- No authentication: one trusted local user (see SECURITY.md).
- CI covers Windows and Ubuntu; macOS is untested. PostgreSQL is untested.
