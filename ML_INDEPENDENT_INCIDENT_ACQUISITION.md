# Phase 12.9: independent incident acquisition, reviewer-blinding integrity and pilot gate

**Protocol:** [`docs/ml/protocol-12.9.md`](docs/ml/protocol-12.9.md), frozen at `89aea4e`
before any audit, search or classification.

**Branch:** `feature/ml-pipeline`.

**RPC budget:** 0. No Ethereum JSON-RPC request, explorer page or explorer API was used in
this phase.

**Public repository:** the repository is public by its owner's choice. This report carries
aggregates, rules and citations only:
- **kept locally:** per-item exposure mappings, cohort membership and incident identifiers
  stay in the git-ignored `data/ml/research/phase12.9/`;
- **in the public registry:** salted SHA-256 commitments in
  [`acquisition-12.9.json`](docs/ml/incident-benchmark/acquisition-12.9.json).

## 1. Executive summary

**Problem A, reviewer blinding.**
- **Cohort A (60 items) is not usable for confirmatory blinded evaluation.** It has no overlap
  with the repository. But every item comes from the public archive's payoff-linked pool, whose
  own labels disclose the outcome (external R3).
- **Cohort B (35 items):**
  - 4 items are R3, through context counterparties that public incident manifests name in an
    outcome role;
  - 30 are R2, either archive context or recorded incident windows;
  - 1 is R1.
- **The Phase 12.8 count is reproduced exactly:** 54 core identifiers in 17 tracked files.
- **No reviewer has been exposed through the project's process:**
  - no kit was sent;
  - there are no submissions and no declarations;
  - actual reviewer exposure is therefore **unknown**, not demonstrated.
- **Both frozen cohorts are byte-identical** to their committed hashes before and after the
  audit.
- **New safeguards** (a protocol, and code with tests):
  - a whitelisted, leak-checked task payload;
  - opaque task ids;
  - a reviewer declaration that is never defaulted;
  - R4 assigned only from a declaration;
  - an adjudication-readiness check.
- **These safeguards do not restore blinding for publicly exposed items.**

**Problem B, incident acquisition.**
- **Leads:** 7 existing leads re-examined and 10 new public leads recorded, within a bounded
  search of 16 searches and 17 page reads (budget 20 / 30).
- **Statuses:** **no lead is ready for blind recording**:
  - 5 need identifier verification;
  - 12 are rejected: 10 because no identifier appears in any source read, 2 because they are
    not on Ethereum mainnet.
- **No source read gives both a verbatim victim address and a verbatim harmful transaction**
  for any incident outside development:
  - two leads have a verbatim harmful transaction but no victim;
  - two Ethereum leads have a verbatim victim but no transaction.
- **Independence:** no lead identifier overlaps any development artifact. Five development
  incidents were re-encountered in the sources and excluded as duplicates.

**Pilot.**
- **The pilot selection is empty:** 0 eligible incidents, 0 collection jobs, total cap 0.
- **No RPC approval is requested**, because the frozen protocol has nothing to approve.
- **Section 35 sets out what would change this:** an identifier source, or a pre-registered
  protocol amendment.

**ML.**
- **Methods and stop rules are frozen.** T5g (reference-group exposure) is added to the blind
  harness and kept apart from address exposure.
- **Independent validation remains BLOCKED BY DATA.** No ML generalization claim is made.

## 2. Phase 12.8 baseline

**What Phase 12.8 left behind:**
- **Contracts:** `benchmark-labels/1`, `benchmark-case/1`, an outcome-free `CollectorRequest`, an
  `OutcomeVault` that opens only for a sealed prediction, and a score-once `Ledger`.
- **Taxonomy and planning:** a failure taxonomy, metric denominators, group splits, paired
  sign-test planning and a repository-safety scan.
- **Local data:** 16 recorded windows:
  - 7 protected;
  - 3 development incident windows from 2 incidents;
  - 6 unlabelled background windows.
  Of these, 15 use `observation/1` and 1 uses `observation/2`.
- **Gaps:** 0 independent incidents, 0 verified legitimate negatives, 0 reviewer submissions.
- **Prior negative result:** Phase 12.7.1 found P1b not supported (−0.018 against B4).
- **Exposure count:** 54 identifiers of the protected cohorts in 17 tracked files.

## 3. Research objectives

1. **Audit the public overlap.** Find which protected items may have outcome-disclosure risk,
   without altering any frozen cohort.
2. **Separate the risk levels.** Distinguish public exposure risk from demonstrated reviewer
   exposure, and design a review workflow that records what reviewers knew.
3. **Re-examine the leads.** Revisit the seven unrecorded leads and search public sources,
   within a fixed budget, for independent incidents with verbatim identifiers.
4. **Classify and plan.** Classify every lead reproducibly, select a pilot of at most 10, and
   prepare outcome-blind collection jobs and their caps without executing anything.
5. **Freeze the comparison.** Freeze the B0 vs B4 comparison and the pilot stop rules before
   any recording.

## 4. Public repository context

- **Visibility timeline:**
  - 2026-11-09: an anonymous API read returned Not Found;
  - 2026-11-10: it returned `visibility: public`;
  - since then, git history is public in full.
- **Both cohorts were frozen on 2026-11-02.**
- **Every artifact that overlaps Cohort B was first committed on 2026-10-24, 2026-10-28 or
  2026-11-03:**
  - all while the repository was private;
  - 134 of the 144 first additions predate the freeze;
  - the other 10 are incident-registry lines of 2026-11-03.
- **The overlap is by construction.** Cohort B's recorded-window frames were drawn from windows
  whose fixtures and manifests were already committed.
- **Nothing has been removed or rewritten:** no history rewrite was requested or done.

## 5. Cohort B exposure audit

**Method.** Identifiers come from the blinded sheet only: wallet, address under review,
transaction, and context counterparties. That is 310 identifiers across both cohorts. The
unblinding keys are hashed, never parsed.

**Channels:**
- every tracked file at HEAD;
- every line ever added in any commit;
- truncated prefixes (at least 8 hex characters before an ellipsis);
- the item's documented provenance.

| Cohort B | Items |
|---|---|
| provenance: archive "uncategorized" pool | 24 |
| provenance: recorded window | 11 |
| repo level R0 / R1 / R2 / R3 | 24 / 1 / 6 / 4 |
| repo level, core identifiers only (R0 / R1 / R2) | 24 / 1 / 10 |
| external level R2 (archive) / R0 (recorded) | 24 / 11 |
| **combined level R1 / R2 / R3** | **1 / 30 / 4** |
| recorded-window items with all three core identifiers in public files | 11 |
| items matched only through history (no longer at HEAD) | 0 |
| items with a truncated-prefix match | 1 (already R3) |

**Where the exposure comes from:**
- **The 4 R3 items are R3 through a context counterparty.** The item's own wallet, address
  and transaction reach R2 at most. The context list of each of these items includes an
  identifier that a public incident manifest names in an outcome role: the harmful
  transaction's recipient or hash. For three of them, the incident registry also names it.
- **A reviewer who reads the repository can learn that the wallet belongs to a documented
  poisoning incident** and which counterparty received the harmful payment.
- **Sensitivity check:** if the campaign-expansion records, which carry a verification status,
  were treated as outcome rather than context, the R3 count would rise from 4 to 8. The frozen
  rule treats them as context.

## 6. Public identifier overlap

| Measure | Cohort A | Cohort B |
|---|---|---|
| tracked files with an item identifier (core or context) | 0 | 18 |
| of which incident manifests / fixtures / registry / campaign / neutral | — | 4 / 4 / 1 / 1 / 8 |
| core identifiers in tracked files (Phase 12.8 measure) | 0 | 54 in 17 files |
| first added (range) | — | 2026-10-24 to 2026-11-03 |

- **The neutral files** are tests and earlier research reports that quote fixture data.
- **The per-item mapping is never committed.** It stays in
  `data/ml/research/phase12.9/blinding/item_exposure.local.jsonl`, a git-ignored file that a
  test checks.

## 7. Outcome-disclosure risks

1. **Repository, outcome role (R3).** 4 Cohort B items.
2. **Repository, context (R2).**
   - 6 Cohort B recorded-window items: their wallet is a published incident victim, or their
     identifiers sit in incident fixtures or campaign expansion.
3. **The public archive (external).**
   - Cohort A: payoff-linked, so the dataset's own labels disclose the outcome (R3).
   - Cohort B: 24 archive items come from its poisoning-attempt context (R2).
   - The dataset is public and carries its source's labels.
4. **Block explorers (not auditable here).**
   - The reviewer instructions for archive items point to a block explorer, which can display
     public name tags and phishing warnings.
   - Without explorer access this channel cannot be measured. It is handled by the declaration
     (`external_sources_consulted`), not assumed absent.
5. **Pre-publication period.** All overlap was committed while the repository was private, but
   it is public now through HEAD and history.

## 8. Reviewer blinding model

**Five conditions are kept separate and never conflated:**

| Condition | Level |
|---|---|
| identifier visible | R1 or above |
| context discoverable | R2 or above |
| outcome discoverable | R3 |
| reviewer exposed | R4: only from the reviewer's declaration or independent evidence |
| reviewer exposure unknown | no declaration |

**Today's status:**
- every item has a computed public-exposure level;
- **no reviewer has an exposure level**, because no review exists;
- R4 is never inferred from R3 (tested);
- an item's combined level is the maximum of its repository and external levels.

## 9. Reviewer protocol

[`docs/ml/reviewer-blinding-protocol.md`](docs/ml/reviewer-blinding-protocol.md) contains:
- **Neutral guidance**, given to reviewers verbatim. It contains no prevalence hints and no
  source-verdict wording; the screen finds zero hits and a test enforces it.
- **A four-question declaration** (`yes`, `no` or `unknown`):
  - prior familiarity;
  - external sources consulted;
  - repository consulted;
  - model output seen.

**Rules:**
- A missing or incomplete declaration makes the review's exposure RU.
- On an R3 item, any declared familiarity or consultation makes it R4.
- `model_output_seen` is reported separately.
- **Access separation is procedural.** The protocol states that it is not proof of blindness.

## 10. Protected cohort disposition

| Cohort | Disposition |
|---|---|
| A (60) | all **not eligible for confirmatory blinded evaluation**; exploratory or sensitivity use only |
| B (35) | 4 not eligible (R3); 30 **qualified blinding, sensitivity stratum** (R2); 1 eligible for an explicitly qualified blinded review (R1) |

- **The frozen files are unchanged.** Their hashes were verified before and after the audit,
  and the dispositions are a separate local record.
- **No replacement cohort was drawn.** The archive pools are externally labelled; the incident
  windows are public context.
- **A new low-exposure cohort is blocked by data.** It could come only from the unlabelled
  background windows (R1, small, already used in development) or from new recordings, which
  need a separately approved RPC budget.

## 11. Annotation-quality improvements

**What `review_blinding` adds:**

| Feature | What it does |
|---|---|
| `ReviewTask` | task id, item version (sheet hash), evidence version and SHA-256, exposure level, whitelisted payload |
| `assert_payload_clean` | refuses label, verdict, score, attribution, cohort or source keys and outcome-bearing wording; errors name the location, never the value |
| `ReviewerDeclaration` | strict schema; an opaque reviewer id; answers limited to yes / no / unknown |
| `review_exposure` | RU / R4 rules |
| `adjudication_readiness` | two or more distinct reviewers, the same evidence hash, declarations naming the task; "confirmatory" only when every review is R1 or below |
| `guidance_findings` | screens reviewer guidance for hints |

**The prepared, unsent kits:**
- They gave 4 screen hits in 2 files. On reading, all are benign: two are a decision option's
  name, one describes the evidence panel, one is a disclosure question.
- They predate the declaration form and must be rebuilt before use.

## 12. Existing incident leads

| Lead | Victim | Harmful tx | Other | Status |
|---|---|---|---|---|
| `usdt-700k-2025-04` (Decrypt) | absent | **verbatim** (hyperlink) | planting and test-transfer tx verbatim; one address with no stated role | NEEDS_IDENTIFIER_VERIFICATION |
| `wbtc-2.38-2025-12-18` (Bitquery) | absent | **verbatim** | lookalike truncated; post-harm tx verbatim; "same crew" as a development case | NEEDS_IDENTIFIER_VERIFICATION |
| `pink-drainer-10eth-2024-06-27` (ForkLog / MistTrack) | **verbatim** | absent | intended verbatim; chain not stated | NEEDS_IDENTIFIER_VERIFICATION |
| `webacy-6.88m-usdt-2025-09` (Webacy) | **verbatim** | absent | four lookalikes as 8-hex prefixes; two bursts | NEEDS_IDENTIFIER_VERIFICATION |
| `dea-usdt-55k-2023` | absent | absent | — | REJECTED (no identifier) |
| `usdt-100k-2026-08` (crypto.news / Cyvers) | absent | absent | re-read; none | REJECTED (no identifier) |
| `usdt-50k-2026-10` (crypto.news / Scam Sniffer) | absent | absent | re-read; none | REJECTED (no identifier) |

- **The two Decrypt hashes match the Phase 12.3 registry.** The Decrypt page was re-read
  independently, and its planting and harmful hashes equal the registry's values.

## 13. New public incident leads

| Lead | Source (read?) | Identifiers | Status |
|---|---|---|---|
| `aethusdc-24m-2026-03` | blockchain.news flash citing PeckShield (read); CCN, Coin-Turk (403) | victim and two addresses truncated; outlets disagree on 4 vs 5 March | NEEDS_IDENTIFIER_VERIFICATION (conflict) |
| `usdt-509k-2026-01` | search results citing Cyvers | none | REJECTED |
| `usdt-600k-2026-02-17` | CryptoRank (403) | none | REJECTED |
| `usdt-100k-2026-08-13` | AMBCrypto citing Lookonchain (read) | none | REJECTED |
| `webacy-polygon-792k-usdc-2025-09` | Webacy (read) | victim verbatim | REJECTED (Polygon) |
| `webacy-base-25k-usdc-2026-04` | Webacy (search result) | none | REJECTED (Base) |
| `amlbot-czech-50k-usdt` | AMLBot blog (read) | none; chain not stated | REJECTED |
| `phantom-chat-wbtc-2026-02` | Cointelegraph (search result) | none | REJECTED |
| `eth-636k-2025-08` | Cointelegraph (search result) | none | REJECTED |
| `cyvers-1.2m-2025-03-aggregate` | ForkLog citing Cyvers (read) | none; several victims | REJECTED |

**Development incidents re-encountered, excluded as duplicates:**

| Development case | Times seen in the sources |
|---|---|
| `usdt-50m` | 3 |
| `eth-4556` | 3 |
| `usdt-counterfeit-39890` | 1 |
| `wbtc-1155` | 1 |
| `scamsniffer-763k` | 1 |

The source URLs for every lead are in the public registry.

## 14. Source verification

**Discovery rules (protocol section 7):**
- **Budget:** 20 searches and 30 page reads. Used: 16 and 17. Three reads returned 403 and one
  PDF was unreadable.
- **Never fetched:** X posts and explorer pages.
- **Identifiers are copied verbatim with where they appeared** (text or hyperlink). Truncated
  values keep their ellipsis; a schema validator refuses a completed or ellipsis-less
  "truncated" value.
- **A role is recorded only when the page states it.** Two identifiers shown without a role are
  kept as `unassigned` and never stand in for a victim (tested).

**Result:**
- **6 of the 17 leads were seen only in search results.** No search summary was used as an
  identifier source.
- **Corroboration:** no lead has two independent original sources that both give identifiers.

## 15. Incident identity

`identifier_problems` checks every verbatim identifier for:
- full-length format;
- the same value appearing in two roles;
- a victim equal to a counterparty.

No lead has an internal inconsistency in its verbatim identifiers. The Polygon lead's page
lists one address as both victim and recipient; it is recorded as a conflict and the lead is
rejected (not Ethereum).

## 16. Campaign overlap

- **Clustering (union-find):** leads join on any shared verbatim identifier or a stated
  narrative link. The 17 leads form **16 clusters**: the two August 2026 USDT reports are
  joined by narrative.
- **Shared attacker identifiers:** no lead shares a verbatim attacker or lookalike identifier
  with another.
- **Link to a development case:** Bitquery describes `wbtc-2.38` as the "same crew" as a
  development incident. Once its victim is known it would go to NEEDS_CAMPAIGN_REVIEW.

## 17. Independence assessment

**What was searched:** every verbatim lead identifier, against every development artifact:

| Artifact class | Files |
|---|---|
| recorded fixtures and manifests | 32 |
| campaign expansion | 1 |
| development registry entries | 6 |
| archive episodes | 1 |
| archive row files | 2 |
| archive databases (indexed lookups) | 5 |
| review packets and evidence | 9 |
| frozen cohort sheets (blinded) | 3 |
| reviewer kits | 86 |
| local research outputs | 58 |

Unblinding keys are never opened.

**Result:**
- **No lead identifier was found in any development artifact.**
- **The search works:** positive controls (a development victim and its harmful tx, and an
  archive victim) are found.

## 18. Eligibility decisions

**The first matching rule wins (protocol section 8):**

| Status | Leads |
|---|---|
| DEVELOPMENT_ONLY | 0 |
| REJECTED | 12 |
| NEEDS_IDENTIFIER_VERIFICATION | 5 |
| NEEDS_CAMPAIGN_REVIEW | 0 |
| UNSUPPORTED_MECHANISM | 0 |
| NOT_EVALUABLE | 0 |
| **READY_FOR_BLIND_RECORDING** | **0** |

**The 5 leads that need verification:**
- 2 lack a victim address;
- 2 lack a harmful transaction;
- 1 has a truncated victim and conflicting dates.

## 19. Rejected leads

| Reason | Leads |
|---|---|
| no identifier in any source read | 10 |
| not Ethereum mainnet (Polygon, Base) | 2 |

**A rejection records what the sources read gave.** It does not claim the incident did not
happen, and a lead can be reopened if a source with identifiers appears.

## 20. Selection bias

**Where the population comes from.** These are incidents that English-language crypto news
and security-firm blogs chose to write about, found by one general-purpose search engine:
- large losses dominate;
- most reports cite an X alert and give truncated identifiers;
- Chinese-language searches returned reprints of the same cases.

| Breakdown | Ready | Verify | Rejected |
|---|---|---|---|
| origin: registry | 0 | 4 | 3 |
| origin: new | 0 | 1 | 9 |
| a source read in full | 0 | 5 | 6 |
| search results only | 0 | 0 | 6 |
| chain stated as Ethereum | 0 | 3 | 1 |
| inside the archive period (≤ 2024-06-30) | 0 | 1 | 1 |

**Two consequences:**
- **Any future pilot from this channel over-represents some incidents:** large, widely
  reported, stablecoin incidents whose reporters published full identifiers. Detectability is
  never a selection input, but **reporting is not independent of the incident's
  characteristics**.
- **The pilot cannot estimate a population rate.**

## 21. Ten-case pilot readiness

**Selection rule:** every READY lead, at most one per cluster, ordered by
`sha256("cg-12.9-pilot|" + lead_id)` and capped at 10.

**Selected: 0.**
- **The pilot is not ready.** There is nothing to authorize.
- **Even a small pilot would hit stop rule S2.** S2 needs at least five mechanism-eligible
  recordings, and the amendments discussed in section 35 would yield 1 to 3 leads.

## 22. Outcome-blind collection requests

**Per lead, two prepared jobs:**

| Job | Contents | Cap |
|---|---|---|
| **anchor** | one receipt read of the harmful transaction; it confirms the sender is the stated victim and gives block H | 5 requests |
| **record** | `CollectorRequest(chain_id=1, wallet=victim, from_block=H−21,600, to_block=H, observation=2, max_requests=2,500)` | 2,500 requests |

- **What reaches the collector:** the anchor passes the block number only; the receipt goes to
  the outcome vault.
- **What cannot be passed:** `CollectorRequest` refuses extra fields, so no lookalike, harmful
  transaction or label can be handed to it (tested).
- **What a job has no field for:** retries. No runner exists.
- **The manifest for this phase has 0 jobs.**

## 23. RPC cost estimates

**Planning basis:** the measured 21,600-block recordings (475 / 1,299 / 1,433 requests), plus 1
request per anchor and a 20 % retry reserve.

| Leads | Per-window cap | Total cap | Low | Typical | High | High + 20 % |
|---|---|---|---|---|---|---|
| 0 (this phase) | 2,505 | 0 | 0 | 0 | 0 | 0 |
| 1 (hypothetical) | 2,505 | 2,505 | 476 | 1,300 | 1,434 | 1,721 |
| 10 (full pilot) | 2,505 | 25,050 | 4,760 | 13,000 | 14,340 | 17,208 |

- **Wallet activity is unknown without RPC**, so a busy wallet can exceed the high estimate.
  The per-window cap is then the bound.
- **Every request would be counted in the durable run ledger.** It fails closed and carries
  nothing over from earlier approvals.

## 24. Proposed authorization gate

**Recording requires an `ApprovalRecord` with:**
- the manifest's SHA-256;
- the per-window cap;
- the total cap;
- the approver's statement quoted from chat.

**`check_approval` refuses:**
- a missing record;
- an empty manifest;
- any mismatch of hash or caps;
- general encouragement ("continue", "go ahead");
- a statement that does not state the total cap and the manifest's first 12 hex characters.

**Approvals do not travel:** an approval for one manifest is refused for another. No
configuration implies approval, and no batch runner exists (tested).

## 25. Frozen ranking baselines

**Unchanged from the Phase 12.8 registry:**

| Kind | Methods |
|---|---|
| generators | C0, C1, C2 and `candidate-evidence/2` |
| orders | B0 (similarity → recency), B1 (recency), B4 (reference rotation), P1, P1b |

- **P1b is comparison-only.**
- **The primary pair is B0 vs B4.**
- **Recorded at freeze:** the code revision, protocol 12.9, and the observation schema
  (`observation/2`).
- **Missingness behaviour is per method,** as listed in `benchmark_eval.REGISTRY`.
- **Not used for tuning:** no incident lead was used to tune anything.

## 26. Benchmark metrics

**Tasks:**
- T1 observation;
- T2 generation;
- T3 conditional rank;
- T4 end-to-end Top-K;
- **T5g reference-group exposure (new);**
- T6 burden;
- T7 evidence fidelity.

**T5g asks:** is there a candidate within K whose best-reference bucket is the intended
recipient?
- **It is reported separately from T4,** with its own denominator: mechanism-eligible cases
  that have an intended recipient.
- **Without an intended recipient it is not assessable.**
- **The bucket map is added to the prediction outside its digest,** so Phase 12.8 ledgers stay
  valid. It is a deterministic function of the observation and the cutoff, which the digest
  binds.

**Development check (not independent):**
- T5g is assessable on 1 of 2 mechanism-eligible development cases.
- In that case, B0 and B4 show the intended recipient's group at K = 1, while the paid address
  ranks third.
- **Group exposure is not address detection.**

## 27. Statistical design

**Analysis plan:**
- **Primary readout:** End-to-End Top-5 for B0 and B4 over mechanism-eligible recorded cases.
- **Test:** the exact sign test on discordant incidents, with clusters counted once.
- **Reported alongside:** the failure-class distribution and T5g. Exact counts and effect sizes
  are reported with their uncertainty.
- **Not reported from the pilot:** precision, recall or a false-positive rate.

**Stop rules, frozen (protocol section 13):**

| Rule | Condition |
|---|---|
| S1 | more than 30 % provider failures |
| S2 | fewer than 5 mechanism-eligible (or under half) |
| S3 | fewer than 2 discordant incidents |
| S4 | one cluster holds more than half: the effective n is the cluster count |
| S5 | a leakage failure: the case is excluded |
| S6 | report missing categories |

**Sample size:** the Phase 12.8 planner gives sample sizes as a function of the discordance
rate, the effect size, power, cluster dependence and the eligibility rate. No fixed count is
claimed as sufficient.

## 28. Future legitimate-negative requirements

**What does not count as a legitimate negative:**
- background windows are not confirmed benign;
- the absence of a known theft is not legitimacy;
- `unknown` is never a negative.

**A verified legitimate negative needs:**
- two independent reviews (`label_policy`), each with a declaration at R1 or below on an item
  that is itself R1 or below;
- or an independent verification of the counterparty relationship, such as a documented
  exchange deposit address.

**There are none today.** The outcome-selected pilot cannot by itself estimate a false-positive
rate.

## 29. Implementation

**New and changed modules:**

| Module | What it holds |
|---|---|
| `ml/review_blinding.py` (new) | exposure audit (HEAD, history, partial, external), levels, dispositions, payload whitelist, declarations, adjudication readiness, guidance screen |
| `ml/incident_acquisition.py` (new) | lead schema, local vault, salted commitments, development-overlap search, clusters, eligibility, pilot selection, jobs, budget, approval gate, stop rules, public registry; no network import |
| `ml/benchmark_eval.py` | T5g, prediction bucket map, aggregate |
| `ml/cli.py` | new commands `cryptoguard ml review-blinding` and `cryptoguard ml incident-acquisition [--write-public]` |

**Documents:**
- [`docs/ml/reviewer-blinding-protocol.md`](docs/ml/reviewer-blinding-protocol.md);
- [`docs/ml/incident-benchmark/acquisition-12.9.json`](docs/ml/incident-benchmark/acquisition-12.9.json).

**Unchanged:** the detector, the replay fixtures and the frozen cohorts.

## 30. Test results

**`tests/test_ml_blinding_acquisition.py` has 42 tests, all offline and synthetic.** They
cover:
- exposure levels;
- R4 never inferred;
- the history channel and its dates;
- partial matches;
- payload leaks, model scores and opaque ids;
- declarations never defaulted;
- adjudication;
- the guidance screen;
- cohort hashes;
- the identifier validator;
- every eligibility rule;
- duplicates and campaigns;
- deterministic, size-blind pilot selection;
- the development-overlap search, which never reads a key;
- the collector request carrying only its fields;
- caps;
- approval specificity;
- stop rules;
- the absence of network imports, runners and retries;
- salted commitments and an identifier-free registry;
- T5g separate from T4.

The full-suite result is given in the delivery note, and the pull-request comment records it.

## 31. CI

CI runs on the pushed commit. Its result is recorded in the pull-request comment and the
delivery note.

## 32. Reproducibility

```bash
uv run cryptoguard ml review-blinding
```

```bash
uv run cryptoguard ml incident-acquisition --write-public
```

```bash
uv run cryptoguard ml benchmark-readiness --out data/ml/research/phase12.9/dev-regression --no-archive --no-history
```

**What each run depends on:**
- **Determinism:** both studies are deterministic given the local vault, the per-lead salts
  (created once, kept locally) and the repository state.
- **Runtime:**

| Study | Runtime | Peak RSS |
|---|---|---|
| blinding audit | 9–16 s | about 71 MiB |
| acquisition | 33–61 s | about 75 MiB |

  Large files are streamed in 16 MiB chunks, and the databases are queried by index.
- **Local data:** the frozen cohorts, the archive extracts and the lead vault are local and are
  not in the repository.

## 33. Public-repository safety

**What this phase publishes:**
- **No incident identifier, full or truncated.** The registry carries salted commitments, and a
  test enforces this on every new public file.
- **No per-item exposure mapping, no cohort membership and no key.**

**What stays local (git-ignored):**
- the vault;
- the salts;
- the item mapping;
- the collection manifest.

**The repository-safety scan is clean:**
- no secret patterns;
- no sensitive names;
- no tracked restricted paths.

The repository stays public by its owner's choice.

## 34. Remaining limitations

- **The external channel is coarse.** External exposure is assigned by provenance class, not
  measured per item.
- **Explorer name tags and warnings are not audited.**
- **Discovery was bounded and came from one engine.** X posts and explorers were not read.
  Three pages returned 403 and one PDF was unreadable.
- **The role rules are frozen choices.** Treating campaign expansion as context, and assigning
  roles to history lines by key, are conservative choices that could be argued. The
  sensitivity count is reported in section 5.
- **No reviewer exists yet.** The declaration workflow is untested with real reviewers.
- **Two implementation choices that protocol 12.9 does not spell out:**
  - a lead with complete identifiers but no stated chain is classed
    NEEDS_IDENTIFIER_VERIFICATION, because READY requires a stated Ethereum chain;
  - the development-artifact search also covers the reviewer kits and local research outputs.
    That can only add DEVELOPMENT_ONLY results, and none occurred.
- **T5g has been exercised on one development case only.**
- **Independent validation remains BLOCKED BY DATA.** ML generalization is not established.

## 35. Recommended next experimental step

**Recording is not the bottleneck; identifiers are.** Without a lead that has a verbatim
victim and harmful transaction, no RPC budget can produce an independent pilot. Requesting one
now would only spend requests.

**Options, in order of preference. Each must be pre-registered before any recording.**

1. **User-sourced incidents.** Obtain incidents whose public source gives both identifiers in
   full, for example a firm's write-up with explorer links. They would be added to the vault and
   classified by the frozen rules.
2. **Amendment A1 (anchor-derived victim).** For a lead whose page states that the hyperlinked
   harmful transaction is the victim's own transfer, the anchor receipt's sender becomes the
   victim. The cross-check of the sender against a stated victim is lost.
   - Today this would make 1 lead ready (`usdt-700k-2025-04`), with a cap of 2,505.
   - `wbtc-2.38` would go to campaign review.
3. **Amendment A2 (date-window recording).** For a lead with a verbatim victim and a stated
   event date but no transaction, record a wider window around the date.
   - The harmful transfer would be identified afterwards, from the recording, by the page's
     stated partial identifiers.
   - Today this would add 1 to 2 leads (`webacy-6.88m`, and `pink-drainer` if its chain is
     accepted).
   - Larger windows need their own caps.

**Even with both amendments, the pilot would be 2 or 3 incidents,** below stop rule S2. Such a
pilot can show feasibility, but it cannot inform the B0 vs B4 comparison.

## Quality gates

| Gate | Status | Basis |
|---|---|---|
| G1 Exposure audit | PASS WITH LIMITATIONS | repository channels exact and reproducible; external channel by provenance class; explorer tags not auditable |
| G2 Reviewer isolation | PASS WITH LIMITATIONS | whitelisted, leak-checked payloads (tested); existing kits must be rebuilt; explorers outside control |
| G3 Cohort integrity | PASS | committed hashes verified before and after; no file written |
| G4 Blinding credibility | PASS | R3 and R4 separated; R4 only from declarations; 0 declarations, so reviewer exposure unknown |
| G5 Lead provenance | PASS WITH LIMITATIONS | every identifier has a cited page and position; 6 leads seen only in search results |
| G6 Incident independence | PASS | overlap search with positive controls; 0 overlaps; 5 development duplicates excluded; campaign link flagged |
| G7 Eligibility | PASS | deterministic first-match rules, each tested |
| G8 Selection bias | PASS WITH LIMITATIONS | documented; the population is what news reports |
| G9 Collector blindness | PASS | outcome-free request with extra fields refused; the anchor passes the block only |
| G10 Resource planning | PASS WITH LIMITATIONS | explicit caps; estimates from measured windows; wallet activity unknown |
| G11 Authorization | PASS | 0 RPC requests; specific approval required; no runner |
| G12 ML benchmark readiness | PASS WITH LIMITATIONS | the harness accepts future cases unchanged, with T5g added; independent validation **BLOCKED BY DATA** |
| G13 Public safety | PASS | no identifiers, mappings or keys published; safety scan clean |
| G14 Production isolation | PASS | detector, fixtures and stable behaviour untouched; existing tests pass |
