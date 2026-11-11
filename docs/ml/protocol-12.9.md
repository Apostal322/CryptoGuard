# Protocol 12.9: reviewer-blinding integrity, independent incident acquisition, pilot gate

**Frozen:** 2026-11-11, in the commit that adds this file. That is before the Phase 12.9
exposure audit is computed, before any new public-source search, and before any lead is
classified.

**Base:** `79ebd6f` (Phase 12.8 contract).

**RPC budget:** 0. No JSON-RPC request, no explorer page or API, no wallet-history download.

**Public repository:** the repository is public by its owner's choice. This phase commits
aggregates, rules and citations only:
- **never committed:** per-item exposure mappings, cohort membership, review keys and incident
  identifiers (victim, lookalike, transactions);
- **kept locally:** those values live under the git-ignored `data/ml/research/phase12.9/`;
- **in the public registry:** SHA-256 commitments of the identifiers instead.

## Part I — reviewer blinding

### 1. Exposure channels

**For each frozen review item,** the identifiers are taken from the blinded reviewer sheet
only: wallet, address under review, transaction, and context counterparties. The unblinding
key is hashed for integrity and never parsed.

**Searched channels:**
- **repo-HEAD:** every tracked text file at HEAD;
- **repo-history:** every line ever added in any commit (public through git history);
- **repo-partial:** truncated identifiers (`0x` plus at least 8 hex characters followed by `…`
  or `...`) in tracked files. They are matched by prefix and are always ambiguous;
- **external:** the item's documented provenance class. Archive-derived items come from a
  publicly downloadable dataset (Tsuchiya et al., KiltHub) that carries the source's own
  labels. Recorded-window items come from public chain data.

### 2. Roles of public artifacts

| Artifact | Role |
|---|---|
| Incident manifests (`replay/cases/*/manifest.json`, `docs/ml/incident-benchmark/cases/*/manifest.json`) | `victim` and `intended_recipient` are **context**; `harm.recipient` and `harm.transaction_hash` are **outcome** |
| Incident registries (`docs/ml/incident-benchmark/*candidates*.json`) | `lookalike`, `harm_tx`, `planting_tx` and Etherscan filter roles are **outcome**; `victim` and `intended` are **context** |
| Incident-window fixtures (`replay/cases/*/fixture.json`, `docs/ml/incident-benchmark/cases/*/fixture.json`) | **context** (the window belongs to a publicly described poisoning incident) |
| Campaign expansion (`replay/campaign_cases/`) | **context** (a cross-wallet poisoning-campaign analysis) |
| Background fixtures and manifests, tests, frontend fixtures, other files | **neutral** |
| repo-history only (no longer at HEAD) | the role of the file it was added to; unknown files are **neutral** |

### 3. Exposure levels (deterministic; the highest applicable level)

| Level | Rule |
|---|---|
| **R3 outcome exposure** | an item identifier matches an **outcome** role in any public artifact |
| **R2 context exposure** | an item identifier matches a **context** role, or appears in a context artifact |
| **R1 identifier overlap** | an item identifier appears only in **neutral** artifacts |
| **RU unknown** | only truncated-prefix matches exist, or the item's identifiers cannot be read |
| **R0** | no match in any channel |
| **R4 confirmed reviewer exposure** | assigned **only** from a reviewer's own declaration or independent evidence that the reviewer accessed outcome-bearing information. Never inferred from R3. |

- The **repo** level and the **external** level are reported separately, and their maximum is
  the item's combined level.
- **External level:**
  - archive-derived items from the payoff-linked pool (Cohort A) are **R3-external**, because
    the public dataset labels the event's victim as a confirmed payoff victim of a poisoning
    attempt;
  - archive-derived items from the "uncategorized" pool are **R2-external**;
  - recorded-window items are **R0-external** (raw chain data alone carries no label).
- **Separate conditions, never conflated:** identifier visible (R1+), context discoverable
  (R2+), outcome discoverable (R3), reviewer exposed (R4), reviewer exposure unknown (no
  declaration).

### 4. Timing

**For each overlapping public artifact,** its first commit date is compared with the cohort's
freeze date: Cohort A on 2026-11-02 (Phase 11.4), Cohort B at `c68d3a4`, 2026-11-02.

**The public-visibility window is bounded by observation:**
- 2026-11-09: an anonymous API read returned Not Found;
- 2026-11-10: it returned `visibility: public`.

Exposure before that window was within a private repository.

### 5. Cohort disposition (per item, then per cohort)

| Combined level | Disposition |
|---|---|
| R3 (repo or external) | **not eligible for confirmatory blinded evaluation**; exploratory or sensitivity analysis only |
| R2 | **requires qualified blinding** (access separation and a reviewer declaration); reported as a sensitivity stratum |
| R1, R0 | **eligible for an explicitly qualified blinded review** (with declaration) |
| RU | **requires exposure clarification** |

- **The frozen cohorts are never rewritten:** dispositions are a separate local record.
- **No replacement cohort is drawn from already-exposed pools.** If no unexposed pool exists, a
  new cohort is reported as blocked.

### 6. Reviewer workflow (prospective)

**Task payloads are built from a per-task whitelist. They never contain:**
- outcome labels or registry statuses;
- attacker attribution;
- model scores, ranks or predictions;
- other reviewers' decisions;
- public report conclusions.

**Every review task carries:**
- a task id;
- the item and evidence versions;
- an evidence SHA-256;
- the item's exposure level;
- a **reviewer declaration**: prior familiarity, external sources consulted, repository
  consulted, model output seen. Each is `yes`, `no` or `unknown`, given by the reviewer.

**Rules:**
- A missing declaration is **never defaulted**: the review's exposure is RU.
- A declared consultation of outcome-bearing material on an R3 item makes it R4.
- Adjudication needs two independent decisions (`label_policy`) plus declarations.
- Instructions not to consult public sources are a procedural protection, not proof of
  blindness.

## Part II — incident acquisition

### 7. Discovery (bounded)

**Budget:** at most **20 searches** and **30 page reads**.

**Source order:**
1. primary forensic and firm reports;
2. research papers;
3. news that quotes identifiers.

**What counts and what is never used:**
- Social-media-only claims are leads at best; X posts are not read.
- Explorer pages and APIs are never fetched.
- A full transaction hash or address inside a cited page's own hyperlink counts as verbatim
  from that page (the 12.3 convention).
- Identifiers are copied verbatim. A truncated identifier is recorded as truncated, never
  completed.
- A role (victim, lookalike, intended recipient, harmful transaction) is assigned only when the
  page states it.
- **Corroboration** needs an independent original source. Articles repeating one alert count
  once.

### 8. Eligibility (first matching rule wins)

1. **DEVELOPMENT_ONLY:** any identifier matches a development artifact, meaning:
   - recorded fixtures and manifests;
   - incident registries;
   - campaign expansion;
   - archive episodes or archive subset;
   - review packets;
   - frozen cohort sheets.
2. **REJECTED:** chain not Ethereum mainnet; or no identifier at all.
3. **CONFLICTING:** sources disagree on an identifier, amount or date. This maps to
   NEEDS_IDENTIFIER_VERIFICATION, with the conflict listed.
4. **NEEDS_IDENTIFIER_VERIFICATION:** the victim address or the harmful transaction hash is
   absent or truncated.
5. **NEEDS_CAMPAIGN_REVIEW:** the lead shares an attacker or lookalike identifier with another
   lead, unless the two are grouped into one cluster.
6. **UNSUPPORTED_MECHANISM:** the claimed mechanism needs a category `observation/2` cannot
   observe: internal transfers, ERC-1155, or zero-value native transfers.
7. **NOT_EVALUABLE:** no harmful transfer is claimed (planting only).
8. **READY_FOR_BLIND_RECORDING:** otherwise. This requires a verbatim victim, a verbatim harm
   transaction, a stated Ethereum chain and stated roles.

**Not required but recorded:**
- the intended recipient (without it, reference-group exposure is not assessable);
- the lookalike (the anchor receipt supplies it to the evaluator only).

### 9. Pilot selection

**Selection:** every READY lead, at most one per victim or attacker cluster, ordered by
`sha256("cg-12.9-pilot|" + lead_id)` and capped at 10.

**Never used to choose:** detectability, loss size, or ease of recording. Fewer than 10 is
reported as found.

### 10. Collection jobs (prepared, never executed here)

**Per selected lead:**

| Step | What it does | Cap |
|---|---|---|
| **anchor** | one receipt read of the harmful transaction, to obtain its block H and confirm that the sender is the stated victim. A mismatch, a missing receipt or a reverted transaction makes the lead NOT_EVALUABLE before any recording. The anchor's output to the collector is the block number only; the receipt fields go to the outcome vault. | 5 requests |
| **record** | a Phase 12.8 `CollectorRequest(chain_id=1, wallet=victim, from_block=H−21,600, to_block=H, observation=2, max_requests=2,500)` | 2,500 requests |

**Overall cap:** n × 2,505.

**Estimates use the measured recordings:**

| Measure | Requests |
|---|---|
| Low | 475 |
| Typical | 1,299 |
| High | 1,433 |
| Retry reserve | +20 % |

- **Wallet activity** is unknown without RPC and stated as such.
- **Every retry is counted** in the existing durable ledger, which fails closed and carries
  nothing over.

### 11. Approval gate

**The manifest is planning only.** Recording requires a separate **approval record**:
- the manifest SHA-256;
- the per-window cap;
- the total cap;
- the approver's statement, quoted from chat.

`check_approval` refuses any mismatch. Configuration never implies approval, and no batch
runner is added in this phase.

## Part III — frozen comparison and pilot rules

### 12. Methods (Phase 12.8 registry, unchanged)

- **Generators:** C0, C1, C2 and `candidate-evidence/2`.
- **Orders:** B0 (similarity → recency), B1 (recency), B4 (reference rotation), P1, P1b.
- **P1b is comparison-only.**
- **Primary pair:** B0 vs B4.
- **Code revision:** the commit that adds this protocol.

**Tasks:** T1–T4 and T6 as in Phase 12.8, plus **T5g reference-group exposure**: within K, a
candidate whose best-reference bucket is the intended recipient. It is reported separately
from address exposure and is not assessable without an intended recipient.

### 13. Pilot stop rules (frozen before any recording)

**Evaluated on the recorded pilot, in order:**

| Rule | Condition | Action |
|---|---|---|
| S1 | anchor or recording fails for more than 30 % of selected leads (provider failures) | stop and report |
| S2 | fewer than 5 of 10 recorded incidents (or fewer than half of those recorded) are mechanism-eligible | pause broader collection |
| S3 | B0 and B4 disagree on End-to-End Top-5 for fewer than 2 incidents | no powered comparison on current assumptions |
| S4 | more than half of the recorded incidents fall in one attacker cluster | report the effective sample size as the cluster count |
| S5 | any case fails the leakage audit (contaminated cutoff) | exclude it from confirmatory metrics |
| S6 | — | report every missing mechanism category by name |

**Primary readout:**
- the failure-class distribution;
- End-to-End Top-5 for B0 and B4 over mechanism-eligible cases;
- the number of discordant incidents;
- T5g.

**Statistics:** the exact sign test on discordant incidents (Phase 12.8 `power`). Clusters
count once. No precision, recall or false-positive rate is reported from the pilot.

## 14. Gates

- **Statuses:** PASS, PASS WITH LIMITATIONS, FAIL, BLOCKED BY DATA, NOT EVALUATED.
- **Gates:** G1–G14 as in the phase brief.
- **Independent validation stays BLOCKED BY DATA** until approved recordings exist and are
  scored once.
