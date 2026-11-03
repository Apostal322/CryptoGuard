# Phase 12.3 protocol: independent incident benchmark

- **Task:** `incident-benchmark/1`.
- **Frozen:** committed before any new incident is searched for, selected or replayed.
- **Frozen components:** those at commit `b3f66ae`.

## 1. Objective and question

Can CryptoGuard's unchanged deterministic poisoning detector, using only information
available before a documented harmful transfer, do three things?
- (a) surface the outcome-linked address as a candidate;
- (b) warn on it;
- (c) with several warnings, rank it first, under the production order and under the frozen
  recency order.

The benchmark answers this per incident. It does not estimate population precision, recall
or a false-positive rate.

## 2. Threat model and scope

| Item | Scope |
|---|---|
| Chain | Ethereum mainnet only (chain id 1) |
| Mechanisms | address poisoning: zero-value transfers, spoofed `transferFrom`, dust or tiny transfers, counterfeit tokens |
| Harm | a victim-signed transfer to the lookalike |

Approval, drainer and signature phishing are out of scope.

## 3. Evidence levels (never pooled)

| Level | Meaning |
|---|---|
| **I** | a new incident from an independently maintained public source, with no event, victim, lookalike or outcome overlap with development data (§6) |
| **II** | a new incident whose observations come from a known source family (the Tsuchiya archive), or whose overlap is partial or unknown |
| **III** | the 4 existing replay incidents (`replay/cases`) and every Phase 12.1/12.2 episode |
| **IV** | synthetic fixtures: software correctness only |

## 4. Incident discovery

Discovery is bounded: at most 8 web searches and 15 page reads. Sources are taken in this
order:
1. original postmortems and security-firm incident reports;
2. research papers;
3. reputable news reporting that quotes on-chain identifiers.

Social-media-only claims are not enough.

**Inclusion criteria:**
- the incident is on Ethereum mainnet;
- the mechanism is address poisoning;
- a public source gives the **harmful transaction hash**, or the **victim address and the
  lookalike address**, verbatim. These are never inferred.

**Exclusion criteria:**
- the chain or mechanism is out of scope;
- the identifiers are missing or contradict each other;
- the only source is unverifiable;
- the incident duplicates an existing fixture.

## 5. Verification and eligibility tiers

No RPC request is made. A case's identifiers count as **verified on chain** only if they
appear in a local on-chain record: a recorded fixture, or the Tsuchiya archive, whose block
range is 15,053,226–20,208,032.

| Tier | Requirement | What it supports |
|---|---|---|
| **A, full operational replay** | a complete recorded wallet stream at the cutoff (a `ReplayFixture` with `transfer_scan_complete`) | candidate generation, warnings, ranking, lead time |
| **A′, archive-observation replay** | the harmful transaction is verified in the archive. Observations are the victim's source-kept rows at or before the cutoff: no signers, values only zero or nonzero, line order within a block. | the same as A, but on a source-selected stream |
| **B, warning-only** | verified warnings already produced (existing fixtures) | ranking only |
| **C, mechanism regression** | verified individual transactions | rule behaviour only |
| **Not evaluable** | the identifiers are unverifiable locally | reported with the missing evidence and the RPC needed |

A **targeted offline archive pass** gathers the A′ rows (§12). Its targets are the
discovered victims and harmful transactions. Nothing is fetched.

## 6. Overlap audit (mandatory, before evaluation)

Each case is compared with:
- the Phase 12.1 episodes (victims, candidates, planting transactions);
- the Phase 12.2 U victims;
- the archive's confirmed and unconfirmed payoff rows (victim, receiver, transaction);
- the 4 replay fixtures;
- Poison-Hunter's ground-truth addresses;
- the frozen cohorts (blinded sheets only: wallet, address under review, transaction).

The dimensions compared are:
- transaction;
- victim;
- lookalike or recipient;
- intended recipient;
- the linkage group of an overlapping Phase 12.1 episode.

**Rules:**
- A shared public token contract never counts as overlap.
- Unknown overlap is never independence.

**Classification:**
- no overlap on every checked dimension, and an independent outcome source: Level I;
- any partial overlap, or observations from the archive: Level II;
- a frozen-cohort overlap: excluded.

## 7. Point-in-time reconstruction

- **Cutoff:** `c = harm block − 1`.
- **Inputs:** only records at or before c. Harmful and later rows never enter.
- **Outcome information** (the harmful transaction, the recipient, public reports) is used
  only to score.
- **Never used as features:** campaign membership, threat tags or later reuse.

## 8. Methods (frozen at `b3f66ae`)

The detector receives the full reconstructed stream. It is never given the outcome address.

| Id | Method |
|---|---|
| B0 | unchanged `detect_poisoning` (tier A: `replay.engine.detector_outputs`, ERC-20 plus wallet transactions; tier A′: `recency_validation.production_cases`) |
| B1 / OP0 | production order: severity tier, then prefix+suffix; remaining ties tied |
| B3 / OP1 | `poisoning-warning-rank/1`: severity tier, then the latest planting signal at or before c |
| B4 | random: exact expectation 1/k |
| T0 (tier A′ only) | Phase 12.1 recency over the source-flagged planting candidates, reported for continuity |

Nothing is tuned. A defect found during the evaluation is reported, but the frozen result
remains the result of record (§11).

## 9. Metrics (per case; aggregates are exact counts)

- **Candidate recovered:** the outcome address is among the detector's suspects at c.
- **Warned:** a production case exists for it at c, with its severity tier.
- **Ranks** under OP0 and OP1 (tie-averaged expected rank), top-1 per case, and the number
  of competing warnings k.
- **Lead:**
  - the harm block minus the block of the outcome address's first planting signal at or
    before c;
  - the harm block minus the earliest cutoff at which it is warned, found by replaying the
    detector at each of that address's planting-signal blocks.
  - This is an on-chain opportunity window. It is not when a warning was delivered.
- **Alert burden** (tier A only): warnings and distinct suspects at c.

**Small samples:**
- exact counts and per-case tables;
- paired OP1 versus OP0, reported as better / equal / worse;
- an exact sign test only when at least 6 cases are untied;
- no intervals from asymptotic or bootstrap methods below 10 independent cases.

## 10. Decision rules (per evidence level, never pooled)

**Gate H (ranking usefulness)**, per level:

| Status | Condition |
|---|---|
| PASS | at least 10 independent rankable cases, OP1 better in more cases than worse, and the exact sign test p < 0.05 |
| PASS WITH LIMITATIONS | fewer cases, OP1 never worse and better in at least 1 |
| FAIL | OP1 worse in more cases than better |
| NOT EVALUATED | no rankable case |

**Gate G (warning coverage):** reported as exact counts of cases warned before the harm.

**Phase classification:**
- **Independently supported operational result:** Gate H passes at Level I.
- **Limited external case-study result:** Level I or II cases exist but do not pass.
- **Data-limited:** no Level I or II case is evaluable.

## 11. Negative controls and failure taxonomy

**No false-positive rate is computed**, because no verified negatives exist.

**Controls:**
- tier A background windows (no outcome) report warning burden only;
- synthetic negatives serve only as invariants.

**Failure categories:**

| Area | Categories |
|---|---|
| Candidate | not observed in the available records; insufficient history; similarity threshold not met; unsupported token semantics; unknown signer |
| Warning | candidate without a warning; wrong tier; invalid cutoff |
| Ranking | ranked below a competitor; a recent distractor; a tie |
| Research | ambiguous outcome; insufficient metadata; overlap; post-outcome information needed |

## 12. Resources and stop conditions

| Run | Budget |
|---|---|
| Targeted archive pass | at most 1 pass, under 30 min, under 512 MiB |
| Benchmark | under 2 min |

0 RPC requests and no downloads.

**Stop:** when the discovery budget is spent, or when no in-range candidate can be verified.
A data-limited report is then the deliverable.

## 13. Provenance and licensing

The committed manifest `docs/ml/incident-benchmark/candidates.json` holds per-case records.
Each record gives:
- the public source URL and publication date;
- the identifiers quoted;
- the verification status;
- the tier, level and overlap results.

Public chain identifiers and URLs are committed. Archive-derived rows and per-case
archive evidence are not (CC BY-NC-ND), and stay under `data/ml/research/phase12.3/`.

Synthetic manifests carry `"synthetic": true` and can never be verified.
