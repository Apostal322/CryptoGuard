# Stage 2 preparation: Stage 1 audit, incident shortlist, budget and protocol review

**Date:** 2026-11-03.

**No RPC request was made**, and no paid API, explorer query or download was used. Stage 2 has
not started. Every request below is a proposal, and each needs explicit approval.

**Inputs:**
- `stage2-candidates.json`: the candidates, with identifiers copied verbatim;
- the offline overlap check (`ml incident-benchmark verify --manifest
  docs/ml/incident-benchmark/stage2-candidates.json`), written to the git-ignored
  `data/ml/research/stage2-shortlist/`;
- the Stage 1 result (`pilot-result.md`).

## 1. Stage 1 audit (completed)

| Item | Result |
|---|---|
| CI for `0aa1892` | **Passed.** One workflow run, `pull_request` event, 16:07:11Z–16:10:17Z. All 9 required jobs succeeded: 3 backend, 2 frontend, browser e2e, dependency audit, 2 package. |
| CI for `61ad1af` (Stage 0) | Passed. It had been unverified when Stage 0 was reported. |
| Lead time | **48 blocks, 576 s, measured.** Both endpoints are block-header timestamps recorded by `eth_getBlockByNumber` in the fixture: planting block 25,718,349 at 2026-08-09T15:34:23Z, harm block 25,718,397 at 15:43:59Z. 576 s equals 48 × 12 s, so no slot was missed in between. Nothing is estimated from an average block time. |
| What the lead time means | An on-chain opportunity window (protocol 12.3 §9), not when a warning would have reached the user: it does not include indexing or delivery latency. The protocol's two lead measures agree. The first planting signal and the earliest warned cutoff are both block 25,718,349. |
| Other times, measured | The victim's legitimate transfer to the intended recipient came 792 s before the harm. The first lookalike arrived 12 s after that transfer. The last competing warning came 72 s before the harm. |
| Frozen case | **Done.** `test_stage_1_pilot_case_is_frozen_and_reproduces_exactly` pins the canonical hashes: fixture `62b3744c…0573b8`, manifest `ef903fbb…095e39`. It also pins the result: early warning, 48 blocks, 576 s, k = 6, OP0 4.0, OP1 2.0. A change to the detector or the ranker that moves the case now fails CI, so it has to be disclosed. Neither the detector nor Recency was changed. |
| **Gate label correction** | Under protocol 12.3 §10, Gate H at Level I is **PASS WITH LIMITATIONS**: fewer than 10 cases, OP1 never worse and better in 1. Gate G is reported as an exact count, **1 of 1**. The Stage 1 report had said "not evaluated" for both. It is corrected here, and in §28 of `ML_INDEPENDENT_INCIDENT_BENCHMARK.md`. The phase classification under §10 becomes a **limited external case-study result** (Level I cases exist, but Gate H does not PASS). The pilot pre-registration's own statement still applies: a single case decides nothing. §6.2 below proposes closing this loophole in the rule. |

## 2. Discovery (bounded, same rules as protocol 12.3 §4)

**Budget:** at most 8 searches and 15 page reads. 8 searches and 12 page reads were used; one
read was a redirect, and one was a PDF. The PDF was a research paper whose text was extracted
locally.

**Source order:**
1. primary forensic and firm reports;
2. papers;
3. news that quotes identifiers.

Social-media-only claims are insufficient. X posts were not read.

**Inclusion rule (unchanged):** the source must give, verbatim, either:
- the harmful transaction hash; or
- the victim **and** the lookalike.

Identifiers are never inferred, and a role is never assigned unless the source states it.

**Outcome:** **no new case meets the inclusion rule in full.** Three cases come close, each with
some full identifiers; §4 lists them. Everything else found has no identifiers, or duplicates an
existing fixture:
- the $50M Dec 2025 theft is `usdt-50m-poisoning-2025-12-19`, which is excluded (Cohort B);
- the 140 ETH Aug 2025 theft is `eth-140-poisoning-2025-08-14`, which is excluded.

All rejections are listed in `stage2-candidates.json`, `not_usable_sources`.

**Why public discovery is thin:**
- **News:** it repeats firm alerts on X without identifiers.
- **Firm reports:**
  - they truncate addresses: Webacy, Bitquery;
  - Guan and Li (CCS 2024) shorten every case-study address on purpose.

## 3. Deduplication (offline)

**What each full identifier was compared with:**
- **Frozen cohorts:** A (60) and B (35), blinded sheets.
- **Archive target groups:** payoff victims, lookalikes and transactions; incident groups.
- **Earlier phases:** Phase 12.1 lookalikes and planting transactions; Phase 12.2 U victims.
- **Poison-Hunter** ground truth.
- **Fixtures:** the 4 replay fixtures and the Stage 1 case.

No set was unreadable.

**A full-text search** for the 5 full addresses found no match in:
- every JSON file under `src/cryptoguard/replay/`: incident, background and campaign cases;
- `docs/ml/`;
- all of `data/`, about 1.5 GB. That includes the uncompressed Tsuchiya payoff CSV and the
  Poison-Hunter ground truth.

| Candidate | Full identifiers | Overlap found | Unknown overlap |
|---|---|---|---|
| scamsniffer-763k-2025-02-20 | 2 addresses | none | none: after the archive's range |
| webacy-6.88m-usdt-2025-09 | victim | none | none: after the archive's range |
| pink-drainer-10eth-2024-06-27 | victim, intended | none | **the compressed attempt archive** (2.3 GB `.sql.gz`, blocks to 20,208,032). This case lies inside its range. Ruling out overlap needs the offline archive pass (about 1 h on the shared HDD), so for now it is Level II at best. |

## 4. Candidate assessment

Selection used only identifier completeness and provenance. No candidate was chosen or
dropped for how Recency is expected to do on it.

| | scamsniffer-763k-2025-02-20 | webacy-6.88m-usdt-2025-09 | pink-drainer-10eth-2024-06-27 |
|---|---|---|---|
| Source (organization) | Scam Sniffer, via ForkLog | Webacy (firm report) | MistTrack (SlowMist), via ForkLog |
| Source type | firm alert, quoted by news with an Etherscan filter link | firm's monthly analysis | firm alert, quoted by news |
| Identifiers | `0xf6b1539cc562c0ca5151825488eb8c3cdaf2b6e4` (Etherscan filter `fadd`) and `0x804051b0cbc20443943c4f363573ef9bb7793375` (`tadd`); **roles not stated**; no tx hash; token not stated | victim `0xee7ada00c9e5f654c8f8ea0f355a1f3c50942732`; lookalikes only as prefixes `0x418e0ddb…`, `0x4186a058…`, `0x4186a666…`, `0x4186b115…`; no tx hash | victim `0x8980ab6d185af9bcc10292d4e91ae4c0b4f14213`; intended `0xeff0e5244d5c78ba4dd6bc01082576280558f58a`; lookalike truncated; no tx hash |
| Date / amount | 2025-02-20 / $763,662 | 2025-09-15 and 2025-09-18 / about 6.88M USDT in two bursts | 2024-06-27 / 10 ETH |
| Subtype | not stated | not stated. The source reports weak similarity (0.50–0.52; Levenshtein 25–28) | not stated. The source says first and last 5 characters match |
| Outcome confidence | medium: a firm alert; the loss is in the source, the roles are not | medium-high: a firm's own analysis with a full victim | medium: a firm alert; atypical victim (a drainer's own wallet) |
| Independence | Level I if resolved (no overlap; post-archive) | Level I if resolved (no overlap; post-archive) | Level II at best until the archive pass |
| Historical data | full chain history is available | available | available |
| Expected wallet activity (drives cost) | unknown | probably high (a large holder) | very high (a drainer hub) |
| Replay suitability | good if the loss is an ERC-20 transfer; **not resolvable from logs if native ETH** | good. Two bursts and several lookalikes; the first harmful transfer sets the cutoff. | poor. A native ETH transfer means the harm must be found from transactions, not logs. A hub wallet's 3-day window may exceed any per-window cap. |
| What would need resolving on chain | the transfer `fadd → tadd` on 2025-02-19..21 (direct; no similarity used) | USDT transfers from the victim on 2025-09-14..19 to the source's stated prefixes | a 10 ETH send from the victim on 2024-06-27 to an address matching the intended one's first and last 5 characters. **That rule uses lookalike similarity, the detector's own feature.** |

**Already listed in Phase 12.3 and still rejected:**
- `usdt-700k-2025-04`: no victim or lookalike is given;
- `wbtc-2.38-2025-12-18`: the victim is not named, and the lookalike is truncated;
- `dea-usdt-55k-2023` and `usdt-50k-2026-10`: no identifiers;
- `usdt-100k-2026-08`: the chain is not stated.

## 5. Ranked shortlist

1. **scamsniffer-763k-2025-02-20: include in Stage 2a.**
   - It is the only case with two full addresses.
   - Resolving it needs no similarity criterion, since the transfer between the two given
     addresses is looked up directly.
   - The roles follow Etherscan's filter semantics (`fadd` is "from", `tadd` is "to"). That
     is an interpretation, so it is pre-registered as such. It is falsified, and the case ends,
     if no transfer from `fadd` to `tadd` exists in the stated dates.
   - It adds a source organization (Scam Sniffer) and a pre-Fusaka 2025 period.
2. **webacy-6.88m-usdt-2025-09: include in Stage 2a, with a high-activity cap.**
   - A full victim, a firm analysis, and the largest loss in the list.
   - Resolution uses only the source's own prefixes.
   - Risks:
     - Webacy is an ML-detection vendor, so the case was selected by a detector, which favours
       visible poisoning;
     - the stated similarity is weak, so the lookalike subtype is atypical;
     - a busy wallet may exceed the per-window cap. That fails closed as *not evaluable:
       budget*, and it is reported.
3. **pink-drainer-10eth-2024-06-27: defer** (not in Stage 2a). Four reasons:
   - the archive overlap is unresolved;
   - the harm is a native ETH transfer;
   - the resolution rule would rely on similarity, which is circular with the detector;
   - the cost is likely beyond any reasonable cap.

   It can be reconsidered only after the offline archive pass, as a Level II case.

**Diversity achieved:**
- **Organizations:** Bitquery (Stage 1), Scam Sniffer, Webacy.
- **Periods:** Feb 2025, Sep 2025, Aug 2026.
- **Mechanisms:** counterfeit token (Stage 1), plus at least one unknown subtype.

That is too few to cover subtypes: zero-value, dust and native ETH are absent at Level I.

## 6. Budget, from measured costs

### 6.1 Measured basis

| Window | Requests | Activity |
|---|---|---|
| Stage 1 pilot (incident) | 472, plus 3 for locate | 12 transfers, 2 wallet transactions, 0 retries |
| Earlier incident windows (n = 4) | 503 / 732 / 1,361 (min / median / max) | the 1,361 came from retries |
| Background windows (n = 9) | 443 / 450 / 534 | quiet wallets |

**The cost model:**
- **Fixed floor:** about 443. That is two log scans of 216 chunks each, plus about 11 calls.
- **Activity:** one timestamp per referenced block, one sender lookup per outgoing transfer (at most 500), and one block read per wallet transaction.
- **Retries:** up to ×4 on the free endpoint.

A quiet wallet such as the pilot's costs 470–500. A busy wallet can cost several thousand.

### 6.2 Per-case limits (proposed)

Each case gets its own hard cap, set by expected activity rather than a flat figure. A case that
reaches its cap is *not evaluable: budget*, and its leftover requests are not reused.

| Case | Resolution step | Recording | Case cap | Expected |
|---|---|---|---|---|
| scamsniffer-763k | timestamp bisection for the date bounds (≤ 60), then a Transfer-log query filtered on `from = fadd, to = tadd` over about 21,600 blocks in 100-block chunks (≤ 240) | activity unknown: 2,000 | **2,300** | about 750 |
| webacy-6.88m | timestamp bisection (≤ 60), then USDT Transfer logs filtered on `from = victim` over about 43,200 blocks (≤ 480) | probably busy: 3,000 | **3,540** | about 1,500 |
| **Stage 2a total** | | | **5,840** | **about 2,250** |

**Revised in Step 0, before any request:** the caps are **2,400 / 3,600 / 6,000**, as given in `preregistration-stage2a.md` §2. The resolution caps above left out the chain check, the head read and up to 10 receipt reads; the resolution steps are now 400 and 600.

**Stage 2b (user-sourced cases).** These need full identifiers including the harm tx, so
`locate` takes at most 20 requests each.
- **Per case:** 20 for locate plus a 2,000 recording cap.
- **For 8 cases:** an expected 8 × (20 + 832) ≈ 6,800 at the measured incident mean, under a stage cap of **14,000**. That leaves room for retries.
- **Busy wallets:** if they push cases into the cap, the stage stops when the cap is reached, and the rest are *not evaluable: budget*.

**Cumulative:**
- **Spent:** 475 (Stage 1).
- **Proposed:**
  - Stage 2a: 6,000 at most (revised), about 2,250 expected;
  - Stage 2b: 14,000 at most, about 6,800 expected.
- **Total:** at most 20,475, about 9,500 expected.

**The fail-closed cap introduces a bias.** It drops busy wallets, so the evaluated sample leans
towards quiet wallets, where the detector's job is easier. The number of cases dropped at the
cap is reported in every summary.

**Prerequisite (0 RPC, code only):** Stage 2a needs a small command that finds Transfer logs
between given addresses in a date range, under the ledger. `replay locate` reads only by hash.
It is mock-tested like the Stage 0 tools, and nothing else is added.

## 7. Statistical protocol review

**Ten cases are a feasibility threshold, not a basis for generalization.**

| Question | n = 10 untied cases | What reliability would need |
|---|---|---|
| **Sign test** (OP1 vs OP0, one-sided α = 0.05) | needs ≥ 9 of 10 better (p = 0.011). Power if OP1 is truly better in 70 / 80 / 90 % of cases: **0.15 / 0.38 / 0.74** | 80 % power needs n = 37 (70 %), 23 (75 %), 18 (80 %) |
| **Warning coverage** (exact 95 % Clopper–Pearson) | 10 of 10 → [0.69, 1.00]; 7 of 10 → [0.35, 0.93] | n = 40 at 32 of 40 → [0.64, 0.91] |
| **Rankable vs recorded** | cases with k = 1, or with the target unwarned, are ties or unrankable. Ten recorded may give fewer than 10 rankable | report both counts; Gate H counts only untied, rankable cases |

**Further threats the current protocol does not address:**
1. **Clustered cases.** Guan and Li attribute 98 % of phishing addresses to four entities.
   Cases from one campaign are not independent, so the sign test overstates n.
   - **Proposed:** record each case's funding or signer infrastructure from the fixture
     (pre-cutoff data only).
   - Report the number of distinct clusters.
   - Make the sign test cluster-level, one vote per cluster.
2. **Selection on outcome and on detectability.**
   - Public cases are large losses that firms' own tools noticed, which favours visible
     poisoning.
   - Results describe *documented* thefts, not all thefts.
   - With no negatives there is no false-positive rate, precision or recall.
3. **Censoring.** The 3-day window caps the observable lead time, and plantings before the
   window are missed. One Cyvers alert reports a planting 66 days before the theft. Lead
   times are therefore reported as censored at the window start, and the share of cases whose
   first planting falls before the window is reported.
4. **The budget-cap bias**, described in §6.2.
5. **The rule allows a pass on one case.** Protocol 12.3 §10 gives PASS WITH LIMITATIONS
   with one case.
   - **Proposed amendment, frozen before any Stage 2 request:** below 6 untied rankable
     cases, Gate H is reported as **DESCRIPTIVE**, never PASS. The Stage 1 label above stays
     on record.
6. **The effect measure depends on k.** Expected ranks are not comparable across different k.
   - **Proposed, pre-registered:** the normalized rank (r − 1)/(k − 1) and the paired
     difference OP0 − OP1 per case, with the raw ranks.
   - None of this changes OP0, OP1 or the detector.

**Recommendation:**
- Keep 10 untied, rankable Level I cases as the **feasibility** threshold for Gate H.
- State in advance that a PASS at n = 10 supports only "consistent with an advantage in
  documented cases".
- Treat roughly 25–40 clustered-independent cases as the scale for a reliability claim. Public
  sources alone cannot supply that at present (§2).

## 8. Recommended Stage 2 execution plan

**Step 0: no RPC; this approval is for code and documents.** Done: `../amendment-12.3-A1.md`, `replay find-transfers` and `ml incident-benchmark resolve`, and `preregistration-stage2a.md`.
1. Commit the protocol amendment of §7, before any Stage 2 request:
   - DESCRIPTIVE below 6 untied cases;
   - cluster-level sign test;
   - normalized rank;
   - censored lead times;
   - count of cases dropped at the cap.
2. Add the capped transfer-finding command, with mock tests.
3. Pre-register Stage 2a:
   - the case manifests for `scamsniffer-763k-2025-02-20` and `webacy-6.88m-usdt-2025-09`;
   - the resolution rules of §5;
   - the date ranges;
   - the per-case caps of §6.2.

   A resolution that fails ends that case (*identifiers not confirmed on chain*), with no
   retry under another rule.

**Step 1: Stage 2a, needs approval of a 6,000 cap** (revised in Step 0).
- Sequence per case: resolve → `prepare` → `record` → offline `verify / run / report`.
- One ledger per stage. One restart per step after a transport error.
- Runs only after the same bounded resource preflight as Stage 1.

**Step 2: Stage 2b, needs a 14,000 cap and cases you source.**
- At least 8 incidents, each with a harm tx hash and a public write-up.
- Prefer:
  - zero-value, dust and native-ETH subtypes;
  - different source organizations;
  - 2024–2026.
- I check and pre-register them offline before any request.

**Step 3, optional and separately approved:** the offline archive pass (about 1 h of HDD, no
RPC). It would turn the Pink Drainer case into a Level II candidate, or rule it out.

**Never:** recording before pre-registration, changing the detector or Recency in response to
an outcome, or pooling levels.

## 9. Remaining uncertainties

- **763k case:** whether `fadd` / `tadd` are the victim and the lookalike. It is falsifiable at
  resolution. Whether the loss was an ERC-20 transfer is also unknown.
- **Webacy case:**
  - whether the victim's window fits a 3,000 cap;
  - whether its weak-similarity lookalikes are poisoning in the protocol's sense, or the
    output of a vendor's model.
- **Stage 2b:** whether 8 or more fully identified incidents can be sourced at all. Public
  sourcing gave 0 fully eligible new cases out of 3 near-misses.
- **External validity of any 10-case result:** limited by clustering, selection on detection
  and loss size, and the 3-day censoring.
