# Independent incident benchmark (Phase 12.3)

| Item | Value |
|---|---|
| Protocol (frozen before discovery) | [`docs/ml/protocol-12.3.md`](docs/ml/protocol-12.3.md), `f0e4dc1` |
| Code (committed before it ran) | `57273fd`: `ml/incident_benchmark.py`, `cryptoguard ml incident-benchmark verify / run / report` |
| Candidate manifest (public identifiers and URLs only) | [`docs/ml/incident-benchmark/candidates.json`](docs/ml/incident-benchmark/candidates.json) |
| Amendments | [12.2 follow-up audit](docs/ml/amendment-12.2-unconfirmed-audit.md); [frozen-cohort overlap](docs/ml/amendment-12.2-cohort-overlap.md) |
| Outputs (git-ignored) | `data/ml/research/phase12.3/` |
| RPC requests / downloads | 0 / none (Phase 12.3); 475 in the Stage 1 pilot (§28) |
| Stage 1 pilot result | [`docs/ml/incident-benchmark/pilot-result.md`](docs/ml/incident-benchmark/pilot-result.md) |

## 1. Executive summary

**Classification: data-limited.** No incident at evidence Level I or II can be evaluated
with the authorized data, and the 4 recorded Level III incidents are excluded by the frozen
protocol.

- **Discovery.** A bounded search (7 searches, 7 page reads) found 10 candidate incidents.
  - The only *new* incident with complete verbatim identifiers is a counterfeit-USDT theft
    of 9 August 2026. That is after the local archive ends (June 2024), and there is no
    recorded wallet stream for it. Evaluating it needs an RPC recording of about 500–1,400
    requests, which is not authorized.
  - Every other new candidate lacks identifiers. Article sources rarely quote the victim
    and lookalike in full.
- **Overlap audit.** It found a **real protection defect**: all 4 recorded incident windows
  hold frozen Cohort B items.
  - Frozen addresses even appeared among the competing warnings in 3 incidents.
  - Phase 12.2's incident result (H3) and background diagnostic (E14) therefore broke the
    cohort rules. Both are withdrawn, and the code now enforces the exclusion everywhere.
  - Archive results are unaffected, as a corrected re-run confirms.
- **Phase 12.2 audit.** The follow-up's numbers are consistent, and its exact p is 0.0625
  (§3).
- **Software delivered:** an offline, reproducible benchmark (`verify / run / report`).
  - **Ready:** it can evaluate new incidents as soon as their windows are recorded.
  - **Tested:** it is tested end to end on a synthetic incident.
  - **Safe:** it rejects oracle candidate lists, and never computes a case that holds
    frozen items.

## 2. Research questions

| Task | Question | Answerable here? |
|---|---|---|
| A | candidate generation | not on real Level I/II cases |
| B | warning generation | not on real Level I/II cases |
| C | prioritization | not on real Level I/II cases |
| D | lead time | not on real Level I/II cases |
| E | robustness | implemented; synthetic only |
| F | generalization | blocked by data |

## 3. Phase 12.2 consistency audit

The details are in [`amendment-12.2-unconfirmed-audit.md`](docs/ml/amendment-12.2-unconfirmed-audit.md).

**Attrition** is a complete partition:

| Stage | In | Out |
|---|---|---|
| Unconfirmed rows | 13,683 | 616 distinct senders |
| Phase 12.1 victims and protected wallets removed (107 + 2) | 616 | 507 |
| No earlier planting by the paid address | 507 | 8 (499 removed: 488 never planted, 11 only after) |
| Single candidate | 8 | **7 episodes** |

**B0 = 0.0238** is (1/6)/7, under the same equal-weight, tie-averaged top-1 as T0:
- in 6 episodes, another candidate is strictly first;
- in 1, B0 abstains (no outgoing history) and scores 1/6 at random.

It is directly comparable with T0's 5/7.

**Statistics:**

| Measure | Value |
|---|---|
| Exact two-sided sign flip (2⁷ = 128 patterns) | p = 0.0625 (reported Monte Carlo: 0.064) |
| Exact sign test (5 wins, 1 loss, 1 tie) | p = 0.219 |
| T0 strictly first in 5/7 | 95% Clopper–Pearson [0.29, 0.96] |
| Bootstrap interval | not meaningful at n = 7 |

The decision is unchanged: inconclusive.

## 4. Incident discovery methodology

The search was bounded and pre-registered (protocol §4). Sources were preferred in this
order: security-firm investigations and postmortems, then research papers, then news that
quotes identifiers.

- **No identifier was inferred.** A truncated or absent identifier is recorded as such.
- **Not used:** social-media posts (X), since they could not be read, and they are
  secondary sources.

## 5. Evidence sources

| Source | Cases |
|---|---|
| Bitquery on-chain investigation | 4 cases, with full identifiers for 3 |
| Decrypt (citing PeckShield, Cyvers, AMLBot, Bubblemaps) | 1 |
| Cointelegraph / The Block (citing Forbes and an FBI warrant) | 1 |
| crypto.news (citing Cyvers and Scam Sniffer posts) | 2 |
| The project's own replay manifests | 4 |
| Guan & Li, CCS 2024 | not readable without new tooling; Poison-Hunter family |

## 6. Inclusion criteria

- **Chain:** Ethereum mainnet.
- **Mechanism:** address poisoning.
- **Identifiers:** a verbatim harmful transaction hash, or the victim and lookalike.
- **Verification:** a local on-chain record (a recorded fixture, or the archive for blocks
  15,053,226–20,208,032).

## 7. Exclusion criteria

A case is excluded when any of these holds:
- the chain is wrong or unstated;
- identifiers are absent or truncated;
- it duplicates a fixture;
- it overlaps a frozen review cohort.

## 8. Benchmark independence assessment

| Level | Cases found | Evaluable |
|---|---|---|
| I (new, independent) | 1 with full identifiers (Aug 2026) | 0: not recorded locally; needs RPC |
| II (archive range or source family) | 1 in range (DEA, 2023), no identifiers | 0 |
| III (existing fixtures) | 4 | 0: excluded for frozen Cohort B overlap |
| IV (synthetic) | tests only | software correctness only |

**Overlap results:**
- **The new full-identifier case** overlaps none of the 17 local reference sets. Every set
  was readable.
- **The 4 fixtures** overlap `archive:incident_*` (expected: these are the archive targets
  built from them) and `frozen_cohorts:addresses` (the victim wallet).

## 9. Incident provenance

`candidates.json` holds every case: source URL, publisher and date, mechanism, verbatim
identifiers or their status, fixture link, and synthetic flag.

**Cross-source check:** Bitquery's identifiers for the 50M USDT and 4,556 ETH incidents
match the fixture manifests exactly (victim, recipient, harmful transaction). That is
independent confirmation of their provenance.

## 10. Available historical observations

| Source | Coverage |
|---|---|
| Recorded fixtures | complete transfer scans for a 21,600-block (about 3-day) window, with signers and the wallet's transactions; earlier history is missing (Bitquery reports the 4,556 ETH lookalike forging transfers 11 months earlier) |
| Archive | source-selected rows only, July 2022 – June 2024 |
| Incidents after June 2024 | no local record |

## 11. Point-in-time reconstruction

Implemented and tested:
- `trim(fixture, cutoff)`;
- `warnings_at(fixture, cutoff)`, which takes no outcome and fails if the detector sees a
  later block;
- the replay engine's leakage checks.

**Tests confirm:**
- rows after the cutoff cannot change the ranking;
- delayed cutoffs before the recorded window are reported as unobservable, not as misses.

## 12. Candidate-generation evaluation

**Not evaluated on real cases:** no Level I or II case is evaluable, and the Level III
cases are excluded.

On the synthetic incident, the generator recovers the outcome address from the stream alone.

## 13. Warning-generation evaluation

Not evaluated on real cases (§12).

## 14. Recency ranking evaluation

- **Not evaluated on real cases.**
- **Phase 12.2's H3 is withdrawn.** It was the only real-incident ranking evidence.
- **The archive evidence of Phase 12.2 still stands:** H2, recency ordering of production
  warnings on 1,057 episodes. It remains source-conditional and retrospective.

## 15. Historical lead-time analysis

Not evaluated on real cases. The method (the replay engine's first pre-harm warning, and the
first planting-signal lead) is implemented and tested.

## 16. Attack-subtype coverage

| Subtype | Candidates found | Evaluable |
|---|---|---|
| zero-value transfer | 3 (2 fixtures, Decrypt) | 0 |
| spoofed `transferFrom` | 1 (fixture) | 0 |
| counterfeit token | 1 (Aug 2026, full identifiers) | 0 |
| token airdrop | 1 (DEA) | 0 |
| unknown | 3 | 0 |

## 17. Negative controls

**No false-positive rate:** there are no verified negatives.

**Background windows,** with frozen items excluded:
- 6 windows produce 0 warnings;
- the 3 windows that produced warnings hold frozen items and are excluded.

Synthetic negatives serve only as invariants.

## 18. Temporal and graph feature analysis

No real-case evidence was produced. No hypothesis was tested on new data, and none is
claimed.

## 19. Failure taxonomy

| Case | Category |
|---|---|
| Aug 2026 counterfeit USDT | research failure: no recorded stream (post-archive; RPC not authorized) |
| Apr 2025, $700K | research failure: identifiers incomplete (victim and lookalike not given) |
| Dec 2025, 2.38 WBTC | research failure: identifiers incomplete (victim absent, lookalike truncated) |
| DEA 2023 and two 2026 cases | research failure: no identifiers |
| 2026-08, $100K | excluded: chain not stated |
| The 4 fixtures | research failure: overlap with a frozen review cohort |

No case reached a detector, warning or ranking failure category.

## 20. Statistical uncertainty

- **Evaluable real cases:** 0, so no statistic is reported.
- **Gate H's PASS rule** needs at least 10 independent rankable cases (protocol §10).

## 21. Software improvements

- **New:** `ml/incident_benchmark.py`.
  - manifest schema with `extra="forbid"`, so there is no oracle candidate field;
  - the provenance, tier and overlap audit;
  - tier A replay, with candidates, warnings, OP0/OP1 expected ranks, lead times, alert
    burden and 6 perturbations;
  - the report renderer and the CLI.
- **Defects fixed:**
  1. **The frozen-cohort leak in replay windows** (amendment). `touches_frozen` is now
     enforced in H3, E14, availability and the benchmark.
  2. **`run` ignored `verify`'s exclusions.** It now computes only admitted cases.
  3. **The no-input sentinel (−1)** was mistaken for a future block. Cutoffs before the
     window are now reported as unobservable.
- **Tests:** 10 new benchmark tests, covering:
  - manifest validity and oracle rejection;
  - tiers by identifier, chain, date and synthetic flag;
  - unknown sets never counting as independence;
  - cohort exclusion, and fixture cross-checks with a mismatch;
  - end-to-end replay with exact ranks and lead time;
  - future-record invariance, and exclusion enforcement.

## 22. Runtime and memory

| Step | Time |
|---|---|
| `verify` | under 5 s |
| `run` (tier A on 4 fixtures, before exclusion) | 9 s |
| 12.2 corrected re-run | 38 s |

Every step stays under 400 MiB. No archive pass was needed.

## 23. Reproducibility

```bash
uv run --offline cryptoguard ml incident-benchmark verify
```

```bash
uv run --offline cryptoguard ml incident-benchmark run
```

```bash
uv run --offline cryptoguard ml incident-benchmark report
```

A missing input fails with a data-availability message. Nothing is fetched.

## 24. Licensing constraints

- **Committed:** public chain identifiers and source URLs.
- **Kept local:** archive-derived rows (CC BY-NC-ND) and per-case results.
- **Not reproduced:** article text, beyond identifiers and facts.

## 25. Limitations

1. **Discovery was bounded.** Better sources, such as firm alert feeds and X, were not
   readable here.
2. **Fixture windows are 3 days long,** so older plantings are invisible.
3. **No verified negatives.**
4. **Archive-range incidents** need identifiers that the reachable sources did not give.

## 26. Conclusions

- **No independent evaluation of real historical warning behaviour is possible** with the
  authorized data. This phase does not claim one.
- **The defensible evidence remains** Phase 12.2's source-conditional archive results (H1,
  H2).
- **Corrected in this phase:** the one piece of evidence that looked independent (H3) is
  withdrawn because it broke the frozen-cohort rules.
- **The benchmark is ready.** It is protocol-bound, offline, and enforces the exclusions.

## 27. Next research action

**Record and evaluate new incidents.** This is the precise, cheapest independent test:
- **Approve a capped RPC budget** to record pre-harm windows with the existing recorder:
  - the Aug 2026 counterfeit-USDT case, which has full identifiers;
  - newly sourced incidents, gathered from firm alert feeds by a person, since this
    environment can't read those feeds.
- **Pre-register** the first 10 rankable cases before recording.
- **Size:** 503–1,361 requests per 3-day window, measured. Ten cases need about 7,000–14,000
  requests, plus about 2 minutes of offline benchmark time.
- **Contribution:** the first Level I test of warning coverage, lead time, and OP1 against
  OP0, with Gate H decided by the frozen rule.

## 28. Addendum: Stage 1 pilot (2026-11-03)

The Aug 2026 counterfeit-USDT case was recorded exactly as pre-registered. That took
475 RPC requests of an approved 2,000. Details:
[`docs/ml/incident-benchmark/pilot-result.md`](docs/ml/incident-benchmark/pilot-result.md).

**The case:**
- It is now Level I, tier A.
- Gate C passes for it: the harmful transfer and the planting are both confirmed in the
  window.

**The detector, on pre-theft data only:**
- It recovered the theft recipient as a candidate.
- It warned 48 blocks (576 s) before the theft.
- The warning was one of 6, all of them lookalikes of the same intended recipient.

**The ranks:**
- OP1 (recency): expected rank 2.0.
- OP0: 4.0.
- Random: 3.5.

**What this changes:** this is one descriptive observation.
- **Gate labels under §10 of the frozen protocol:**
  - Gate G is reported as an exact count: 1 of 1 warned before the harm.
  - Gate H at Level I is **PASS WITH LIMITATIONS**: fewer than 10 cases, OP1 never worse and
    better in 1.
  - The phase classification becomes a **limited external case-study result**.
- **Correction (2026-11-03, Stage 2 preparation):** this section first said that Gates G and H
  were "not decided". That misapplied §10, and both labels are corrected above.
- **The labels are weak evidence.** The pilot pre-registration's statement that one case decides nothing still stands, and Gate I is still FAIL (1 of the 10 required). `docs/ml/incident-benchmark/stage2-shortlist.md` §7 proposes reporting
  fewer than 6 untied cases as DESCRIPTIVE, never PASS.
- **Not claimed:** a rate or independent ML validation.

## Benchmark result table

| Case | Level | Subtype | Outcome status | Mode | Candidate | Warning | Pre-harm | OP0 rank | OP1 rank | Lead | History | Main limitation |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| usdt-counterfeit-39890-2026-08-09 | I | counterfeit token | documented (Bitquery); confirmed on chain (§28) | evaluated | recovered | yes | yes | 4.0 | 2.0 | 48 blocks | 3-day window, planting inside | single source; 3-day history |
| usdt-700k-2025-04 | — | zero-value | documented (Decrypt) | not evaluable | unknown | unknown | unknown | — | — | — | none local | identifiers incomplete |
| wbtc-2.38-2025-12-18 | — | unknown | documented (Bitquery) | not evaluable | unknown | unknown | unknown | — | — | — | none local | identifiers incomplete |
| dea-usdt-55k-2023 | — | airdrop | documented (Forbes, via press) | not evaluable | unknown | unknown | unknown | — | — | — | archive range | no identifiers |
| usdt-100k-2026-08 | — | unknown | reported | excluded | — | — | — | — | — | — | — | chain not stated |
| usdt-50k-2026-10 | — | unknown | reported | not evaluable | unknown | unknown | unknown | — | — | — | — | no identifiers |
| 4 recorded fixtures | III | various | confirmed | excluded | not computed | not computed | not computed | — | — | — | 3-day windows | frozen Cohort B overlap |

## Decision gates

| Gate | Status | Evidence |
|---|---|---|
| B. Independent provenance | PASS FOR 1 CASE | the new case is independent on all readable sets and, since §28, confirmed on chain |
| B. Independent provenance | BLOCKED BY DATA | the new case is independent on all readable sets, but unverifiable on chain offline |
| C. Transaction verification | PASS FOR 1 CASE | §28: the Stage 1 pilot confirmed harm and planting on chain; the others lack identifiers |
| D. Point-in-time validity | PASS | implemented and tested (trim, cutoff guard, leakage checks) |
| E. Candidate availability | 1 of 1 (exact count) | §28: theft recipient recovered in 1 of 1 Level I case; no rate from one case |
| F. Operational replay | PASS FOR 1 CASE | §28: one admissible recorded stream; leakage checks pass |
| G. Warning coverage | 1 of 1 (exact count, per §10) | §28: warned 48 blocks (576 s, measured) before the theft in 1 of 1 Level I case |
| H. Ranking usefulness | PASS WITH LIMITATIONS (Level I, n = 1) | §28: OP1 better in 1, worse in 0; the §10 rule allows this label below 10 cases; descriptive only. H3 withdrawn. |
| I. Statistical support | FAIL | 1 independent case (§28), against the 10 required |
| J. Production safety | PASS | no detector, service or risk change; ranker isolated |
| K. Reproducibility | PASS WITH LIMITATIONS | offline commands; the inputs cannot be redistributed |
