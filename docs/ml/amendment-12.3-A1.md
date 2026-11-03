# Amendment 12.3-A1: Stage 2 reporting and identifier resolution

**Frozen:** 2026-11-03, in the commit that adds this file. That is before any Stage 2 RPC
request and before any Stage 2 window exists. The only Level I outcome known at freezing is the
Stage 1 pilot (`incident-benchmark/pilot-result.md`).

**Amends:** `protocol-12.3.md`, §5, §9 and §10.

**Motivation:** `incident-benchmark/stage2-shortlist.md` §7.

**What is unchanged:**
- the detector, OP0, OP1 (Recency) and the perturbations;
- the window rule (H − 21,600 to H) and the cutoff (H − 1);
- the overlap audit and the evidence levels.

Everything here changes **reporting**, plus one new, rule-bound way to obtain identifiers.
Every metric of protocol 12.3 is still reported unchanged, beside the amended ones.

**Code:** `ml/incident_benchmark.py`: `RESOLUTION_RULES`, `resolve`, `amended_gate_h`,
`sign_test_p`, and the new fields of `ranking`, `run_case` and `run`. Also `replay
find-transfers` (`replay/record.py`: `find_transfers`, `block_at_time`). All of it is tested
on mock nodes only.

## R1. Identifier resolution (amends §5)

Protocol 12.3 admits only identifiers a source gives verbatim. A case whose source gives full
addresses but no harmful transaction may still enter, under four conditions:

1. **The rule is frozen in code before any request.** It lives in `RESOLUTION_RULES` and
   fixes:
   - which reported identifier is the sender and which the recipient, or the reported recipient prefixes;
   - the token, if the source names it;
   - inclusive UTC dates around the reported date.
2. **The query is exact.** `replay find-transfers` returns ERC-20 Transfer logs from the
   sender (to the recipient, if given), with nonzero value, oldest first, and reads the
   receipts of the first 10.
   - `resolve` refuses output whose query differs from the rule, or whose scan is incomplete.
3. **The harmful transaction** is the oldest match whose transaction succeeded and was signed by
   the sender, and which carries the Transfer.
   - A transfer that an attacker signed "from" the victim (a counterfeit-token or
     `transferFrom` spoof) is therefore never taken as the theft.
   - If no match qualifies, the case ends as *identifiers not confirmed on chain*. No second
     rule and no other dates are tried.
4. **No similarity is scored.** The rule uses only the source's identifiers and dates. A case
   whose resolution would need a lookalike-similarity criterion is not admitted under R1.

**Reporting:** a resolved case carries `identifier_source: resolved` in `verify`. Level I is
summarized twice, with resolved cases (`summary_level_I`) and without them
(`summary_level_I_verbatim_only`).

The overlap audit runs again on the resolved identifiers (lookalike and harmful transaction)
before anything is recorded.

## R2. Gate H (amends §10)

| Status | Condition |
|---|---|
| NOT EVALUATED | no rankable case |
| **DESCRIPTIVE** | fewer than 6 untied clusters. This replaces "PASS WITH LIMITATIONS", which a single case could reach. |
| FAIL | more clusters worse than better |
| PASS | at least 10 rankable clusters, more better than worse, and an exact one-sided sign test over the untied clusters with p < 0.05 |
| NOT PASSED | otherwise |

**Clusters:**
- Two cases share a cluster when the planting transfers involving their outcome address have a transaction signer in common.
  - The signers come from the recorded fixture, at or before the cutoff, with the victim excluded.
  - The link is transitive.
- A cluster votes better, worse or equal by the majority of its cases' paired differences.
- A case with no known signer is its own cluster, and is counted as `linkage_unknown_cases`.

Rankable is unchanged: the target is warned and k ≥ 2.

**What a PASS supports.** A PASS at the minimum of 10 clusters supports only this statement:
*consistent with an advantage of OP1 over OP0 on documented thefts*. It is not a reliable
generalization; `stage2-shortlist.md` §7 gives the power.

**The Stage 1 label stays on record.** Under protocol 12.3 it was PASS WITH LIMITATIONS
(Level I, n = 1). Under this amendment it is DESCRIPTIVE.

## R3. Added per-case measures (amend §9)

- **Normalized ranks:** (r − 1)/(k − 1) for OP0 and OP1, where 0 is first and 1 is last.
  Also the paired difference OP0 − OP1 in expected rank.
- **`cluster_signers`:** see R2.
- **`lead_possibly_censored`:** true when the outcome address's first record in the window
  lies within the window's first day (7,200 blocks).
  - Plantings before the window are unobservable, so any lead time is only a lower bound on the time since the attack began.
  - The number of censored cases is reported.
- **`new_cases_not_recorded`:** pre-registered cases with no complete window. These include runs that stopped at the cap (*not evaluable: budget*) or after a second transport error (*not evaluable: RPC*).
  - The cause of each is taken from the ledger notes and the stage report.

## R4. Unchanged prohibitions

- No outcome may change the detector, OP0, OP1, the rules above, or which cases are reported.
- No pooling of levels.
- No rates: no detection rate, precision, recall or false-positive rate.
- No interval methods below 10 independent clusters, other than the exact counts and the
  Clopper–Pearson intervals stated in advance in `stage2-shortlist.md` §7.
