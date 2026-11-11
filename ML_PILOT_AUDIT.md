# Audit of the option A pilot (2026-11-01)

Status: **reconstructed offline from the pilot's raw outputs (0 new RPC requests).** The
approved cap was 3,000 requests on `eth.drpc.org`. The remaining 364 are not used and are not
authorization for further collection. Regenerate the numbers with
`cryptoguard ml poisoning-report`; the tables are in [ML_POISONING_TABLES.md](ML_POISONING_TABLES.md).
Raw files stay in the git-ignored `data/ml/pilot/`.

## 1. What the pilot measured

- **Yield phase.** For each of the 149 valid Poison-Hunter rows, the pilot compared the
  victim's nonce at the start and end of the 7 days after the planting. For victims who
  signed 1–8 transactions, it located each one by nonce bisection and decoded it.
- **Cost phase.** It recorded random wallets over one day with `replay.record_window` and
  measured the requests used.
- The plan was frozen before the run (`plan.json`, SHA-256 `82ae27e0…`).

## 2. Reconstructed request accounting

| Item | Requests | Source |
|---|---|---|
| Smoke tests and range probes before the final run | 70 | `summary.json` (`started_used`) |
| Yield phase | 1,521 | sum of `requests` in `yield.jsonl` |
| Cost phase | 1,044 | sum of `requests` in `cost.jsonl` |
| Chain check at the start of the run | 1 | difference |
| **Ledger total** | **2,636** | `budget.json` |

The sum matches the ledger exactly. The ledger counts reservations, so a request cut off in
flight is counted whether or not the provider received it. Provider-side billing is not
reconstructed. Provider failures in the final run: 1 rate-limit error (cost phase, draw 14)
and 0 yield-phase errors.

## 3. Yield phase: corrected interpretation

| Outcome | Rows |
|---|---|
| `confirmed_direct_payment` | 0 |
| `no_direct_payment_observed_with_complete_declared_coverage` | 52 (35 signed nothing; 17 located and decoded) |
| `partial_coverage` | 0 |
| `unresolved` (signed more than 8 transactions; not inspected) | 46 (33 signed 9–100, 13 more than 100) |
| `not_evaluated` (signed 1–8 but the phase cap was reached) | 51 |

- **Declared coverage** is limited to transactions the victim signed: native ETH sends and
  `transfer(recipient, amount)` calls in blocks [planting + 1, planting + 50,400].
- **Not covered:**
  - `transferFrom` by a spender;
  - router and aggregator payments;
  - contract-wallet (relayed) payments;
  - permit-based transfers;
  - payments after the window.
- **The pilot's calldata check is weaker than the new verifier.** It did not check the
  receipt log or whether the token was genuine. `ml/payments.py` now requires a reviewed
  token, a successful receipt and a matching Transfer log. No pilot row would have been
  affected, because none matched at all.
- **Rows versus events.** The 149 rows contain 6 duplicate victim-events, so there are 143
  distinct ones. Rows are not independent observations.

**Correction to the earlier report.**
- `docs/ml/proposal-next-dataset.md` §11.2 gave a Wilson 95% upper bound of **0.069** on
  "the share of candidate rows that end in a payment".
- That bound is valid only **conditional on** the 52 complete rows being representative.
  They are not:
  - they are the victims who signed nothing or very little;
  - the 97 rows that were not checked are systematically the more active victims;
  - the 52 include duplicate events.
- The 0.069 bound therefore **does not apply to all 149 rows or to Poison-Hunter victims in
  general**. The supported statement: *0 confirmed direct payments in 52 rows checked with
  complete declared coverage; outcomes of the other 97 rows are unknown.* The proposal has
  been corrected.

## 4. Cost phase and the lost-data defect

- **Draws.**
  - 25 draws, of which 11 were eligible (an externally owned account with a nonce of
    20–2,000).
  - 6 eligible wallets signed more than 12 transactions in the day and were not recorded.
  - 1 eligible wallet was rate-limited after 170 requests.
  - 1 was skipped for budget.
- **Recordings.** 3 wallet-days were recorded completely, using **216, 224 and 351
  requests** inside `record_window`.

**The defect.**
- The pilot script (outside the package, untyped) read `fixture.transactions`. The replay
  model's field is `wallet_transactions`.
- The resulting `AttributeError` was caught by a broad `except Exception`, so the three
  completed recordings were logged as `error` and their fixtures were never written.
- No raw RPC responses, checkpoints or temporary files were kept, so the search for
  recoverable data found none.

**Recovered and lost.**
- **Recovered from the log:** request counts (exact) and transactions signed in the window
  (3, 6 and 12, from the logged nonce difference).
- **Irrecoverable:** transfer counts, payment counts and scan completeness. They are now
  explicitly `None` (`recorded_contents_lost`), never zero.

**Did it change the conclusions?** The cost numbers came from the request ledger, which is
intact. The lost payment counts were never used in a reported number, so no published figure
changes. The "1,500–2,500 requests per wallet-week" extrapolation stays an estimate, from
three wallet-days and biased low (busier wallets were excluded).

**Fix (`ml/pilot.py`).**
- Versioned pydantic records (`pilot-yield/2`, `pilot-cost/2`, `extra="forbid"`).
- `summarize_fixture` reads typed attributes that mypy checks.
- A stored fixture whose fields do not match `ReplayFixture` raises `PilotRecordError`
  instead of being read as zero.
- Legacy lines are migrated explicitly (`migrated_from`), and unknown versions or fields
  are rejected.
- A cut-off final JSONL line is reported and skipped; a corrupt middle line is an error.
- Regression tests: `tests/unit/test_ml_poisoning.py`. They cover the correct field, the
  old field, a missing field, a wrong type, an empty valid list, a truncated JSONL, schema
  versions, migration and deterministic reconstruction.

## 5. Provider observations (one free endpoint, not general)

- `eth.drpc.org` on its free plan rejected `eth_getLogs` ranges of 250 blocks or more and
  accepted 100. The error text claimed a 10,000-block limit, which is wrong.
- Throughput was about 4 requests/s (2,566 requests in 646 s).
- These describe one endpoint on one day. Providers with larger log ranges, or an indexed
  source, change the cost model (ML_RESEARCH_PLAN.md §4).

## 6. Request-budget hardening done in this phase

- `RequestLedger` now uses an OS file lock (`msvcrt`/`flock`), which the OS releases if the
  holder dies.
- **The P1 race this removes:** the previous lock file was broken after 60 s. Two waiting
  processes could both break a crashed holder's lock, and then both would hold it.
- Writes are fsynced before the atomic replace. That costs about 56 ms per reservation on
  this machine, capping one ledger at roughly 18 reservations/s, far above the free
  endpoint's 4 requests/s.
- Threads of one process queue on a blocking in-process lock before taking the OS lock.
  Without it, polling threads could starve under load: the full test suite showed one
  starved thread in a five-thread test. A lock timeout is fail-safe, because nothing is sent.
- New tests:
  - two separate processes sharing a cap;
  - a process killed while holding the lock;
  - a live holder (times out; the lock is not broken);
  - a zero budget (sends nothing);
  - rate limits and timeouts (counted as attempts);
  - the cap reached during retries;
  - five async workers on one client;
  - a truncated ledger file (fails closed).
- **Guarantee:** the recorded count is never below the attempts sent by budgeted clients. It
  exceeds them only by attempts reserved but never sent, for example after a crash.

## 7. Independent cross-check with Tsuchiya et al. (2026-11-02, 0 RPC requests)

- **Source.** Tsuchiya et al.'s `payoff_transfers_ethereum.csv` was downloaded with your
  approval: KiltHub DOI 10.1184/R1/29212703.v1, CC BY-NC-ND 4.0. It is kept local in
  `data/external/tsuchiya2025/` and its MD5 matches KiltHub's.
  - It lists 1,738 victim-to-lookalike token payoffs in blocks 16,060,625–20,207,365: 1,733
    in USDT, USDC or DAI, 5 in other tokens, and none in native ETH.
  - Parser and join: `ml/tsuchiya.py`. Tables: ML_POISONING_TABLES.md.
- **No contradiction.** None of the 52 complete-coverage rows has a payoff in the file, to
  any lookalike, at any time.
- **The 97 rows the pilot could not check:**
  - 76 of them fall inside the study period and its 3+4 lookalike definition (34
    unresolved, 42 not evaluated). The file has no payoff to the row's own lookalike for any
    of them.
  - **Line 74** (not evaluated): 11,653 blocks (about 1.6 days) after the planting, the
    victim paid about $5,032 to a *different* lookalike of the same address. That lookalike
    matched 3+6 characters; the row's own lookalike matched 7+6.
- **Line 87** (not evaluated): the row's lookalike had received about $5,973 from *another*
  victim, who meant to pay the same address, 12,053 blocks *before* this planting. That is
  independent evidence that this lookalike belongs to an attacker.
- **What this does and does not show.**
  - Missing from the file is weaker evidence than "no payment". The file lists only token
    payoffs to lookalikes that Tsuchiya et al.'s own pipeline detected, and only up to block
    20,207,365.
  - Whether their pipeline detected each Poison-Hunter lookalike can't be checked from the
    payoff file; that needs their attempt table (the 2.3 GB dump).
  - The result is consistent with a low success rate for each event, but it isn't a rate
    estimate: the rows are not a random sample, and 6 are duplicates.
- **Effect on the pilot outcomes: none.** Pilot outcomes record only payments the pilot
  observed itself. Line 74 shows that a *victim's* loss and a *given event's* outcome can
  differ: the payment went to a competing lookalike.

## 8. Coverage check against Tsuchiya et al.'s attempt archive (Phase 11.3, 0 RPC requests)

- The archive (34.9 million transfers, July 2022 to June 2024) lists the planting itself
  (same transaction, victim and lookalike) for:
  - **27 of the 52 complete-coverage rows**;
  - **62 of the 97 rows the pilot could not check** (39 not evaluated, 23 unresolved).
- For those 62 rows the study demonstrably tracked the attempt, and its payoff list
  confirms no ERC-20 payoff to the row's lookalike. This is stronger than the bare
  absence reported in §7. It still says nothing about ETH, other tokens or payments after
  June 2024.
- The remaining rows are mostly "dust" plantings below the archive's 3+4 lookalike rule.
  For most of them, the archive shows the same victim targeted by other lookalikes of the
  same address.
- The pilot's outcomes and the conditional 0.069 bound are unchanged. Details:
  ML_CROSS_DATASET_VALIDATION.md §10–12 and §19.

