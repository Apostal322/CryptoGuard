# Plan: RPC budget for recording new incident windows

**Status:**
- **Stage 0 is complete:** the recorder cap, the pre-registration
  (`incident-benchmark/preregistration-pilot.md`) and the overlap check are all done.
- **Stage 1 is complete** (2026-11-03): **475 of 2,000 approved requests** used
  (`incident-benchmark/pilot-result.md`). The other 1,525 do not carry over.
- **Stage 2 preparation** (0 requests): `incident-benchmark/stage2-shortlist.md`. Public
  discovery found no fully eligible new case. It proposes Stage 2a (2 public cases, cap
  6,000 after the Step 0 revision) and Stage 2b (user-sourced, cap 14,000), plus a protocol
  amendment.
- **Stage 2 Step 0 is complete** (0 requests): amendment `amendment-12.3-A1.md`, the
  resolution tools, and `incident-benchmark/preregistration-stage2a.md`.
- **No further request is authorized** by this document. Each stage below needs its own explicit approval of a request cap, and unused
requests from one approval do not carry over to the next.

**Purpose:** give the Phase 12.3 benchmark its first independently documented (Level I) cases.
This is the next action recommended in `ML_INDEPENDENT_INCIDENT_BENCHMARK.md` §27.

## 1. What one window costs (measured)

These are all 13 recorded windows. Each covers 21,601 blocks (about 3 days), was recorded on
`https://eth.drpc.org` with 100-block log chunks, and counts retries.

| Window type | n | Requests (min / median / max) | Mean |
|---|---|---|---|
| Incident (`replay/cases`) | 4 | 503 / 732 / 1,361 | 832 |
| Background (`replay/background_cases`) | 9 | 443 / 450 / 534 | 462 |
| All | 13 | 443 / 474 / 1,361 | 576 |

**Why the counts vary:**
- **The floor is about 443 requests.** That is two log scans (outgoing and incoming) of 216
  chunks each, plus about 11 calls for the chain check, nonce bisection, code and timestamps.
- **Activity adds cost:** a timestamp read per referenced block, a sender lookup per outgoing
  transfer, and a block read per wallet transaction. The WBTC window, with 340 transfers,
  cost 756.
- **The largest cost came from retries, not activity.** The 1,361-request window had only
  4 transfers and 2 transactions. Rate limiting on the free endpoint can multiply a window's
  cost by up to 4, since the client is set to 3 retries.

## 2. Defect found while planning: the recorder has no hard total cap

`cryptoguard replay record` (`replay/record.py`) builds a plain RPC provider. It does not use
the durable `RequestLedger` / `BudgetedTransport` that `ml collect` uses
(`ml/collect.py`, audited in `ML_GENERALIZATION_AUDIT.md` §14).

Its only limits are per step:
- up to 2,000 log requests, shared between the two scans;
- up to 500 sender lookups;
- up to 10,000 wallet transactions;
- one timestamp read per referenced block, with no upper bound.

So a single busy wallet could spend several thousand requests, more than any cap proposed
below, and a killed run would lose its count.

**Fixed in Stage 0:** `replay record`, `sample-background` and `record-background` now route
every attempt through `RequestLedger`, failing closed. They require `--ledger` and `--cap`,
with an optional per-run `--max-requests`.

A window that hits the cap is reported as *not evaluable: budget*, and no partial fixture is
written. Tests with counting mock transports cover this, along with a mocked dry run of the
whole Stage 1 chain.

## 3. Stages

### Stage 0: preparation (0 requests)

1. Add the recorder cap described in §2, with tests.
2. **Pre-register** the case manifest for `usdt-counterfeit-39890-2026-08-09`. The manifest
   gives only:
   - the victim;
   - the rule for the window: the 21,600 blocks before and including the harmful block, the
     same convention as the 4 existing incident manifests.

   It is committed before any request. Its identifiers come from `candidates.json` and are
   never given to the recorder.
3. **Run the offline overlap check (`incident-benchmark verify`) again.** The victim and both
   counterparties must touch neither frozen cohort, nor any other reference set.

### Stage 1: pilot, one Level I case

| Step | Requests |
|---|---|
| Locate the harmful block (`eth_getTransactionByHash`, harm tx; planting tx as a cross-check) | 2 (up to 8 with retries) |
| Record one 21,601-block window | 443–1,361 measured; about 2 min |
| **Proposed cap** | **2,000** |

**Endpoint and ledger:** the same free endpoint as before (`eth.drpc.org`), with a separate
ledger file (`data/ml/rpc/ledger-incident-pilot.json`).

**This stage settles:**
- whether the identifiers are verified on chain (Gate C for this case);
- whether the production detector warned before the harm;
- the lead time;
- the ranks under OP0 and OP1.

A single case decides no ranking gate. The protocol needs 10, and an exact sign test needs at
least 6 untied cases.

### Stage 2: nine more cases, which need you

- **Sourcing:** this environment cannot read firm alert feeds, so the 9 further cases need
  identifiers sourced by a person. Each needs a victim, a lookalike, and a harm tx with a
  public write-up.
- **Pre-registration:** all 9 are pre-registered and checked offline before any request.
- **Size:** 9 windows at a measured incident mean of 832 is about 7,500 requests expected,
  and about 12,250 at the measured maximum.

| Proposed cap | Value |
|---|---|
| Per window | 2,000 (fail closed) |
| Stage total | **14,000** |

With Stage 1, the 10 cases cost about 8,300 requests expected and at most 16,000 under the
caps.

### Stage 3 (optional): background windows for warning burden

Phase 12.3 excluded 3 of the 9 background windows because of the frozen-cohort overlap. Ten
fresh background wallets would restore a warning-burden estimate (E14) at the new incidents'
dates. The cost is about 460 requests each plus seeded sampling: a cap of **6,000**.

This stage is not needed for the ranking gate, and it is asked separately.

## 4. Stop rules (all stages)

- **The cap:** stop at the cap. A window that hits the per-window cap is not retried within
  the same approval.
- **One restart:** at most one restart per window after a transport error. A second failure
  marks the case *not evaluable: RPC*.
- **Endpoint:** no change of endpoint or provider, and no paid API, without a new approval.
- **Isolation:** no other ML or RPC process runs at the same time.
- **After recording:** fixtures are hashed and recorded in the run ledger. The benchmark then
  runs offline (`incident-benchmark verify → run → report`), and nothing is tuned on the
  outcome.

## 5. Approvals requested

| Approval | Cap | Required for |
|---|---|---|
| Stage 0 | 0 requests (code and docs only) | all later stages |
| Stage 1 | 2,000 | the first Level I case |
| Stage 2 | 14,000, after you supply 9 sourced cases | the ranking gate (Gate H) |
| Stage 3 | 6,000 | the warning-burden estimate (optional) |
