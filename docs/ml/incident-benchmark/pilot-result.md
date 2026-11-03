# Incident-recording pilot (Stage 1): result

**Run:** 2026-11-03, under `preregistration-pilot.md`. The pre-registration and the methods
were unchanged. **Evidence:** one Level I case. The result is descriptive only: it decides no
gate, and it gives no rate.

## 1. RPC usage (exact)

| Step | Requests (retries included) | Ledger total |
|---|---|---|
| `replay locate` (harm tx, planting tx) | 3 | 3 |
| `replay record` (21,601-block window) | 472 | 475 |
| `prepare`, `verify`, `run`, `report` (offline) | 0 | 475 |
| **Approved cap** | | **2,000** |

**Endpoint and ledger:** `https://eth.drpc.org`, ledger `data/ml/rpc/ledger-incident-pilot.json`.

**What did not happen:**
- no restart and no transport error;
- no other endpoint, no paid API.

The 1,525 unused requests do not carry over.

**Timing:** locate ran at 15:51:46Z; recording ran from 15:52:16Z to 15:54:25Z.

## 2. Preflight and deviation

**Preflight checks.** Recording began after a bounded, read-only resource check, taken twice:
- free RAM, at least 2.1 GiB;
- CPU load, 9–38 %;
- disk queue, at most 1.7.

Before any request, I also checked four things:
- The ledger was absent, so 0 requests had been used.
- The ledger tests passed (29 tests, covering retries, crashes and concurrent processes).
- The endpoint completed a TLS 1.3 handshake. No HTTP request was sent.
- Both frozen cohort sheets match the hashes recorded when they were sent to reviewers:
  A `a0ec4b6e…`, 60 items; B `121c112d…`, 35 items.

**Deviation from §5.** One unrelated Python job was running (causalverse, about 60 MiB). The
pre-registration forbids "no other RPC or ML process at the same time". The user replaced that
rule with this resource-aware preflight. The job made no RPC requests and used a different
ledger. No process was stopped or changed.

## 3. Incident verification (Gate C for this case: PASS)

| Check | Result |
|---|---|
| Harmful tx `0x3740…80eb` | block 25,718,397; succeeded; signed by the victim; a USDT Transfer of 39,889.952535 from the victim to the lookalike `0x053dc459…da3a` |
| Planting tx `0xf84d…a10d` | block 25,718,349, 48 blocks before the harm, inside the window. It is a batch of 187 Transfer logs. One is a counterfeit-token (`0x647a…`) transfer of 115.147641 shown as from the victim to the lookalike. The batch was signed by `0x1584…c7DD`, not by the victim. |
| `prepare` | accepted; window 25,696,797 to 25,718,397 by the frozen rule |
| Overlap (all reference sets, both frozen cohorts) | none |
| Harm timestamp | 1786290239 (2026-08-09 UTC), as the source dates it |

## 4. Data completeness

- **The window is complete.**
  - The transfer scan is complete, with 0 sender lookups skipped.
  - The window holds 12 Transfer logs, 2 wallet transactions and 12 block timestamps.
  - Fixture: canonical SHA-256 `62b3744c…0573b8`.
- **The planting is inside the window**, so there is no coverage gap for it.
- **The legitimate-recipient history is only partly observed.**
  - The victim's real transfer to the intended recipient `0x053dba72…da3a` is inside the window, at block 25,718,331, 66 blocks before the harm. This is the use the attack copies.
  - Earlier history with that address, before block 25,696,797, is **not observed**. This report does not claim there was none.
- **What the window cannot show:**
  - planting attempts, or campaign activity, before the window;
  - earlier interactions of the victim with these addresses.

## 5. Point-in-time correctness

- **Cutoff:** harm block − 1 (25,718,396).
  - The whole harm block is excluded, so a same-block earlier transaction would also be hidden. This is conservative.
  - The detector's newest input was checked against the cutoff, and the replay leakage checks passed.
- **What the detector receives:** no manifest.
  - The harmful transaction, the victim label and the lookalike label are used only to look up the outcome afterwards.
  - Candidate generation runs on the trimmed fixture, in (block, tx index, log index) order.
- **The recorder** received only the victim and the window.
- **The theft recipient was never injected as a candidate.** It was recovered by the
  detector's own `spoofed_out` method.

## 6. Results (one case)

| Measure | Value |
|---|---|
| Candidates generated / distinct lookalikes | 9 / 6 |
| Theft recipient recovered as a candidate | yes (`spoofed_out`) |
| Warned at the cutoff | yes, `elevated_risk` |
| Outcome, ERC-20 only and full visibility | early warning in both |
| Lead time | **48 blocks (576 s, about 10 min)**, first warning at the planting block |
| Warnings at the cutoff (k) | 6 |
| OP0 (severity, then similarity) expected rank | 4.0 |
| OP1 (frozen recency) expected rank | **2.0** |
| Random expected rank | 3.5 |
| Top-1 under OP0 / OP1 | no / no |
| Warning set preserved by the ranker | yes |

**The other 5 warned addresses** all end in `…da3a`, the intended recipient's suffix, and two
also share its `0x053d` prefix, as the theft recipient does. They appeared in the same 60 blocks: a swarm of lookalikes of one
address.
- They are **unlabelled**. They are counted neither as false positives nor as true positives.
- OP1 put the most recent of them (`0x053d505a…`, an incoming 115-unit USDT transfer at block
  25,718,391) first, and the theft recipient second.

**Perturbations:**
- **No effect:** ERC-20 only, history limited to the last day, and duplicate records.
  Each gives the same k = 6 and the same ranks.
- **Signers unknown:** k = 5, OP0 4.5, OP1 2.0.
- **Cutoff delayed by 300 blocks or 1 day:** k = 0. The whole swarm arrived within 66 blocks of
  the harm, so no earlier cutoff had anything to warn about.

## 7. What this shows, and what it does not

**Shown, for this one wallet:**
- the production detector warned on the eventual theft recipient 48 blocks before the theft,
  from pre-theft data only;
- OP1 placed that recipient above OP0's expected position and above random.

**Not shown:**
- **No ranking gate.** Gate H needs at least 10 rankable cases, and an exact sign test needs at least 6 untied cases.
  This is 1 case, so OP1 "better" here is a single observation, not evidence of superiority.
- **No rates.** There is no detection rate, precision, recall or false-positive rate.
- **Not independent ML validation.** OP1 is a frozen ranking rule. It was not trained or tuned here, and nothing was tuned on this outcome.
- **No claim on warning burden.** The 6 background windows from Phase 12.3 hold 0 warnings. They are other wallets at other dates and are not a control for this one.

**Limitations:**
- **Source:** one public write-up (Bitquery). The lookalike label comes from that source and the on-chain transfer, not from an independent label.
- **History:** 3 days only; pre-window history is unobserved.
- **Lead time:** 48 blocks is short. Any realistic delay before showing a warning (300 blocks or more) would remove it entirely in this case.
- **Cutoff:** the cutoff has block resolution.

## 8. Reproduce (offline, from the committed case)

```
cryptoguard ml incident-benchmark verify --out data/ml/research/incident-pilot
cryptoguard ml incident-benchmark run --out data/ml/research/incident-pilot
cryptoguard ml incident-benchmark report --out data/ml/research/incident-pilot
```
