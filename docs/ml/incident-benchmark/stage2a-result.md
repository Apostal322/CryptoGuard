# Stage 2a: result

**Run:** 2026-11-03, under `preregistration-stage2a.md` and `../amendment-12.3-A1.md`, which
were frozen in `fdffc05` before any request. CI passed on that commit: 9 of 9 jobs.

**Outcome:**
- **Case 1** (`scamsniffer-763k-2025-02-20`): resolved and recorded. It is a Level I case,
  and the detector **missed** it.
- **Case 2** (`webacy-6.88m-usdt-2025-09`): **not evaluable: RPC**. Two provider rejections,
  so the stop rule applied.
- **Overall:** descriptive only, with no rates.

## 1. RPC usage (exact; ledger `data/ml/rpc/ledger-incident-stage2a.json`)

| Step | Limit | Used | Result |
|---|---|---|---|
| Case 1 `find-transfers` | 400 | 275 (one `eth_chainId` timeout, retried) | scan complete; 6 matches |
| Case 1 `record` | 2,000 | 645 | complete: 9 transfers, 12 wallet transactions |
| Case 2 `find-transfers`, attempt 1 | 600 | 72 | `eth_getLogs` rejected by the provider (`rpc_request_rejected`) |
| Case 2 `find-transfers`, the one permitted restart | 528 (the step's remaining limit) | 441 | rejected again, much later in the scan |
| **Stage 2a total** | **6,000** | **1,433** | 4,567 unused. They do not carry over. |

**Endpoint:** `https://eth.drpc.org` only. No paid API was used.

**Why case 2 failed.** The two rejections came at very different points in the scan: about
chunk 20, then about chunk 390 of 432. That points to transient throttling on the free
endpoint, not a malformed query. The client does not keep the provider's error message, so
this is not confirmed.

The pre-registered rule allows no third attempt, and no other endpoint. Case 2 has no
manifest and no fixture. Its stage-total requests were not reused.

**Preflight.** The bounded resource check passed on the 4th of 5 checks before case 1: 1.7 GiB
free, disk queue 0.2. It passed on the 3rd check before case 2: 1.66 GiB free.
- Checks 1–3, and 1–2 before case 2, failed. Free RAM was 1.1–1.4 GiB, CPU 77–100 %, and the
  disk queue was up to 11. Unrelated netsentinel and causalverse jobs were running.
- No process was touched.
- CPU stayed high (78 %) when case 2 started. That step is network-bound.

## 2. Case 1: verification and resolution

| Check | Result |
|---|---|
| Rule (frozen) | oldest nonzero Transfer from `0xf6b1…b6e4` (`fadd`) to `0x8040…3375` (`tadd`) on 2025-02-19..21 UTC, signed by `fadd` |
| Found | 6 transfers of token `0x44ff8620…bf73` from `fadd` to `tadd`, blocks 21,890,897–21,891,033 (about 27 min). All succeeded, and all were signed by `fadd`. That fits the source's single "victim lost $763,662" (it names no token), and the Etherscan filter link's from→to reading. **The role reading was not falsified.** |
| Harmful transaction (rule) | `0x05ea701d3d53976632b228127cafedc84abe7dec8054051ebcc070f9ecd81ced`, block 21,890,897, 96,517,394,555,617,036,350,647 base units (96,517.39 if the token has 18 decimals, which was not read) |
| Overlap, re-run on the resolved identifiers before recording | none (victim, recipient, harm tx) |
| Gate C | PASS: the harmful transfer is in the window. The planting status is "not reported", since the source gave none. |
| Window | 21,869,297–21,890,897, complete scan, fixture `67e44177…5674f1`, now frozen by test |

## 3. Case 1: what the detector saw (pre-harm data only)

All times are measured from recorded block-header timestamps.

| Block | Time (UTC) | Event |
|---|---|---|
| 21,890,495 | 2025-02-20 22:19:23 | The victim sends token `0x44ff…` to `0x80404f3e…793375`. A wallet transaction 13 blocks later sends that address 600 ETH. This is the reference use. |
| 21,890,558 | 22:32:23 | A spoofed "from victim" transfer of a fake token, signed by `0x7730…Ba3f`, to `0x8045233d…793375`. **Warned.** |
| 21,890,871 | 23:35:23 | Another spoofed transfer, signed by `0x0C0b…2bb9`, to `0x804041c8…1f3375`. **Warned.** |
| 21,890,897 | 23:40:35 | **Theft:** to `0x804051b0…793375`. This is its **first** appearance in the recorded window. |

**Outcome:**
- **Candidates:** 2 were generated (the two warned lookalikes). The theft recipient was
  **not recovered**.
- **Classification:** `post_incident_only` under both visibilities. The case is recognised
  only once the theft itself is visible.
- **The two warned addresses** are lookalikes of the same reference address, and they are
  unlabelled. The victim paid a *third* lookalike of it.
- **Not rankable:** the target was not warned, so there are no OP0 or OP1 ranks. k = 2.
- **Gaps:**
  - `cluster_signers` is empty, since the target has no pre-harm record.
  - `lead_possibly_censored` does not apply.

**Why it was missed.** This is a coverage miss, not a ranking failure. The theft recipient
leaves no ERC-20 Transfer to or from this wallet before the theft. The recorder stores Transfer
logs in both directions and the wallet's own transactions, but **not incoming native-ETH
transfers or internal transactions**.

**A hypothesis, not a finding:** a planting by native-ETH dust, a known variant, would be
invisible to this recorder. It is not tested here, because that needs data the pre-registration
did not collect. Planting before the window is unlikely, since the reference use itself lies
inside the window, 402 blocks before the theft. Whether the victim had used the reference
address before the window is not observed.

## 4. Benchmark summaries (offline, `data/ml/research/stage2a/`)

| Level I | All (pilot + case 1) | Verbatim-only (pilot) |
|---|---|---|
| Tier A cases | 2 | 1 |
| Target recovered as a candidate | 1 of 2 | 1 of 1 |
| Warned before the harm (Gate G, exact count) | 1 of 2 | 1 of 1 |
| Rankable (target warned, k ≥ 2) | 1 | 1 |
| OP1 vs OP0 (better / equal / worse) | 1 / 0 / 0 | 1 / 0 / 0 |
| Gate H, amendment A1 | **DESCRIPTIVE** (1 cluster) | DESCRIPTIVE |
| Gate H, protocol 12.3 §10 (kept on record) | PASS WITH LIMITATIONS | PASS WITH LIMITATIONS |

Level III: no case is admitted (frozen-cohort overlap).

The pilot's result is unchanged, and its frozen regression test passes.

## 5. What this shows, and what it does not

**Shown:** of two independent documented thefts, the detector warned on the eventual recipient
before the harm in one. In the other it warned on two other lookalikes of the same address, but
never saw the one that was paid.

That second case is informative. Coverage depends on what the recorded stream contains, and
attackers can plant through channels the recorder does not observe. The same may hold for
wallets using CryptoGuard live. That is a hypothesis for the product, not a measured rate.

**Not shown:**
- **No rates.** There is no detection rate, precision, recall or false-positive rate, and 1 of 2 is not an estimate of coverage.
- **No ranking evidence.** One rankable case is DESCRIPTIVE under A1.
- **Not independent ML validation.**

**Limitations:**
- **Case 1's identifiers** were resolved on chain (R1). The roles came from Etherscan's filter semantics, which the chain did not contradict. The source gives no intended address and no planting.
- **Case 2:** its loss is not evaluated. The RPC failure is not a result about the case.
- **Selection:** both cases are public, large and firm-noticed.

## 6. Reproduce (offline)

`cryptoguard ml incident-benchmark verify`, then `run` and `report`, each with `--out
data/ml/research/stage2a`. The default manifests are `candidates.json` and
`stage2-resolved.json`.

**Update, 2026-11-04 (forward pointer; the result above is unchanged).** The native-ETH hypothesis in §3 was confirmed by an approved 17-request query. The paid lookalike sent the victim 10¹² wei at block 21,890,540, 357 blocks before the theft, in a class `observation/1` does not record. See `ML_OBSERVATION_COMPLETENESS.md` §34.
