# Pre-registration: outcome-blind `observation/2` replay of the Stage 2a window

**Frozen:** 2026-11-08, in the commit that adds this file. That is before any request for this replay.

**Status:** run on 2026-11-08/09 under an approved 2,500 cap. It used 1,299 requests: attempt 1 hit a rate limit after 596 and wrote no fixture, and the one restart used 703. **V1–V5 all passed.** See `ML_OBSERVATION_COMPLETENESS.md` §35. This file was not changed before or during the run.

**Governing rules:** `docs/ml/protocol-12.4.md`, and `ML_OBSERVATION_COMPLETENESS.md` §33–34.

**Classification:** a **development-case regression**. The case and its planting (Q1b) are known. A success here shows that the wallet-centric path finds the planting blindly. It is not independent validation.

## 1. Input: the wallet, chain, window and collection settings only

| Field | Value |
|---|---|
| Wallet | `0xf6b1539cc562c0ca5151825488eb8c3cdaf2b6e4` (the victim) |
| Chain | 1 |
| Window | blocks 21,869,297–21,890,897: the same window as the frozen fixture (harm block − 21,600 to harm block, the rule fixed in Stage 2a) |
| Collection | `observation/2`, 100-block log chunks, receipts read for every nonzero native inbound transaction |

The command, `replay record-window`, reads **no manifest**. It never receives the paid address, the planting hash or the harmful hash. The output goes to a new file in the git-ignored research folder. **The frozen fixture `67e44177…` and the original C0 miss stay unchanged.**

```
cryptoguard replay record-window --wallet 0xf6b1539cc562c0ca5151825488eb8c3cdaf2b6e4
  --chain-id 1 --from-block 21869297 --to-block 21890897 --observation 2
  --out data/ml/research/phase12.4/blind-v2/fixture.json
  --rpc-url https://eth.drpc.org --ledger data/ml/rpc/ledger-blind-v2.json --cap 2500
```

## 2. Request cap requested: 2,500 (cumulative, retries included)

**Measured basis:** `observation/1` recorded this window in 645 requests. That was 9 transfers and 12 wallet transactions, in 12 distinct blocks.

| `observation/2` addition | Estimate |
|---|---|
| Balance reads at the edges of 13 runs without own transactions | about 26 |
| Increase blocks, k of them (at least 1: the planting). Each costs about 15 balance reads, 1 block read and 1 receipt. | about 17 × k, so about 340 if k ≈ 20 |
| Block reads for the 12 own-transaction blocks, plus receipts there | about 15 |
| Timestamps of the new blocks | about k |
| **Expected total** | **about 1,050** |

- **The cap:** 2,500, hard.
- **Retries:** included, through the durable ledger.
- **Stopping at the cap:** a run that hits it is *not evaluable: budget*, and no fixture is written.
- **Restarts:** one restart after a transport error, within the same cap.
- **Endpoint:** no other endpoint and no paid API.
- **Preflight:** the bounded resource check, plus a connectivity check through the local proxy.

## 3. Verification (fixed now; checked offline after recording)

| ID | Criterion |
|---|---|
| V1 | `native_inbound` contains transaction `0xf4530315e9248c4a677987a5f32797b0dbc17a12ff713c96421e4e8d9b0b2b83`, with all of these fields: sender `0x804051b0cbc20443943c4f363573ef9bb7793375`, block 21,890,540, transaction index 150, value 1,000,000,000,000 wei, and `succeeded` true **read from the receipt**. |
| V2 | Coverage `native_inbound_external` is `complete`. |
| V3 | The ERC-20 transfers and wallet transactions match the frozen `observation/1` fixture identity for identity. |
| V4 | At cutoff (21,890,897, 0), the same for every variant:<br>• C0 finds the 2 fake-token lookalikes;<br>• C1 also contains the paid address, as `lookalike_in`, native;<br>• C2 keeps the paid address, imitating `0x80404f3e…793375`.<br>Every other added candidate is reported, along with duplicates, abstentions and coverage. |
| V5 | `detector_outputs` is identical on the `observation/2` fixture and on its `observation/1` projection: production isolation. |

**If any criterion fails,** the result is reported as a failure of `observation/2` on a real window. Nothing is tuned and nothing is re-run under different settings.
