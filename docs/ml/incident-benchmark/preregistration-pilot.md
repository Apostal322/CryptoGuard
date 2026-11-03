# Pre-registration: incident-recording pilot (Stage 1)

**Frozen:** 2026-11-03, in the commit that adds this file. That is before any RPC request for
the case, before its window exists, and before any detector output on it.

**Budget plan:** `docs/ml/incident-recording-budget-plan.md`, Stage 1.

**Status:** Stage 0 is complete, and 0 requests have been made. Stage 1 runs only after you
explicitly approve its cap.

## 1. The case

| Field | Value (copied from `candidates.json`; never given to the recorder) |
|---|---|
| Case | `usdt-counterfeit-39890-2026-08-09` |
| Source | Bitquery, https://bitquery.io/investigations/address-poisoning-ethereum (2026; read 2026-11-03) |
| Mechanism | counterfeit token |
| Victim | `0xb83f1c98b6d799f8ec56a002f2c0a2c343a0f50e` |
| Lookalike | `0x053dc459bade1baf76aed6e8630823f8392fda3a` |
| Intended | `0x053dba7292957341779cb0e9aae1aa7b139ada3a` |
| Planting tx | `0xf84dacfeb3a92ae3291120d954b86d89932fe31702103754cad4f8e8ac41a10d` |
| Harmful tx | `0x374076fa28ed745227c28f42c5054a0bcd024c51ad7a41c17d52e7c6c24980eb` |

**Overlap check** (`ml incident-benchmark verify`, run offline in Stage 0): no identifier
appears in any local reference set. The sets covered are:
- both frozen review cohorts (A: 60 items, B: 35 items);
- every archive group;
- the Phase 12.1 and 12.2 target sets;
- Poison-Hunter.

No set was unreadable. The case therefore enters as a Level I candidate. The verify output is
byte-identical to Phase 12.3's, which shows that the Stage 0 code changes alter no existing
result.

## 2. Fixed before any request

- **Window rule:** the 21,600 blocks before and including the harmful block, H − 21,600 to H.
  This is the same rule as the 4 replay cases. The window is not widened or moved after
  anything is seen.
- **Recorder input:** the victim and the window only. The recorder never receives the
  lookalike, the intended recipient or any hash.
- **Methods:** the Phase 12.3 benchmark, unchanged in what it computes:
  - the production detector;
  - OP0 (severity, then similarity);
  - OP1 (the frozen recency order);
  - lead time;
  - 6 perturbations.

  Stage 0 only adds Level I bookkeeping, `prepare`, and the on-chain identifier check.
- **Case location:** `docs/ml/incident-benchmark/cases/<case>/`, kept apart from the packaged
  replay cases. `EVALUATION.md`, the replay cases and the frozen cohorts' source windows are
  unchanged.

## 3. Stage 1 commands (in this order, nothing else)

Every command uses `--rpc-url https://eth.drpc.org`, ledger
`data/ml/rpc/ledger-incident-pilot.json`, and `--cap 2000`.

1. **Locate** both transactions, at most 20 requests. Output goes to
   `data/ml/research/incident-pilot/located.json`.
   `cryptoguard replay locate <harm tx> <planting tx> --max-requests 20 --out …`
2. **Prepare** the manifest, offline:
   `cryptoguard ml incident-benchmark prepare --case usdt-counterfeit-39890-2026-08-09
   --located … --title "Counterfeit-USDT poisoning theft, Aug 2026" --first-report 2026-11-03`.
   - The first-report field uses the read date as an upper bound, since the page shows no
     publication date.
   - **If `prepare` refuses**, Stage 1 ends there. The case is then reported as
     *identifiers not confirmed on chain* and no window is recorded. `prepare` refuses when
     the harmful transaction is not found, failed, was not signed by the victim, or carries
     no Transfer from the victim to the lookalike.
3. **Record** the window, with the rest of the cap:
   `cryptoguard replay record usdt-counterfeit-39890-2026-08-09
   --cases-dir docs/ml/incident-benchmark/cases`.
4. **Evaluate** offline: `cryptoguard ml incident-benchmark verify`, then `run` and `report`,
   with `--out data/ml/research/incident-pilot`.

## 4. What is reported, whatever the outcome

**Gate C for this case:** `verify`'s on-chain check. It passes when two things hold:
- the harmful transfer from the victim to the lookalike is in the recorded window;
- the planting transaction, if inside the window, has the lookalike as a party.

A planting transaction before the window is reported as such. It is not a failure, and the
window is not extended.

**The case row:**
- whether the candidate was recovered;
- whether the detector warned at the cutoff, and the outcome per visibility;
- the lead time;
- k (the number of warnings);
- the OP0, OP1 and random ranks;
- the perturbations.

**What is not claimed:**
- **No ranking gate is decided.** Gate H needs at least 10 rankable cases, and an exact sign
  test needs at least 6 untied ones. One case is descriptive only.
- **No rates.** There is no detection rate, precision, recall or false-positive rate from a
  single positive case.

**No tuning.** Nothing is changed in response to the outcome. Any defect found is fixed in
the open, and the case is re-run with the original output kept.

## 5. Stop rules

- **The cap:** stop at the cap (2,000 in total, retries included). A run that hits it is
  *not evaluable: budget* and writes no fixture.
- **Restarts:** at most one restart per step after a transport error. A second failure is
  *not evaluable: RPC*.
- **No substitutes:** no other endpoint, no paid API, and no other RPC or ML process at the
  same time.
- **Leftover requests** are not authorization for anything else.
