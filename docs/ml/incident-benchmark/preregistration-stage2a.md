# Pre-registration: Stage 2a (two resolved public cases)

**Frozen:** 2026-11-03, in the commit that adds this file. That is before any Stage 2 request,
and before any detector output on these cases.

**Governing rules:**
- `protocol-12.3.md` and `../amendment-12.3-A1.md`;
- the shortlist and statistical review in `stage2-shortlist.md`.

**Status: not approved.** Stage 2a runs only after the user explicitly approves its cap.

## 1. Cases

The identifiers are copied verbatim from `stage2-candidates.json`. The resolution rules are
those frozen in `RESOLUTION_RULES` (`ml/incident_benchmark.py`).

| Order | Case | Source | Rule: sender → recipient | Token | UTC days |
|---|---|---|---|---|---|
| 1 | `scamsniffer-763k-2025-02-20` | Scam Sniffer via ForkLog | `0xf6b1539cc562c0ca5151825488eb8c3cdaf2b6e4` (Etherscan `fadd`) → `0x804051b0cbc20443943c4f363573ef9bb7793375` (`tadd`) | any | 2025-02-19 to 2025-02-21 |
| 2 | `webacy-6.88m-usdt-2025-09` | Webacy | `0xee7ada00c9e5f654c8f8ea0f355a1f3c50942732` → prefixes `0x418e0ddb`, `0x4186a058`, `0x4186a666`, `0x4186b115` | USDT `0xdac17f958d2ee523a2206206994597c13d831ec7` | 2025-09-14 to 2025-09-19 |

Deferred and **not** part of Stage 2a: `pink-drainer-10eth-2024-06-27`. Its resolution would
need a similarity criterion, which R1 excludes, and its overlap with the archive is unresolved.

## 2. Caps

Revised before any request from `stage2-shortlist.md` §6.2: the resolution caps now include
the chain check, the head read and up to 10 receipt reads.

| Case | `find-transfers` | `record` | Case cap |
|---|---|---|---|
| scamsniffer-763k | 400 (about 52 bisection + 216 log chunks + ≤ 10 receipts) | 2,000 | 2,400 |
| webacy-6.88m | 600 (about 52 + 432 log chunks + ≤ 10) | 3,000 | 3,600 |
| **Stage 2a** | | | **6,000** |

- **Ledger:** `data/ml/rpc/ledger-incident-stage2a.json`, with `--cap 6000` on every
  command. Each command also carries the `--max-requests` above.
- **No reuse:** the per-case caps add up to the stage cap, so no case can use another's
  leftover.
- **Endpoint:** `https://eth.drpc.org` only.

## 3. Commands (in this order, nothing else)

`RPC` stands for `--rpc-url https://eth.drpc.org --ledger data/ml/rpc/ledger-incident-stage2a.json --cap 6000`.
`OUT` stands for `data/ml/research/stage2a`.

**Preflight**, before the first command: the same bounded, read-only resource check as
Stage 1.
- At least 1.5 GiB of free RAM, with CPU and disk load moderate.
- Other projects' processes are never touched.
- At most 5 checks; then stop and report the blocker.

**Case 1:**
1. `cryptoguard replay find-transfers --sender 0xf6b1539cc562c0ca5151825488eb8c3cdaf2b6e4
   --recipient 0x804051b0cbc20443943c4f363573ef9bb7793375 --since 2025-02-19 --until
   2025-02-21 --max-requests 400 --out OUT/scamsniffer-763k-2025-02-20/found.json RPC`
2. `cryptoguard ml incident-benchmark resolve --case scamsniffer-763k-2025-02-20 --found
   OUT/scamsniffer-763k-2025-02-20/found.json`. **If it refuses**, case 1 ends and is reported
   as *identifiers not confirmed on chain*.
3. `cryptoguard ml incident-benchmark prepare --case scamsniffer-763k-2025-02-20 --located
   OUT/scamsniffer-763k-2025-02-20/found.json --title "Scam Sniffer-reported poisoning loss,
   Feb 2025" --first-report 2025-02-26`
4. `cryptoguard replay record scamsniffer-763k-2025-02-20 --cases-dir
   docs/ml/incident-benchmark/cases --max-requests 2000 RPC`

**Case 2:** the same four steps, with these values:
- `find-transfers`: `--sender 0xee7ada00c9e5f654c8f8ea0f355a1f3c50942732 --token
  0xdac17f958d2ee523a2206206994597c13d831ec7`, then `--recipient-prefix` once for each of
  `0x418e0ddb`, `0x4186a058`, `0x4186a666` and `0x4186b115`, then `--since 2025-09-14 --until
  2025-09-19 --max-requests 600`.
- `prepare`: `--title "Webacy-reported USDT poisoning loss, Sep 2025" --first-report
  2026-11-03`. The first-report date is the read date, used as an upper bound, because no
  exact publication date was read.
- `record`: `--max-requests 3000`.

**Evaluation, offline:**
- `cryptoguard ml incident-benchmark verify`, then `run`, then `report`, each with `--out
  OUT`.
- The default manifests are `candidates.json` and `stage2-resolved.json`, so the Stage 1 case
  is evaluated with them.

## 4. What is reported, whatever the outcome

**Per case:**
- RPC usage per step;
- whether the case was resolved, refused or stopped at the cap;
- the resolved identifiers;
- the overlap audit on them;
- Gate C;
- the planting status. No planting transaction was reported, so it is "not reported".
- data completeness;
- candidate recovery;
- warning and lead time, measured from header timestamps, with the censoring flag;
- k, the OP0 / OP1 / random ranks and the normalized ranks;
- the perturbations;
- `cluster_signers`.

**Summaries:**
- Level I with and without resolved cases;
- Gate H under amendment A1. With at most 3 Level I cases it is DESCRIPTIVE by construction.
- the protocol 12.3 labels alongside;
- `new_cases_not_recorded`.

**Not claimed:** any rate, any generalization, or independent ML validation.

## 5. Stop rules

- **Caps:** stop at each per-command cap and at the stage cap. A case that hits a cap is *not evaluable: budget*, and its leftover is not reused.
- **Restarts:** one restart per step after a transport error. A second failure is *not evaluable: RPC*.
- **Falsified resolution:** if `resolve` refuses, the case ends. There is no role swap, no wider dates and no other rule.
- **No substitutes:** no other endpoint, no paid API, and no other RPC process at the same time.
- **No tuning:** nothing is tuned on the outcome. A defect found is fixed in the open, and the original output is kept.
