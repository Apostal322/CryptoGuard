# Amendment: frozen-cohort overlap in the recorded replay windows

**Found:** 2026-11-03, by the Phase 12.3 overlap audit (`cryptoguard ml incident-benchmark
verify`). This is a confirmed protection defect, and it is corrected below.

## What was wrong

Frozen **Cohort B** (`hard-negative-candidates/1`, 35 items) was drawn in Phase 11.5 partly
from recorded wallet windows.
- **8 of its items** have as their wallet the victim of a recorded incident: 2 for each of
  the 4 incidents in `replay/cases`.
- **3 of the 9 background windows** belong to protected wallets.
- **Competing warnings:** frozen addresses under review appear among the production
  detector's warnings at the cutoff in 3 of the 4 incidents, 4 warnings in total.

Protocol 12.1 §3 requires that no event of a frozen wallet enter any computation. Three
analyses broke that rule:

| Analysis | What it computed on those windows |
|---|---|
| Phase 12.1 `availability` (report §21) | candidate counts for P2 and P3 |
| Phase 12.2 **H3** (report §1, §15) | warning rankings, with frozen items among the competitors |
| Phase 12.2 **E14** (report §15) | warning burden on background windows; all 5 counted warnings came from protected windows |

Phase 12.3's first `run` had the same problem. It did not consume `verify`'s exclusions.

## What was not affected

- **No frozen item's label was used.** None exists: 0 human submissions.
- **Nothing was tuned, selected or fitted** on these windows.
- **Cohort files and hashes are unchanged.** `ml verify-research` passes.
- **The archive analyses are unaffected:** H1, H2, every E1–E13 result, and all of Phase
  12.1's confirmatory results. They already excluded protected wallets as episodes and as
  graph edges.
- **A corrected re-run confirms this:**
  `data/ml/research/phase12.2/recency-validation-corrected.json` differs from the original
  only in H3, E14 and timing fields.

## Correction

- **New check:** `recency_validation.touches_frozen` flags a recorded window when its wallet
  is a frozen address, or when any transfer's party or transaction is frozen.
- **Applied in:**
  - `incidents()` (H3);
  - `background()` (E14);
  - `lookalike_study.availability()`;
  - `incident_benchmark.run()`, which now also computes only the cases `verify` admitted.
- **Corrected values:**
  - **H3: all 4 incidents are excluded.** The Phase 12.2 statement "3 of 3 rankable incidents
    rank the recipient first" is **withdrawn**.
  - **E14:** 6 windows remain, with 0 warnings; 3 windows are excluded.
  - **12.1 availability:** recomputed with the exclusion on any re-run. The saved Phase 12.1
    output is preserved as it was.
- **Superseded output:** the unenforced Phase 12.3 run output is preserved locally as
  `data/ml/research/phase12.3/incident-benchmark.SUPERSEDED-unenforced-exclusions.json`. It
  is not reported and not used.
- **Tests** cover each exclusion.

## Consequence

The 4 recorded incidents cannot serve as benchmark cases while Cohort B is frozen. They
become usable again as Level III regression cases only after the human review of Cohort B
is complete and its protocol releases the items.
