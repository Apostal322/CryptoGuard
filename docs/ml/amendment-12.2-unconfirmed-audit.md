# Amendment: audit of the Phase 12.2 unconfirmed-payoff follow-up

**Basis.** This audit was made at the start of Phase 12.3. It uses the saved derived
subset (`data/ml/poisoning/unconfirmed/`), with no archive pass.
- **Output:** `data/ml/research/phase12.3/audit-12.2-unconfirmed.json` (git-ignored,
  aggregates and per-episode values without addresses).
- **Not changed:** the original results (`unconfirmed-recency.json`) and the decision.

## A. Attrition: a complete partition

| Stage | In | Excluded | Out |
|---|---|---|---|
| Unconfirmed payoff rows (pass 1) | 13,683 rows | — | 616 distinct senders |
| Phase 12.1 payoff victims | 616 | 107 | 509 |
| Protected review wallets | 509 | 2 | **507 U victims** |
| Victim also has a confirmed payoff row | 507 | 0 | 507 |
| Paid address planted no earlier transfer | 507 | 499 | 8 |
| Single candidate | 8 | 1 | 7 |
| Protected-entity overlap | 7 | 0 | **7 rankable episodes** (one per victim) |

The post-hoc split of the 499 is 488 that never planted and 11 that planted only after the
payment. Its "planted before: 8" equals the 7 episodes plus the 1 single-candidate victim.

The numbers in §25a were consistent. They were presented at different stages without this
table.

## B. B0 top-1 = 0.0238

Both methods use the same tie-averaged per-episode top-1 (`1/m` when the paid candidate is
among the m tied at the top, else 0), with every episode weighted equally.

| | Episodes | B0 top-1 |
|---|---|---|
| B0 ranks another candidate strictly first; the paid address scores 0 (it passes the detector against none of the victim's recorded recipients) | 6 | 0 each |
| B0 abstains: the victim has no observed outgoing row, so all 6 candidates tie at random | 1 | 1/6 |

So `0.0238 = (1/6) / 7`, which is directly comparable with T0's `5/7 = 0.714`. That 5/7
counts T0 as strictly first in 5 episodes; it is never tied there.

## C. Statistical significance

- **The reported p = 0.064** came from 10,000 random sign flips over 7 singleton groups.
  Only `2^7 = 128` patterns exist.
- **The exact two-sided p is 0.0625** (8/128). The smallest attainable p is 0.0156.
- **The exact sign test** gives p = 0.219 (5 wins, 1 loss, 1 tie).
- **T0 strictly first in 5 of 7** has an exact Clopper–Pearson 95% interval of
  [0.29, 0.96].
- **The bootstrap interval [0.357, 1.0] is not meaningful at n = 7.** It should be read as
  descriptive only.

**Correction:** report exact p = 0.0625 and exact counts. The decision is unchanged
(inconclusive). Future small-sample analyses report exact enumeration (protocol 12.3 §9).
