# Phase 12.2 protocol: deviations

The protocol is frozen at `03f1c1d` and is not edited. The analysis code was committed at
`623b36d` before it ran.

## D1. H2 not repeated without protected overlap (omission)

**Section 7 asks** for H1 and H2 to be repeated without the episodes that overlap a frozen
item.

**What happened:** only H1 was repeated. Its decision is unchanged: 1,058 episodes,
+0.382.

**The H2 gap is negligible:** exactly 1 episode overlaps, and one episode can move H2's
mean top-1 difference by at most 1/1,057 ≈ 0.001.

## No other deviations

- **Unchanged:** the populations, scorers, rules, tests, seeds and decision rules.
- **Exploratory permutation counts:** sensitivity analyses use 2,000 sign-flip draws, as
  allowed for exploratory output. H1 and H2 use 10,000, as pre-registered.
