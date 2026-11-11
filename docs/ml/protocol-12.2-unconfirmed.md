# Phase 12.2 follow-up protocol: recency on the source's unconfirmed payoffs

- **Task:** `recency-unconfirmed/1`.
- **Frozen:** committed before either archive pass runs, so no row, count or outcome of this
  population had been seen. The only facts known beforehand come from the Phase 11.3 scan
  summary:
  - the archive holds 13,683 rows flagged `payoff_transfer_unconfirmed`;
  - 143 of them touch Phase 12.1 victims.

Phase 12.2 (`docs/ml/protocol-12.2.md`) is unchanged.

## 1. Question

**Is the Phase 12.1 recency effect produced by the source's confirmation step?** The source
confirmed a payoff only after checking on Etherscan that "the poisoning transfer exists
between the intended and the payoff transfer". Its unconfirmed payoffs never went through
that check. If recency is strong there too, the confirmation step is not its cause. If it is
much weaker, the step is implicated.

**Classification:** same-source, never-examined, **label-uncertain** data. It is not
independent validation: the collection and the upstream flagging rules are shared.

## 2. Data (two offline passes; 0 RPC requests, no download)

**Pass 1** extracts every archive row with the `payoff_transfer_unconfirmed` flag to
`data/ml/poisoning/unconfirmed/rows.jsonl`. The file is git-ignored and hash-recorded.

**Pass 2** stores every archive row touching a **U victim** in
`unconfirmed/victim_subset.sqlite`.
- A U victim is the sender of an unconfirmed row.
- Excluded: Phase 12.1 payoff victims (the archive targets' `payoff_victims`), protected
  wallets and incident victims.
- As in Phase 12.1, this is the source-kept rows only, never a full wallet history.

## 3. Episodes (population U)

Phase 12.1 eligibility applies, with the unconfirmed flag in place of the confirmed one:
- **T** is the block of the victim's first unconfirmed payoff row it sent;
- **c** = T − 1;
- **candidates** are the source plantings at or before c;
- **eligible** when exactly one lookalike was paid in T, it planted at or before c, and
  k ≥ 2.

Further rules:
- The victim's outgoing rows that are themselves unconfirmed payoffs are excluded from the
  history B0 reads, as confirmed payoffs were in Phase 12.1.
- A victim with any confirmed payoff row is excluded.
- **Excluded upfront:** episodes that share an entity with a frozen review item. That means
  a candidate, or a planting counterparty, that is a protected wallet or address under
  review, or a planting transaction that is a protected transaction. All are read from the
  blinded sheets.
- **Reported:** episodes that share a candidate lookalike or a planting transaction with any
  Phase 12.1 episode (infrastructure overlap).

## 4. Scorers

Frozen and unchanged:
- **T0** (`lookalike-features/1`);
- **B0**, the production similarity;
- **OP0 / OP1** (`poisoning-warning-rank/1`, protocol 12.2 §2).

Nothing is tuned.

## 5. Tests and decision rules

**U-H1 (primary):** `Δ_U = top-1(T0) − top-1(B0)` on all U episodes.
- Paired, clustered on U's own linkage groups (shared candidate lookalikes; protocol 12.1
  §7 fallback rule).
- 10,000 sign flips and 2,000 bootstrap draws, seed 20261104.
- Decided with protocol 12.2 §4: survives, explained or null, or inconclusive.

**U-H2 (contrast):** `D = Δ_R − Δ_U`.
- `Δ_R = 0.3817` is the Phase 12.2 value on all 1,068 R episodes.
- Its 95% interval comes from an independent group bootstrap of both populations, 2,000
  draws.
- **Confirmation implicated:** the CI lower bound is above 0 and `D ≥ 0.19`, half of `Δ_R`.
- **Not implicated:** the CI upper bound is below 0.19.
- **Inconclusive:** otherwise.

Holm is not applied: U-H2 is interpreted only together with U-H1.

**Phase conclusion:**

| U-H1 | U-H2 | Conclusion |
|---|---|---|
| survives | not implicated | the confirmation step does not explain recency |
| explained or null | implicated | recency is plausibly a confirmation artifact |
| any other combination | — | inconclusive |

## 6. Exploratory analyses (no confirmatory claims)

UE1. **The rule on U itself.** U episodes are split by whether the paid candidate satisfies
SR_any, and separately SR_latest. T0 and B0 are reported in each part.
- *Fails the rule* means these payoffs would not have passed the source's check, as we read
  it.
- This split stratifies on an outcome attribute and is labelled so.

UE2. Random, the within-episode permutation of T0, and oldest-first.

UE3. Strata by year, paid subtype and k bin, with group counts.

UE4. **Production replay:** OP1 against OP0 on production warnings over the archive rows at
or before c, as H2 in Phase 12.2.

UE5. U-H1 without episodes that share infrastructure with Phase 12.1.

UE6. Exclusion counts, k distribution, and the share of paid candidates warned by
production.

## 7. Limitations fixed in advance

1. **Unconfirmed labels are uncertain.** Some may be deliberate payments to a lookalike-like
   address, or transfers the source did not check. A null result could therefore come from
   label noise rather than from the confirmation step.
2. **Shared source.** The upstream flagging of payoff candidates is the same in U and R, so
   U cannot test that stage.
3. **Victim-side history is source-selected**, as in R.

## 8. Budgets

| Run | Wall time | Memory |
|---|---|---|
| Each archive pass | under 75 min on this disk | under 512 MiB |
| Analysis | under 5 min | under 1 GB |

0 RPC requests and no downloads. Outputs are aggregates only.
