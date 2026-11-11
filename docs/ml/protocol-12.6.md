# Protocol 12.6: candidate reliability, signer provenance and evidence-aware presentation

**Frozen:** 2026-11-09, in the commit that adds this file. That is before the evidence model exists and before any H2–H7 measurement.

**Development analyses already done:**
- the signer-coverage audit (§1);
- the recovery-rule consistency check (§2).

**RPC:** 0. **Downloads:** none.

## 1. Audit finding (development analysis)

On the 9 eligible wallet-centric recordings (P3 and P5, frozen-overlap windows excluded):
- every outgoing ERC-20 transfer has a looked-up signer (18 of 18), and 0 lookups were skipped;
- 8 of them are foreign-signed spoofs;
- incoming transfers' signers are never looked up, by design.

**So the Phase 12.5 finding is not a recovery defect.** "Signer loss removes every spoofed candidate" came from synthetic masking. A spoof is defined by the victim *not* having signed, so it needs signer evidence.

**The realistic failure** is a busy wallet. The recorder looks up at most 500 outgoing transactions, and the overflow becomes an unknown signer. Such an event is silently neither a reference nor a spoof.

## 2. Deterministic local recovery (rule R-SIG)

Nonce bisection records **every** transaction a wallet signed in the window: `wallet_signed_transactions`, complete by construction. For an outgoing ERC-20 event whose signer was not looked up:

| Condition | Signer status |
|---|---|
| Its transaction is in the wallet's signed set | **`wallet` (verified)** |
| The signed set is complete, the wallet has no code at the cutoff, and the transaction is not in the set | **`foreign_identity_unknown` (verified by absence)**. The signer's address stays unknown and is never guessed. |
| Otherwise | **`unknown`** |

**Exclusions:**
- **A wallet with code** (a contract wallet or EIP-7702 delegation) **never gets the absence inference.** Others can execute its transfers.

**Consistency on real data** (development): the rule matches the looked-up signer in 18 of 18 eligible outgoing transfers, including 8 of 8 foreign-signed ones.

## 3. Hypotheses

| ID | Hypothesis | Population | Measure | Fails if |
|---|---|---|---|---|
| H1 provenance | The evidence model never substitutes the event sender for the signer, the token for the attacker, or an association for signing evidence. R-SIG recovers spoof status without inventing identities. | P1 synthetic, P2/P3 real (consistency) | oracle agreement; R-SIG agreement on real data | any disagreement |
| H2 deduplication | Grouping by (chain, victim, lookalike) reduces output while every distinct evidence record stays linked | P1, P3 | raw events, groups, evidence records kept | any evidence record lost, or any merge across victims or chains |
| H3 presentation | A bounded top-k summary discloses the total and the truncation, is deterministic, and never drops the strongest-evidence candidate under spam | P1, 12 adversarial scenarios | presence of the designated high-evidence candidate in top-k; disclosure fields; determinism | the candidate is dropped, or truncation is not disclosed |
| H4 missingness | Under masking (S0–S5), no claim is made that needs the masked information; unknowns lower *support*, never raise *suspicion* | P1, P3 | unsafe inferences by C1 (baseline) and by the evidence model; candidates kept, recovered or abstained | the evidence model makes any unsafe inference |
| H5 ranking | The evidence-aware order is more stable under cheap spam than recency-only or similarity-only orders | P1; a P3 copy with injected synthetic spam (in memory) | top-k retention of the real candidates; Kendall τ of their relative order | the evidence-aware order retains fewer real candidates than a baseline |
| H6 ML | Robust proxy features (shares, log counts) reduce shift sensitivity on the RQ8 proxy | P4 **development split only**, an internal temporal sub-split (earliest 70 % of groups train, latest 30 % validate) | log loss, macro-F1, top-class ECE (10 bins) against raw-feature LR and the frequency baselines | **exploratory.** The 12.5 test split is never used. No confirmatory claim. |
| H7 cost | Grouping, ranking and summary scale near-linearly | P1 at 10 / 100 / 1,000 / 10,000 candidates | wall, peak traced memory, evidence records, output bytes, throughput | super-linear growth or unbounded memory |

**No learned ranking model (M4).** No valid ranking labels exist beyond 2 development cases and the used 12.1 test split.

## 4. Evidence levels (non-probabilistic)

| Level | Definition |
|---|---|
| `directly_verified` | A planting whose mechanism is established by the transaction's own provenance: an outgoing event "from" the victim whose signer is verified not to be the wallet (known foreign, or R-SIG absence), or a native transfer from the lookalike whose receipt reads success |
| `supported` | A lookalike planting whose execution is implied but not read, such as a token log from the lookalike, or native with unread status |
| `partially_supported` | An outgoing event to a lookalike of a verified reference with an **unknown** signer, which is not asserted as a spoof. Also any non-lookalike rule (`zero_value_in`, `dust_in`). |
| `insufficient` | The wallet's references are not fully observed |
| `unsupported_source` | Coverage-level only: classes not collected |

## 5. Ordering and summary (research only)

**Suspicion, support and availability are separate dimensions.** The order of groups is:
1. evidence level;
2. affix strength (prefix + suffix to the imitated reference). Vanity cost grows about 16× per character, so cheap spam has short affixes.
3. latest planting position;
4. lookalike address (deterministic).

**Missingness only ever lowers the support level.** It never raises suspicion.

**Summary contract:**
- top-k (default 10);
- the totals of groups, raw events and evidence records;
- the number shown and a `truncated` flag;
- the identities of the hidden groups;
- counts per level and per mechanism;
- a note that hidden candidates are not assessed as safe.

**A display budget is not an evidence budget.** All groups and records stay in the result. The production detector is never consulted or changed.

## 6. Integrity

- **Unchanged:** C0, C1 and C2 and their published outputs. The new model is a separate module (`candidate-evidence/1`).
- **Data:** no cohort file is read beyond the entity exclusion. Frozen-overlap windows are excluded.
- **Claims:** no labels, no probabilities, no false-positive rate.
- **Resources:** one process, under 1 GiB.
