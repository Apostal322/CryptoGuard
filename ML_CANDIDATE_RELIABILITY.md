# Candidate reliability, signer provenance and evidence-aware presentation (Phase 12.6)

| Item | Value |
|---|---|
| Protocol (frozen first) | [`docs/ml/protocol-12.6.md`](docs/ml/protocol-12.6.md), `c060ccc` |
| Code (committed before the measured run) | `8e59c9d` |
| Study output (git-ignored) | `data/ml/research/phase12.6/reliability-study.json` (`cryptoguard ml reliability-study`) |
| RPC requests / downloads | **0** / none |

## 1. Executive summary

**Is signer loss a defect?** No. The real recordings have complete outgoing-signer coverage: 18 of 18 on the eligible windows, with 0 lookups skipped. The Phase 12.5 result, "signer loss removes every spoofed candidate", came from masking. A spoof is defined by the victim *not* signing, so it needs signer evidence. The realistic gap is the recorder's 500-lookup cap on busy wallets.

**Deterministic recovery, R-SIG.** Nonce bisection records every transaction a wallet signed.
- An outgoing event whose transaction is in that set was signed by the wallet.
- One absent from a complete set, for a wallet without code, was **not** signed by it. The signer's address is never guessed.
- **Result:** the rule matches the looked-up signer in **18 of 18** real cases, including 8 of 8 spoofs.
- **With every signer masked,** the real windows lose **0** candidates and recover 4–5 signers each. Phase 12.5 lost them all.

**Evidence model, `candidate-evidence/1`.**
- **One group per (chain, victim, lookalike)**, keeping **every** record. The pilot's 9 events become 6 groups with all 9 records; C2 had kept only one per group.
- **Typed provenance:** the event sender is never taken as the signer, and an unknown token is never called untrusted. With token identity masked, C1 makes 5 such unsupported claims on the pilot; the evidence model makes **0** under every masking condition.

**Spam resilience.**
- 1,000 zero-value strangers produce **0** groups (C1 lists 1,000).
- One strong candidate stays **rank 1** among 2,001.
- The bounded summary discloses totals and truncation, and deletes nothing.
- It scales linearly: 10,000 groups in 1.77 s.

**H5 fails against similarity (pre-registered).** The support-first order keeps only 3 of 6 real pilot candidates in the top 10 under cheap dust spam, while similarity-only keeps 6 of 6. A dust receipt verifies execution, which is cheap for an attacker. **Support is not suspicion.** Recency keeps 0.

**H6 (exploratory).** Log-scaled proxy features beat raw ones on a development sub-split. That sub-split has mild shift, so this does **not** show the Phase 12.5 failure is fixed.

**No learned ranking model.** There are no valid labels.

**Classification:**
- a confirmed provenance improvement (R-SIG);
- confirmed evidence preservation and spam resilience on controlled tasks;
- a negative ranking finding (H5);
- an exploratory feature-robustness signal (H6).

## 2. Baseline repository state

| Item | Value |
|---|---|
| HEAD | `82d54a3`, clean, equal to `origin/feature/ml-pipeline` |
| CI | 9 of 9 jobs passed |
| Cohort sheet hashes | Cohort A `a0ec4b6e…` and Cohort B `121c112d…`, unchanged |
| Detector | `address-poisoning` 1.0.0 |
| Generators | C0 `candidates/2`, plus C1 and C2 (`poisoning-candidate-discovery/1`), unchanged |

## 3. Signer-provenance audit

| Field | Source | Historical availability | Trust | Missingness | Failure mode | Correction |
|---|---|---|---|---|---|---|
| Transaction signer (outgoing ERC-20) | `eth_getTransactionByHash` `from`, newest 500 | complete in real windows (18 of 18) | verified | skipped beyond 500 (`sender_lookups_skipped`) | unknown signer: neither reference nor spoof | **R-SIG** recovery from the signed set |
| Transaction signer (incoming ERC-20) | not looked up | never | — | always unknown | none for current rules (inbound evidence is the event's own `from`) | stated as `unknown` |
| Event sender / recipient | log topics | complete | as reported by the emitting contract (a fake token can report anything) | — | taken as the signer | **never substituted**: `event_sender` is kept separate |
| Emitting contract | log address | complete | an identity, not a legitimacy | — | treated as attacker | never an attacker identity |
| Native sender | the transaction's `from` (balance bisection) | `observation/2` only | verified (the sender signed it) | not collected in `/1` | — | `lookalike_itself` |
| Wallet's own transactions | nonce bisection | complete by construction | verified | — | — | basis of R-SIG |
| Receipt status | receipts (native, `/2`); logs imply execution | native `/2`: read | verified | unread: `unknown` | inferred success (fixed in 12.4) | `succeeded` / `reverted` / `implied_by_log` / `unknown` |
| Token legitimacy | reviewed list | static | list-based | unknown when masked | C1 calls an unknown token untrusted | no claim; `token_identity` listed as missing |

## 4. Confirmed defects

1. **C2 aggregation dropped evidence.** It kept the first record per lookalike: the pilot had 9 records in 6 candidates, and 3 records were dropped. Fixed in `candidate-evidence/1`. C2 itself is unchanged, for reproducibility.
2. **There was no signer recovery** even though the wallet's complete signed set is local. Fixed by R-SIG, at the research layer.
3. **C1 asserts `untrusted_token_in` when token identity is unknown.** That is 5 unsafe claims on the pilot under masking. Real logs always carry the token, so in practice this is a latent defect. The evidence model makes no such claim. C1 is unchanged.

## 5. Unsupported hypotheses

- **"Real recordings lose signer information":** not observed (18 of 18, 0 skipped).
- **"Missing signer could support a spoof claim":** rejected by design. Without R-SIG evidence, an outgoing lookalike is kept as `unverified_out_lookalike` (partially supported) and never called a spoof.

## 6. Evidence representation

`EvidenceRecord` holds:
- identity: `tx:<hash>:<log>`;
- kind and direction;
- position: block, transaction index, log index;
- mechanisms and level;
- signer status and signer;
- event sender and recipient;
- emitter and receipt;
- the zero-value flag;
- `missing`.

`CandidateGroup` holds:
- identity and lookalike;
- the references, with affixes;
- mechanisms and kinds;
- the best level and best affix;
- the first and last positions;
- every record, in order;
- `missing`.

**Levels** (non-probabilistic):

| Level | Definition |
|---|---|
| `directly_verified` | a foreign-signed or R-SIG-absent spoof; a native lookalike transfer whose receipt reads success |
| `supported` | a token lookalike planting; a native transfer with an unread receipt |
| `partially_supported` | an unknown-signer outgoing lookalike; a non-lookalike rule |

## 7. Candidate identity rules

- **Identity:** `<chain>:<victim>:<lookalike>`.
- **Separate identities:** different victims or chains never share one (tested).
- **Not identity:** a shared token contract is never part of identity or of linkage (scenario 12).
- **Duplicates:** source duplicates collapse on `(tx hash, log index)`.

## 8. Deduplication results (real windows, eligible only)

| Window | Raw records | C1 events | C2 candidates | Groups | Records kept |
|---|---|---|---|---|---|
| pilot | 12 | 9 | 6 | 6 | **9** (C2 kept 6) |
| Scam Sniffer `/1` | 13 | 2 | 2 | 2 | 2 |
| Scam Sniffer blind `/2` | 15 | 3 | 3 | 3 | 3 |
| 6 × P5 | 0–9 | 0 | 0 | 0 | 0 (2 abstain: no reference) |

## 9. Candidate presentation, and 14. operational candidate budget

**The summary holds:**
- `total_groups`, `raw_events`, `evidence_records`;
- `shown` (k = 10) and `truncated`;
- `hidden_identities`;
- counts by level and by mechanism;
- `abstain`;
- the note that hidden candidates are not assessed as safe;
- for each shown group: references, affix, blocks, evidence count, missing, and an explanation along three separate dimensions (suspicion, support, missing).

**Order:**
1. level;
2. affix;
3. latest planting;
4. address, which keeps it deterministic (tested).

**A display budget is not an evidence budget.** All groups and records stay in the result.

**Measured cost of disclosure:** the hidden-identity list makes the summary O(n). It is 95.6 KB at 1,000 groups and 915 KB at 10,000 (§21). A UI may prefer counts plus a digest. The list is kept because the protocol requires it.

## 10. Adversarial spam results (synthetic, 12 scenarios; all deterministic)

| Scenario | Raw | C1 events | Groups | Records | Shown / hidden | Strong rank | Time |
|---|---|---|---|---|---|---|---|
| 1. 1,000 zero-value strangers | 1,001 | 1,000 | **0** | 0 | 0 / 0 | — | 0.02 s |
| 2. 1,000 distinct lookalikes | 1,001 | 1,000 | 1,000 | 1,000 | 10 / 990 | — | 0.19 s |
| 3. 500 dust transfers from one lookalike | 501 | 500 | **1** | **500** | 1 / 0 | 1 | 0.04 s |
| 4. 1,000 weak + 1 strong (one reference) | 1,002 | 1,001 | 1,001 | 1,001 | 10 / 991 | **1** | 0.23 s |
| 5. 50 references, a lookalike of each | 101 | 50 | 50 | 50 | 10 / 40 | — | 0.01 s |
| 6. 1,000 fake-token events | 1,001 | 1,000 | 1,000 | 1,000 | 10 / 990 | — | 0.14 s |
| 7. 100 in one block | 101 | 100 | 100 | 100 | 10 / 90 | — | 0.01 s |
| 8. Unknown signer, complete signed set | 2 | **0** | **1** (spoof by R-SIG) | 1 | 1 / 0 | 1 | <0.01 s |
| 9. Missing receipt | 2 | 1 | 1 (supported) | 1 | 1 / 0 | 1 | <0.01 s |
| 10. Partial history | 2 | 0 | 1 (partial), abstains | 1 | 1 / 0 | — | <0.01 s |
| 11. Strong spoof among 2,000 weak | 2,002 | 2,001 | 2,001 | 2,001 | 10 / 1,991 | **1** | 0.31 s |
| 12. 200 plantings via public USDT | 201 | 200 | 200 | 200 | 10 / 190 | — | 0.03 s |

Peak traced memory is at most 3.1 MiB for any scenario.

## 11. Historical correctness

- **Cutoff:** strictly before `(block, tx index)`.
- **Tested:** later plantings, payoffs and lookalikes leave groups and records at an earlier cutoff unchanged, and record order changes nothing.
- **Hashes** in the synthetic builder are content-derived, so a record has the same identity in any fixture.

## 12. Missingness handling (S0–S5, real windows)

Each cell shows kept / lost / added, then the change in level.

| Condition | pilot (6) | Scam Sniffer `/1` (2) | Scam Sniffer blind `/2` (3) | C1 unsafe | Evidence unsafe |
|---|---|---|---|---|---|
| S1 signer | 6/0/0; 5 recovered | 2/0/0; 4 recovered | 3/0/0; 4 recovered | 0 | **0** |
| S2 event sender | 4/2/0; 4 lowered, abstains | 0/2/0, abstains | 0/3/0, abstains | 0 | **0** |
| S3 receipt | 6/0/0 | 2/0/0 | 3/0/0; 1 lowered (verified → supported) | 0 | **0** |
| S4 token identity | 6/0/0 | 2/0/0 | 3/0/0 | **5** | **0** |
| S5 partial history | 6/0/0, abstains | 2/0/0, abstains | 3/0/0, abstains | 0 | **0** |

**No condition ever adds a candidate or raises a level.** Missing information only lowers support or causes abstention.

## 13. ML research protocol

Protocol 12.6 sets out H1–H7. No learned ranking model (M4) was trained: no valid ranking labels exist beyond 2 development cases and Phase 12.1's used test split.

## 15. Ranking methods, and baseline comparisons (H5)

| Ordering | Definition |
|---|---|
| **Evidence-aware** | level, then affix, then latest planting |
| Recency-only | latest planting |
| Similarity-only | affix |

**Test:** 1,000 cheap native-dust lookalikes (affix 3 + 3, receipt success, planted latest) are injected into copies of the two real windows, in memory.

| Window (real candidates) | Evidence-aware: real in top 10 / τ | Recency-only | Similarity-only |
|---|---|---|---|
| Scam Sniffer blind (3) | **3** / 1.00 | 0 / −0.33 | 3 / 1.00 |
| pilot (6) | **3** / 1.00 | 0 / 0.47 | **6** / 0.47 |

**H5 is not supported.** The evidence-aware order retains fewer real candidates than similarity-only on the pilot.
- **Cause:** cheap dust spam earns `directly_verified`, because its receipt is real. So it outranks the pilot's `supported` lookalikes, whose affixes are stronger.
- **Lesson:** the support level measures how certain the *interpretation* is, and that certainty is cheap for an attacker to produce. It must not lead the order.
- **Not tested here:** ordering by affix first, then level. It is proposed for the next pre-registered test and not claimed.
- **Recency is the most spam-fragile order.**

## 16. Learned-model feasibility, and 17. feature robustness (H6, exploratory)

**Setup:** Phase 12.1's development split only. The 12.5 test split is never used. An internal temporal sub-split: 442 training groups (7,766 rows) and 190 validation groups (5,037 rows).

| Method | Log loss | Macro-F1 | Top-class ECE |
|---|---|---|---|
| Global | 0.2804 | 0.243 | 0.0023 |
| Victim prefix | 0.2621 | 0.297 | 0.0206 |
| Markov | 0.2713 | 0.243 | 0.0108 |
| LR, raw counts (12.5 features) | 0.2708 | 0.350 | 0.0284 |
| **LR, log-scaled counts** | **0.2384** | **0.393** | 0.0133 |

- **Robust minus raw:** −0.032 [−0.068, −0.006] over 190 groups.
- **Shift within this sub-split:** prefix p90 154 → 177, which is mild.
- **Not shown:** that the 12.5 failure, with p90 163 → 2,481, is fixed. That would need an untouched later population.
- **Status:** exploratory. The Phase 12.5 conclusion stands.

## 18. Evaluation populations

| Population | Description |
|---|---|
| P1 | synthetic |
| P2 | the 2 Level I development cases |
| P3 | 9 eligible wallet recordings |
| P4/P5 | the archive episode cache, development split only |

They are never pooled. Background windows are not negatives.

## 19. Candidate-volume analysis

| Population | Volume |
|---|---|
| Real (P3) | 0–6 groups per window; at most 2 groups per wallet-day |
| Synthetic | bounded by distinct lookalikes, never by raw events |

Native volume on unlabelled wallets is still unmeasured, because P5 is `observation/1`.

## 20. Statistical limitations

- **Real windows:** n = 3, two of them development cases.
- **Spam tests:** synthetic, testing robustness, not detection.
- **H6:** exploratory, on development data that was seen before.
- **Not reported:** any precision, recall, false-positive rate or probability.

## 21. Operational performance (synthetic, linear)

| Candidates | Build | Summary | Peak traced | Result JSON | Summary JSON | Groups / s |
|---|---|---|---|---|---|---|
| 10 | 0.002 s | <0.001 s | 0.01 MiB | 10.8 KB | 5.5 KB | 5,000 |
| 100 | 0.011 s | <0.001 s | 0.12 MiB | 103 KB | 13.7 KB | 9,091 |
| 1,000 | 0.169 s | 0.004 s | 1.44 MiB | 1.03 MB | 95.6 KB | 5,917 |
| 10,000 | 1.771 s | 0.028 s | 16.6 MiB | 10.3 MB | 915 KB | 5,647 |

**The whole study:** 90 s, peak RSS 235 MiB, one process.

**The Phase 12.5 optimization is preserved:** observations are built once per window.

## 22. Production isolation

- **Detector:** unchanged. `detector_outputs` is identical before and after building evidence (tested).
- **Research code:** reachable only through `cryptoguard ml reliability-study`.
- **Dependencies:** no new production dependency. scikit-learn is used only in the exploratory proxy, as before.

## 23. Tests, and 24. CI

| Check | Command | Result |
|---|---|---|
| Lint | `uv run ruff check .` | clean |
| Format | `uv run ruff format --check .` | 291 files formatted |
| Types | `uv run mypy src` | clean (153 files) |
| Tests | `uv run pytest -q` | **950 passed, 1 failed**, 4 deselected (an 18-minute run on a heavily loaded machine) |

**About the failure.** It was `tests/integration/test_leases.py::test_lease_of_a_crashed_process_is_recovered_after_expiry`, a timing-sensitive lease-expiry test whose own comment records load flakiness. It passed **3 of 3** reruns in isolation. Phase 12.6 changed no lease code: its only source changes are `ml/cli.py` and two new research modules.

There are 27 new tests in `tests/test_ml_candidate_evidence.py`.

**Frozen artifacts:** the Cohort A and B sheet and key hashes are unchanged after the run (`a0ec4b6e…`, `407b412f…`, `121c112d…`, `f333386d…`). The frozen Level I fixtures are pinned by their regression tests, which passed.

CI is recorded in the PR #1 description.

## 25. Resource usage

- 0 RPC requests, 0 downloads.
- The study took 90 s at 235 MiB peak.
- It reused the Phase 12.5 episode cache, with no archive re-read.

## 26. Positive findings

1. R-SIG recovers spoof status without inventing identities, matching the real signer in 18 of 18 cases.
2. Evidence is fully preserved and grouped.
3. No unsafe inference occurs under any masking.
4. Spam can't bury a strong candidate whose support is also high, and zero-value floods produce nothing.
5. Cost scales linearly.

## 27. Negative findings

1. H5: a support-first order is beaten by similarity under cheap verified spam.
2. Recency is the most spam-fragile order.
3. The summary's hidden-identity list is O(n).
4. There is no valid task for a learned ranker.

## 28. Production-readiness decisions

| Change | Category | Decision | Risk and evidence |
|---|---|---|---|
| R-SIG signer recovery | A/B, provenance | **Eligible for a separately approved production change.** Not integrated here: it would silently change production spoof signals for busy wallets. | 18 of 18 consistency; contract and EIP-7702 wallets excluded |
| Evidence model and levels | B | research (shadow); integrate after a migration review | levels are not probabilities |
| Unknown-signer outgoing lookalikes kept as partially supported | C | research only | never a spoof claim |
| Bounded summary contract | E | research output; never suppresses production warnings | O(n) disclosure list |
| Support-first ordering | D | **do not adopt**; H5 failed | spam outranks real candidates |
| Robust proxy features | D | exploratory | mild-shift development sub-split only |

## 29. Recommended next experiment

**Question:** on untouched `observation/2` incident windows, does an affix-first order, then support, then recency, keep the later-paid lookalike in the top 10 under cheap spam more often than recency?

| Element | Specification |
|---|---|
| Observations | At least 10 untouched incidents, recorded blind with `observation/2`. User-sourced harm-transaction hashes. |
| Labels | The paid address, from the harm transaction, used only to score |
| Contribution | The first prospective-style test of spam-robust ordering on real data |
| Cost | About 700–1,300 RPC requests per window, so about 15,000 in total. Analysis takes seconds. |
| Failure | The affix-first order does not keep the paid lookalike in the top 10 in more untied clusters than recency, under amendment A1's cluster sign test |

Phase 12.7 is not started.
