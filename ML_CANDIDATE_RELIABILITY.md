# Candidate reliability, signer provenance and evidence-aware presentation (Phase 12.6)

| Item | Value |
|---|---|
| Protocol (frozen first) | [`docs/ml/protocol-12.6.md`](docs/ml/protocol-12.6.md), `c060ccc` |
| Code (committed before the measured run) | `8e59c9d` |
| Study output (git-ignored) | `data/ml/research/phase12.6/reliability-study.json` (`cryptoguard ml reliability-study`) |
| RPC requests / downloads | **0** / none |
| Phase 12.6.1 addendum | §30–§39 (signer guards, authorization, bounded pages, lease test) |

## 1. Executive summary

**Is signer loss a defect?** No. The real recordings have complete outgoing-signer coverage: 18 of 18 on the eligible windows, with 0 lookups skipped. The Phase 12.5 result, "signer loss removes every spoofed candidate", came from masking. A spoof is defined by the victim *not* signing, so it needs signer evidence. The realistic gap is the recorder's 500-lookup cap on busy wallets.

**Deterministic recovery, R-SIG.** Nonce bisection records every transaction a wallet signed.
- An outgoing event whose transaction is in that set was signed by the wallet.
- One absent from a complete set, for a wallet without code, was **not** signed by it. The signer's address is never guessed.
- **Result:** the rule matches the looked-up signer in **18 of 18** real cases, including 8 of 8 spoofs.
- **With every signer masked,** the real windows lose **0** candidates and recover 4–5 signers each. Phase 12.5 lost them all.
- **12.6.1 correction:** R-SIG proves only that the wallet did not *directly sign*, never that it did not *authorize* (allowance, permit, delegation), and it now runs only under `absence_guard` (§30–§31).

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
- `hidden_identities` (replaced in 12.6.1 by `hidden_count`, `next_offset`, a digest and page access, §32);
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

**Measured cost of disclosure:** the hidden-identity list makes the summary O(n). It is 95.6 KB at 1,000 groups and 915 KB at 10,000 (§21). A UI may prefer counts plus a digest. The list is kept because the protocol requires it. **12.6.1:** removed; the summary is now 6.8 KB at any size (§32).

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

**About the failure.** It was `tests/integration/test_leases.py::test_lease_of_a_crashed_process_is_recovered_after_expiry`, a timing-sensitive lease-expiry test whose own comment records load flakiness. It passed **3 of 3** reruns in isolation. Phase 12.6 changed no lease code: its only source changes are `ml/cli.py` and two new research modules. **12.6.1:** investigated and fixed in the test (§37).

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
| R-SIG signer recovery (see §39 for the 12.6.1 decision) | A/B, provenance | **Eligible for a separately approved production change.** Not integrated here: it would silently change production spoof signals for busy wallets. | 18 of 18 consistency; contract and EIP-7702 wallets excluded |
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

---

# Phase 12.6.1 addendum: signer-recovery safety, bounded summaries, research reliability

| Item | Value |
|---|---|
| Amendment | [`docs/ml/amendment-12.6.1.md`](docs/ml/amendment-12.6.1.md), written with the code |
| Code | `5a5e876` (`candidate-evidence/2`, `reliability-study/2`) |
| Study output (git-ignored) | `data/ml/research/phase12.6.1/reliability-study.json`, run on `5a5e876` |
| RPC requests / downloads | **0** / none |

Sections 1–29 above are the Phase 12.6 record and stay as written. Where 12.6.1 corrects
them, the correction is stated here and marked in place.

## 30. Executive summary (12.6.1)

**Correction to 12.6:** R-SIG had been used as if "not signed by the wallet" meant "not
authorized by the wallet". It doesn't. An ERC-20 allowance, a permit or an EIP-7702 delegation
lets someone else's transaction move the wallet's tokens, and a fabricated log needs no
authorization at all.
- **Now:** only a **zero-value** foreign-signed transfer is `spoofed_out` (nothing moved, so
  no authorization question arises).
- **Value moved:** the transfer is `foreign_initiated_out`, with `authorization = unknown`.
- **Effect on the real windows:**
  - All 8 real foreign-signed events are still evidence, in the same groups and at the same
    levels.
  - The 6 that moved value were called spoofs by C1/C0 and by `candidate-evidence/1`. All 6
    came from untrusted token contracts and are now labelled `foreign_initiated_out` +
    `untrusted_token_out`.
  - None moved a trusted token.

**Signer recovery is now guarded.** The absence inference runs only if the signed set is:
- complete;
- count-consistent;
- nonce-contiguous;
- inside the window;
- from an account whose code is `0x` at every sample up to the cutoff.

Otherwise the signer stays unknown. 20 conditions are tested (§31). The guard allows the
inference on all 9 eligible real windows, and R-SIG still agrees with the looked-up signer
in **18 of 18** cases.

**The summary is bounded.** It is 6.8 KB at 1,000, 10,000 and 100,000 candidates. Under
12.6, the hidden-identity list made it 915 KB at 10,000. Every group and record stays
reachable through digest-checked offset/limit pages.

**Support no longer orders candidates.** The presentation order is affix, then recency,
then address. Masking receipts, token identity or signers changed the relative order of
**0** kept candidates on the 3 real windows with candidates. H5's negative result is
reproduced unchanged (§34).

**Adversarial suite at 10,000 events per scenario:**
- the high-relevance candidate is rank 1 in 8 of 9 scenarios;
- in the ninth, 10,000 equally similar lookalikes planted later outrank it by recency (rank
  10,001);
- it stays reachable through the page interface in all 9;
- output is deterministic everywhere;
- each build takes about 2 s at about 17 MiB traced;
- the whole study ran in 92 s at a 623 MiB RSS peak, mostly from the 100,000-candidate step.

**Lease test:** the cause of the single 12.6 failure could not be attributed: only the
failing test's name was kept, not its assertion. The test had three defects, all now fixed
(§37): an ambiguous child exit code, an unbounded wait for the child, and lease checks tied
to the wall clock. The rewritten test passed 15 of 15 runs under CPU contention.

## 31. Signer-recovery audit (synthetic matrix)

The probe is an outgoing USDT transfer from the wallet to a lookalike, whose signer was not
looked up.

| Condition | Absence inference | Probe result | Why |
|---|---|---|---|
| Complete history, zero value | allowed | `foreign_identity_unknown`, `spoofed_out`, authorization `not_required` | — |
| Complete history, value moved, trusted token | allowed | `foreign_initiated_out`, authorization `unknown` | allowance, permit or delegation possible |
| Complete history, value moved, untrusted token | allowed | `foreign_initiated_out` + `untrusted_token_out`, authorization `unknown` | — |
| Signer lookups capped (600 skipped) | allowed | spoof recovered | the 500 cap limits lookups, not the signed set |
| Signed set `truncated` | **blocked** | `unknown`, `unverified_out_lookalike` | incomplete source |
| Signed set `partial` (partial recording) | **blocked** | same | incomplete source |
| Stated count ≠ held (5 vs 1) | **blocked** | same | inconsistent source |
| Nonce gap (missing page or EIP-7702 authorization) | **blocked** | same | a nonce was used with no recorded transaction |
| Legacy fixture without documented nonce bisection | **blocked** | same | completeness claim unsupported |
| Code deployed inside the window, before the cutoff | **blocked** | same | contract code |
| Code only after the cutoff | allowed | spoof recovered | future samples are not used |
| No code sample at the window start | **blocked** | same | code unknown |
| EIP-7702 delegation designator at the window start | **blocked** | same | delegated execution |
| Smart wallet (code) | **blocked** | same | never signs itself |
| Wallet calls a router that pulls with `transferFrom` | allowed | `wallet`, not evidence | the outer transaction is in the signed set |
| Same block: spoof before the wallet's own transaction | allowed | spoof recovered | identity is by hash, not order |
| Same block: own transaction after the cutoff | allowed | not observed | the cutoff is `(block, tx index)` |
| Same block: own transaction before the cutoff | allowed | `wallet`, not evidence | — |
| Wallet-signed transaction with unknown receipt | allowed | `wallet`, not evidence | membership does not depend on the receipt |
| Looked-up foreign signer, but the hash is in the signed set | allowed | `conflicting`, `unverified_out_lookalike` | never a spoof and never a reference |

**Why these conditions suffice for recorder output.** The recorder (`replay/record.py`)
refuses an incomplete nonce bisection. And an EIP-7702 authorization included in someone
else's transaction increments the wallet's nonce with no wallet-signed transaction in that
block, so `_read_transaction` raises and no fixture is written. The guard re-checks both
from the stored data, so a fixture produced any other way is held to the same standard.

**Limitation.** A signed set truncated at either end while still claiming `complete`, with a
matching count, is not detectable from the fixture, because the boundary nonces are not
stored. The guard relies on the recorder's guarantee there.

**Real windows (`signer_audit`):**
- Absence inference is allowed on 9 of 9 eligible windows; nonces are contiguous and code is
  `0x` at every sample.
- Foreign-signed outgoing events: 2 zero-value (pilot), 6 value-moving through untrusted
  tokens (2 per development window), 0 value-moving through trusted tokens.
- C1 spoof claims on value-moving transfers: **6**. `candidate-evidence/2`: **0**.

## 32. Bounded summary and page access

| Candidates | Build | Build peak (traced) | Summary | Summary JSON | Page of 10 | Group records page | Digest |
|---|---|---|---|---|---|---|---|
| 1,000 | 0.14 s | 1.1 MiB | 0.009 s | 6,807 B | 6,209 B | 743 B | 0.001 s |
| 10,000 | 1.60 s | 13.2 MiB | 0.093 s | 6,812 B | 6,222 B | 743 B | 0.012 s |
| 100,000 | 17.8 s | 137 MiB | 0.81 s | 6,817 B | 6,235 B | 743 B | 0.13 s |

**Generation:** observations are generated directly, one small dataclass per event, with no
fixture models.

**What the summary contains:**
- the top `k` (1 ≤ k ≤ 1,000);
- `total_groups`, `hidden_count`, `truncated` and `next_offset`;
- `result_digest`;
- counts by level and by mechanism (fixed vocabularies);
- `absence_inference` and its blockers;
- at most 3 references per item, with `references_total`.

**Access:**
- `page(offset, limit, expect_digest)` follows the project's `items`/`total`/`limit`/`offset`
  convention and refuses a stale digest;
- `group_records(identity, offset, limit)` pages a single group's records.

**Tests:**
- pages cover every group exactly once, in order;
- out-of-range `k`/`limit`/`offset` are refused;
- the summary carries no floats;
- every item says `legitimacy: not_assessed`.

## 33. Evidence reliability versus suspiciousness

| Requirement | How it holds | Test |
|---|---|---|
| A verified receipt does not raise suspicion | `presentation_key` never reads `level`; a verified older lookalike ranks below an unread newer one with the same affix | `test_a_verified_receipt_does_not_move_a_candidate_up` |
| High evidence quality does not imply attack probability | levels stay categories; `explain` separates indicators, support and missing | `test_presentation_order_never_reads_the_support_level` |
| Missing evidence is not suspicious | masking receipts, tokens or signers keeps the relative order (synthetic and real) | `test_missing_evidence_never_changes_the_order`; real windows below |
| Similarity and time are separate from provenance | the order uses affix and recency; level is reported beside them | same |
| Unknown legitimacy stays unknown | `legitimacy: not_assessed` on every item | `test_summary_items_are_bounded_and_carry_no_probability` |
| No calibrated-probability claims | no float field in the summary; `order_note` says "not a risk score or a probability" | same |

**Real windows:**

| Window | Mask | Kept | Relative order unchanged | Levels changed |
|---|---|---|---|---|
| pilot | receipt / token / signer | 6 / 6 / 6 | yes / yes / yes | 0 / 0 / 0 |
| ScamSniffer `/1` | receipt / token / signer | 2 / 2 / 2 | yes / yes / yes | 0 / 0 / 0 |
| ScamSniffer blind `/2` | receipt / token / signer | 3 / 3 / 3 | yes / yes / yes | 1 / 0 / 0 |

The one level change is a lowering (verified → supported) and moved nothing.

## 34. H5 preserved; the presentation order is not validated

The H5 injection was repeated unchanged: 1,000 verified dust lookalikes (affix 3 + 3).

| Window (real candidates) | Evidence-first (pre-registered) | Presentation (affix, recency) | Similarity-only | Recency-only |
|---|---|---|---|---|
| ScamSniffer blind (3) | 3 | 3 | 3 | 0 |
| pilot (6) | **3** | 6 | 6 | 0 |

- **H5 stays negative.**
- **The presentation order's 6 of 6 on the pilot is development data.** The pilot informed
  the choice, so it is not independent validation and is not claimed as one. The order was
  adopted because support must not act as suspicion (§33), not because of this table.
- **Partial-history case:** under the evidence-first order, a strong but partially supported
  candidate ranks 10,001st of 10,001 (§35). Missing evidence became burial there. The
  presentation order keeps it at rank 1.

## 35. Adversarial suite (synthetic, 10,000 flood events per scenario)

| Scenario | Groups | Records | Strong rank (presentation) | Strong rank (evidence-first) | Reachable by page | Strong support | Build | Peak traced | Summary |
|---|---|---|---|---|---|---|---|---|---|
| 10,000 cheap lookalikes (3 + 3 dust) | 10,001 | 10,001 | **1** | 1 | yes | directly verified | 2.08 s | 16.6 MiB | 6.8 KB |
| Repeated dust from one lookalike | 2 | 10,001 | **1** | 1 | yes | directly verified | 0.98 s | 9.0 MiB | 2.0 KB |
| Fake-token flood | 10,001 | 10,001 | **1** | 1 | yes | directly verified | 1.86 s | 17.7 MiB | 7.1 KB |
| Missing signer (R-SIG) | 10,001 | 10,001 | **1** | 1 | yes | directly verified | 2.07 s | 16.5 MiB | 6.9 KB |
| Partial historical coverage | 10,001 | 10,001 | **1** | 10,001 | yes | partially supported, abstains | 2.19 s | 17.0 MiB | 7.5 KB |
| 50 references × 200 lookalikes | 10,001 | 10,001 | **1** | 1 | yes | directly verified | 2.23 s | 16.6 MiB | 6.8 KB |
| Multiple mechanisms (spoof + zero-value in + native) | 10,001 | 10,003 | **1** (3 mechanisms, 3 records) | 1 | yes | directly verified | 1.87 s | 16.5 MiB | 6.9 KB |
| 10,000 identical-similarity ties (5 + 5), later | 10,001 | 10,001 | 10,001 | 10,001 | **yes** | directly verified | 2.26 s | 16.6 MiB | 6.9 KB |
| Recency manipulation (all spam in the last block) | 10,001 | 10,001 | **1** | 1 | yes | directly verified | 2.28 s | 16.6 MiB | 6.8 KB |

**Determinism:** all 9 builds produce identical digests when repeated.

**Remaining weakness: ties.**
- With equal affixes, recency decides. An attacker who plants k or more later lookalikes,
  each as similar as the real one, pushes it off the first page.
- At 5 + 5 hex characters, each such lookalike costs about 2⁴⁰ address-generation
  attempts.
- The candidate is still listed, counted in `hidden_count` and reachable by page.

**Harness fix found by this suite:** the synthetic builder had given identical dust sends
in the same block the same transaction hash, which merged them. It now adds the event index
to the hash (tested). The evidence model was not involved.

## 36. Historical correctness

- The guard reads only code samples at or before the cutoff. A later EIP-7702 designator
  leaves an earlier result byte-identical (by digest) and blocks the inference only once the
  cutoff passes it (tested).
- The signed set may contain later transactions. Membership is tested only for events before
  the cutoff, and completeness covers the whole window.

## 37. The lease test

**Investigation:** the full-suite failure kept only the test's name, so the failing assertion
is unknown.

**Measurements on the unchanged test:**
- 20 of 20 passed, with 4 CPU burners competing for the 4 cores.
- Each run took 14–21 s, against 3 s idle. Nearly all of it was spawn start-up before the
  lease was taken (6–11 s).
- From the child taking the lease to the parent's check: 0.28–0.72 s.
- Lease time remaining at the check: about 7.3–7.7 s of the 8 s TTL.
- The conditional "still held" assertion ran in 15 of 15 instrumented runs.

So scheduling delay before the check doesn't explain a failure.

**Defects in the test that could explain it:**
1. **Ambiguous exit code.** A child that raises also exits with code 1, so a child failure
   passed `exitcode == 1` and then failed later at `held is not None` with no diagnosis.
2. **Unbounded wait.** A join that timed out left a live child and failed with an unclear
   assertion.
3. **Wall-clock coupling.** The "still held" assertion was conditional, and it was a
   check-then-act on the real clock: a pause over 1 s between the check and `acquire`'s own
   clock read fails it even though the lease logic is correct.

**Fix, with no assertion weakened:**
- distinct exit codes (17: crashed holding; 3: no lease; 1: raised);
- a 180 s bounded join that kills a hung child;
- expiry probed with explicit clock values: held at expiry − 1 µs, still held at the expiry
  instant, recovered with generation 2 at + 1 µs. These checks always run; before, they could
  be skipped.
- A new deterministic test: at the expiry instant the old owner is already fenced out and
  nobody can take over yet, so no instant has two owners.

**Result:** the rewritten test passed 15 of 15 runs under the same 4-burner contention, with
no wall-clock waits.

**Production code:** unchanged. One observation: `acquire` reads the clock before waiting on
a busy database, so the new lease expires early by the wait time. That is safe, because
fencing rejects late writes, and it is noted rather than changed.

## 38. Validation (12.6.1)

| Check | Result |
|---|---|
| `ruff check` / `ruff format --check` / `mypy src` | clean / formatted / clean (153 files) |
| New tests | `tests/test_ml_signer_guards.py`: 47; `tests/integration/test_leases.py`: 1 new, 1 rewritten |
| Full suite | **999 passed, 0 failed**, 4 deselected, in 14 min 22 s at about 1.6 GiB free RAM; the rewritten lease test passed within it |
| Package | `uv build --offline` wheel and sdist; `scripts/inspect_dist.py` OK (wheel 190 files, sdist 398) |
| Frozen artifacts | cohort sheet and key hashes unchanged; original incident fixtures untouched (no data file modified) |
| CI | recorded in the PR #1 description |

## 39. Readiness, limitations and decisions (12.6.1)

| Change | Decision |
|---|---|
| R-SIG with `absence_guard`, as a non-signing proof | **Reliable for offline research.** Production integration still needs a separately approved change. It would alter production spoof signals for busy wallets, and the production detector's own `spoofed_out` definition would first need the authorization split (A2). |
| Authorization split (`foreign_initiated_out`) | research; C0/C1 and the detector unchanged, so earlier results stay reproducible |
| Presentation order (affix, recency, address) | offline research default; **not validated** (§34) |
| Bounded summary and pages | research interface, ready for a UI prototype; never suppresses production warnings |
| Lease test | fixed; no production change |

**Is the candidate-evidence pipeline reliable enough for broader offline research?** Yes,
for offline research on recorded windows:
- signer claims are guarded and never negative from an incomplete source;
- authorization is never assumed;
- evidence is preserved and paged with bounded output;
- missing evidence moves nothing;
- outputs are deterministic and cost is linear (100,000 candidates in 18 s).

**What blocks production integration:**
1. **No independent validation.** The presentation order and the indicators are tested only
   on synthetic data and 2 development incidents.
2. **Authorization is unobserved.** Distinguishing an approved pull from a fabricated log
   needs allowance and permit history, which no recording collects yet.
3. **Legitimate intent-based settlements** (solver-signed `transferFrom` pulls) become
   `foreign_initiated_out` groups whenever value moves. That is a false-positive source
   with unmeasured volume.
4. **The production detector's spoof rule** would need the authorization split and a
   migration review before R-SIG feeds warnings.
5. **Equal-affix ties** fall back to recency (§35).
6. **The signed set's end boundaries** rest on the recorder's guarantee (§31).

The next experiment is unchanged (§29). Phase 12.7 is not started.
