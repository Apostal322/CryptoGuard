# Detection methods

Phase 1 produces **observations**, not risk findings. This file documents how each observation
is derived and where it can mislead. Detectors with severities arrive in Phase 2+.

## Account code classification (`blockchain/eip7702.py`, version `address-inspection/1`)

Source of truth: [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702). Input: `eth_getCode` at
a pinned block.

| Result | Rule |
|---|---|
| `no_code` | Code is empty |
| `eip7702_delegation` | Code is **exactly** 23 bytes and starts with `0xef0100`; bytes 3–22 are the target |
| `malformed_delegation_prefix` | Starts with `0xef0100` but any other length |
| `contract` | Any other non-empty code |

For delegations, the target's code is read at the same block and classified the same way.

Interpretation and caveats:

- `no_code` does not prove an EOA: an address can also be a not-yet-deployed contract.
- A delegation is not malicious by itself. Smart-account delegations are a legitimate use; the
  observation says only which code now governs the account.
- Current code shows only the current delegation. When it was set, by which transaction, and
  any earlier targets are unknown without indexed history (future work).
- Per spec, indicators are not rolled back when the set-code transaction's execution reverts,
  delegating to the zero address clears code, and delegation chains are not followed. A target
  that is itself delegated is reported as such.
- `malformed_delegation_prefix` should not occur on a correct chain (EIP-3541 forbids
  deploying `0xEF`-prefixed code); it signals a provider or client problem.

## ERC-20 approvals (`services/approvals.py`, version `approval-scan/1`)

Source of truth: [ERC-20](https://eips.ethereum.org/EIPS/eip-20).

**Discovery.** `eth_getLogs` with topics `[Approval, owner]` over an explicit block window
(default: last 10,000 blocks), newest-first in chunks of `MAX_LOG_BLOCK_RANGE`. If the provider
refuses a chunk as too large it is halved; if the request budget runs out, coverage is reported
as partial (`scanned_from_block > requested_from_block`). Logs flagged `removed` are dropped
and duplicates (same block hash and log index) are counted once.

**Standard disambiguation.** ERC-20 and ERC-721 `Approval` share topic0. Only logs with exactly
3 topics and 32 bytes of data are fungible allowances; 4 topics with empty data are counted as
`erc721_shaped_approvals` and not analyzed; anything else is `malformed`.

**Verification.** For each (token, spender) pair, using the most recent event as discovery
evidence only, at one pinned block: `allowance(owner, spender)`, `balanceOf(owner)`,
`decimals()`, `symbol()`, the token's and spender's code. A revert is `call_reverted`, a
return that is not exactly one 32-byte word is `nonstandard_return`, a token without code is
`token_has_no_code`. All of these are reported as **unknown**, never as zero.

**Allowance level**

| Level | Rule |
|---|---|
| `none` | allowance = 0 |
| `limited` | 0 < allowance < 2^128 |
| `effectively_unlimited` | 2^128 ≤ allowance < 2^256 − 1 (no real supply approaches 2^128 base units) |
| `unlimited` | allowance = 2^256 − 1 |
| `unknown` | allowance could not be read |

**Exposure upper bound** = `min(balance, allowance)` when both are known, otherwise unknown.
It is the visible amount the spender is currently permitted to move, not a loss estimate, and
it assumes standard `transferFrom` semantics.

**Signals** (attached to a pair; not severities, which the Phase 3 rule engine will assign)

| Code | Evidence | Fires when | False-positive considerations |
|---|---|---|---|
| `unlimited_allowance` | observed fact | allowance = max uint256 | Common and often intended (DEX routers, Permit2) |
| `effectively_unlimited_allowance` | observed fact | allowance ≥ 2^128 | Same as above; also seen after an unlimited approval was partly spent on some tokens |
| `allowance_exceeds_balance` | observed fact | allowance > balance | Normal for any unlimited approval |
| `spender_has_no_code` | heuristic | active allowance to a codeless address | Legitimate for some OTC/custody flows or counterfactual contracts; not proof of phishing |
| `spender_is_delegated_eoa` | observed fact | spender has an EIP-7702 delegation | Smart-account spenders are legitimate |
| `allowance_differs_from_latest_event` | observed fact | current allowance ≠ latest event value | Expected after `transferFrom` spending, which often emits no `Approval` |
| `token_metadata_unavailable` | observed fact | `decimals()` unreadable | Amounts shown in base units |

Known-spender labels (`core/known_contracts.py`) identify a few published contracts; a label is
not a safety verdict and an unlabelled spender is not suspicious by itself.

Not covered yet: ERC-721/ERC-1155 approvals (including `ApprovalForAll`), Permit2
sub-allowances, EIP-2612 nonces, and approvals granted before the scanned window.

## Security timeline (`history/`, version `wallet-snapshot/1`)

A **snapshot** is the wallet's canonical state at one block `B` (default `head − 12`):
verified approvals and the account-code / delegation observation. Its `state_hash` is
keccak-256 of the canonical JSON (sorted keys), so identical observations hash identically.

Approval discovery is **incremental**: the first snapshot scans a bounded lookback; each later
one scans only `(previous B, B]`, then re-verifies every pair not known to be zero plus the
new ones. Coverage is the merged list of scanned ranges; any unscanned window (e.g. a gap
longer than `APPROVAL_MAX_SCAN_BLOCKS`) is listed as a gap. Pairs beyond the pair limit are
carried forward with their last verification block and treated as unverifiable.

**Delta** `previous_state → current_state` (sorted by subject, then kind):

| Kind | Rule |
|---|---|
| `allowance_granted` | none/0 → known > 0 |
| `allowance_discovered_unverified` | new pair whose allowance is unreadable |
| `allowance_increased` / `allowance_reduced` | known → larger / smaller nonzero |
| `allowance_revoked` | known > 0 → 0 |
| `allowance_became_unknown` / `allowance_became_known` | verifiability changed |
| `delegation_set` / `delegation_changed` / `delegation_cleared` | EIP-7702 indicator appeared / target changed / cleared |
| `account_code_changed` | any other code-hash change |

Every change is located in `(from_block, to_block]`. The **cause** is an `approval_event` (with
its transaction hash) only if the latest Approval event in that interval sets exactly the new
allowance; otherwise it is `state_comparison` with no transaction hash. This is common and
expected: tokens often reduce allowances in `transferFrom` without an event, and an approval
can be partly spent in the same block. Delegation causes are always `state_comparison`
(set-code transactions are not indexed yet). A pair carried forward without re-verification
never produces a change.

## Rules (`risk/rules.py`, ruleset `cg-rules` 1.0.0)

Severity (`informational`, `review_recommended`, `elevated_risk`, `critical_evidence`,
`unknown`) is independent of confidence (`high`, `medium`, `low`). No current rule emits
`critical_evidence`; it is reserved for independently verifiable evidence of harm.

| Rule | Fires when | Severity / confidence | False-positive considerations |
|---|---|---|---|
| CG-APR-001 | Active unlimited or effectively unlimited allowance | review_recommended if balance > 0, else informational / high | Standard for DEX routers and Permit2 |
| CG-APR-002 | Active allowance to a spender with no code | elevated_risk / medium | Counterfactual smart accounts, some OTC flows |
| CG-APR-003 | Approval exists but `allowance()` is unreadable | unknown / low | Non-standard or self-destructed tokens |
| CG-DEL-001 | Active EIP-7702 delegation | review_recommended / high | Intended smart-account upgrades |
| CG-DEL-002 | Delegation target has no code | elevated_risk / medium | Target deployed later by the intended party |
| CG-COD-001 | `0xef0100` prefix with wrong length | unknown / low | Indicates provider/data problems, not user risk |

**Fingerprint** = keccak(`rule | ruleset major | chain | wallet | subject`); the subject is the
`token:spender` pair or `delegation:<target>`. The same condition is always the same finding.

**Lifecycle**: first observation → `new`; observed again → `active`; user acknowledgement →
`acknowledged` (persists while the condition holds); condition gone → `resolved`; reappears →
`new` again (`reopen_count` increments); open findings from an older ruleset major →
`superseded`. Rules that are stages of one condition form an exclusive group (CG-POI-001/002/
003); when one replaces another for the same subject, the old finding is `superseded` with the
replacement named, never `resolved`, because the condition escalated rather than ended. An open finding whose subject could not be verified at the snapshot block is
left unchanged and counted as not re-verified, never resolved. Every transition is stored with
its snapshot and reason.

## Address poisoning (`detectors/poisoning.py`, detector `address-poisoning` 1.0.0)

**Attack.** After a wallet pays address R, an attacker generates a vanity address C with R's
first and last characters (what wallets display) and plants it in the wallet's history, most
often with `transferFrom(wallet, C, 0)`, which many tokens allow without any allowance, or
with dust or fake-token transfers from C. The victim later copies C from history.

**Inputs.** ERC-20 `Transfer` logs in both directions (3 topics + 32-byte data only; ERC-721
shapes are excluded), plus `tx.from` of outgoing transfers (bounded lookups, newest first).
Snapshots keep this history, so lookalikes are compared against every reference seen since
the wallet's first snapshot.

**References** are recipients of nonzero outgoing transfers that the wallet signed. A
foreign signer on a plain EOA means the transfer was spoofed: it is never a reference. For
wallets with code (smart accounts, EIP-7702 delegations) a relayer may sign legitimately, so
foreign signers make the reference *unconfirmed* instead.

**Similarity** compares the full 40-hex-character bodies (never the shortened display):
common prefix ≥ `POISONING_MIN_PREFIX` (2), common suffix ≥ `POISONING_MIN_SUFFIX` (2), and
together ≥ `POISONING_MIN_AFFIX_TOTAL` (7). If the shared prefix is only zeros, the suffix
must be ≥ 4. A random address matches n characters with probability 16⁻ⁿ; each case reports
these odds.

**Signals** on the lookalike

| Signal | Meaning |
|---|---|
| `zero_value_transfer` | zero-value transfer between wallet and lookalike (signer named if foreign) |
| `spoofed_outgoing_transfer` | nonzero "outgoing" transfer in a transaction the wallet did not sign (fake tokens) |
| `unsolicited_incoming_transfer` | incoming transfer from the lookalike before the wallet ever paid it |
| `appeared_soon_after_reference_use` | first appearance within `POISONING_REACTION_WINDOW_BLOCKS` (≈1 week) of the reference's first use |
| `unverified_outgoing_to_lookalike` | nonzero send to the lookalike whose signer is unknown |
| `wallet_sent_to_lookalike` | the wallet signed a nonzero send to the lookalike after paying the reference |

**Rules**

| Rule | Fires when | Severity / confidence |
|---|---|---|
| CG-POI-003 | `wallet_sent_to_lookalike` | critical_evidence / medium if poisoning context preceded the send; else elevated_risk / low |
| CG-POI-001 | similarity + zero-value, spoofed or unsolicited transfer | elevated_risk / high (zero-value or spoofed) or medium |
| CG-POI-002 | similarity with no other context | informational / low |

Each case lists the suspect, the imitated address, prefix/suffix lengths, a display example,
the random-match odds, every signal with its transaction, and a verification action ("compare
the full address with a trusted source; never copy from history"). No action ever involves
keys or signing.

**False-positive guards (each covered by tests):** identical addresses; the wallet itself;
the zero and `…dEaD` burn addresses; curated known contracts; shared zero-only prefixes
(vanity contracts) with short suffixes; similarity below thresholds; unrelated token spam
(similarity is always required); relayer-signed transfers of smart accounts; and ordering:
of two similar references, the one used first is the original.

**Native sends.** The wallet's own ETH-carrying transactions count as wallet-signed sends,
both as references and as sends to a lookalike. Snapshots and the one-off scan locate every
transaction the wallet signed in their window by nonce search (`services/wallet_txs.py`):
gallop down from the newest known block, then bisect `eth_getTransactionCount`, then read the
transaction from its block. Each snapshot stores the wallet's nonce, so the next one needs no
old state. On providers without historical state, transactions beyond the readable horizon
are counted as *unlocated* in the coverage instead of guessed. Each ETH-carrying transaction's
receipt is read: a **reverted** send (nonce used, no ETH moved) still shows which recipient the
wallet meant to pay, so it can be a reference, but it is never evidence that funds reached a
lookalike; a receipt that cannot be read, or that comes from another block, leaves the status
unknown and the send is treated as executed (the conservative choice for warnings). The 1,155 WBTC case shows why
this matters: the victim paid the later-imitated address in native ETH, so ERC-20 data alone
never reveals it (see [EVALUATION.md](EVALUATION.md)). Confirmed through the live snapshot
pipeline on 2026-10-24 (eth.drpc.org, 477 requests): snapshots at blocks 19,788,641 /
19,788,642 / 19,789,009 produced no finding, then CG-POI-001 (elevated, high) at the poisoning
block, then CG-POI-003 (critical evidence, medium) at the theft block with CG-POI-001
superseded.

**Known gaps.** Native ETH *received* by the wallet (ETH dust from a lookalike) is still
invisible over JSON-RPC. Contract wallets' payments are executed by relayers, not signed by
the wallet, so they are not located this way.
Lookalikes of addresses paid before the scanned history are not recognized. Signer lookups are
budgeted; skipped ones are reported.

## Experimental analyses (`analytics/`, version 0.1.0): off by default, shadow mode only

Three families of analyses were implemented and evaluated against the existing detector
and simpler baselines. **None improved detection on the evaluation data, so none is enabled
by default and none can create a finding or change a severity.** With
`CRYPTOGUARD_ANALYSIS_GRAPH`, `_SPECTRAL` or `_TEMPORAL` set to `shadow`, the analyses run on
stored data, are returned by `GET /api/v1/wallets/{address}/analysis`, are logged after each
snapshot (bounded to 30 s, failures logged, never failing the snapshot), and appear in the
UI as a clearly labelled "Additional context (experimental)" block under the threat graph.
They need the optional `analytics` extra (NumPy, SciPy); without it they report
`unavailable`.

**Input.** `analytics/observations.py` cuts the stored ERC-20 transfers and wallet-signed
native sends at an explicit block, drops repeated observations of the same event (transfer
= transaction hash + log index; native send = transaction hash), and carries the ranges in
which each kind was completely scanned. Bins or windows outside those ranges are *missing*,
never zero. Coverage notes (including what is not visible at all: native ETH received,
internal transfers, counterparties' other activity, signers of incoming transfers) come
with every result, and "nothing unusual observed" is never phrased as "safe".

**Graph (`analytics/graph.py`).** A directed, typed graph of the wallet's *observed
neighbourhood*: `transfer` (sender → recipient), `native_transfer` (wallet → recipient),
`caused` (signer → recipient, when someone other than the wallet signed a transaction that
moved tokens "from" it), `token_use` (counterparty → token contract). Edges aggregate the
events behind them (count, zero-value count, first/last block, sample transactions) and keep
their direction. Node order is sorted (deterministic); node and edge budgets truncate the
least recently active parts and report how much was dropped. Every counterparty is adjacent
to the wallet by construction, so analyses of links *between* counterparties exclude the
wallet node; otherwise every pair would be at most two hops apart.

**Propagation (`analytics/diffusion.py`).** Seeds are open CG-POI-001/003 warnings first
seen at or before the cutoff (detector outputs used as secondary signals; no external
threat labels are ingested, and no later knowledge is used). On the symmetric projection
`W + Wᵀ` (weights: transfer, native transfer and caused 1.0, token use 0.25):
`u(τ) = exp(−τ L_sym) u(0)` with `L_sym = I′ − D^(−1/2) W D^(−1/2)`, computed with SciPy's
`expm_multiply` (never a dense exponential), τ ∈ {0.5, 1, 2} (dimensionless, not chain time).
Isolated nodes follow Chung's convention (`I′` has 0 there), so they neither leak nor receive
signal. The projection loses who-paid-whom; the direction-aware baseline is personalized
PageRank (damping 0.85) walked against edge direction, alongside hop distance and
degree-normalized neighbour aggregation. Each related address is explained by its shortest
path to a seed, with the relation and an example transaction per step. Scores are not
probabilities. Verified by tests: τ = 0 identity; two-node closed form; sparse = dense
`expm` on small graphs (combinatorial and normalized, including isolated nodes and two
components); mass and constant-vector conservation for `L` and `D^(1/2)1` invariance for
`L_sym`; non-negativity on random graphs; disconnected components receive nothing;
determinism; PPR sums to 1 and respects direction.

**Structure (`analytics/spectral.py`).** Plain features (nodes, edges, counterparties,
events, maximum degree) and normalized-Laplacian eigenvalues (components, algebraic
connectivity of the largest component, λ_max), computed densely up to 1,500 nodes and
otherwise reported as skipped. Graphs whose node sets differ are compared only through their
empirical spectral distributions (1-Wasserstein distance, bounded by 2 for any size), never
through eigenvectors from different bases. Verified: K4 and P3 spectra, relabelling
invariance, degenerate graphs, size normalization of the distance, `uᵀLu = ½ Σ W_ij (u_i − u_j)²`.

**Activity (`analytics/temporal.py`).** Per 300-block bin (about an hour; block time, not
ingestion time): transfers, zero-value transfers, incoming transfers from addresses the
wallet never paid (decided with the data available at the time), and new counterparties.
A bin's score is `(count − median) / max(1.4826·MAD, √(median + 1))` against strictly earlier
observed bins; at least 12 observed bins are required, otherwise the result is
`insufficient_data`. An EWMA baseline is evaluated alongside. A univariate Hawkes process
with exponential kernel (`hawkes.py`, MLE with the branching ratio constrained below 0.99)
was fitted for evaluation only. Verified: constant rate gives no anomaly, an injected burst is
found with its transactions, short histories are not scored, uncovered bins are missing,
ingestion order does not matter, a later burst cannot change earlier scores, Hawkes reduces to
Poisson at α = 0 and recovers a simulated branching ratio.

**Evaluation and decision** (details and every number in [EVALUATION.md](EVALUATION.md)): 4
publicly reported poisoning thefts and 9 randomly sampled background wallets (27 wallet-days,
unlabelled), all methods point in time per bin.

- The existing detector named the eventual recipient before the harm in 4/4 incidents, 42 to
  13,057 blocks ahead. No other method and no combination warned earlier in any incident.
- Count rule, robust-z bursts and EWMA bursts were on target in the same 2/4 incidents (the
  ones with a visible burst of planting transfers), always at or after A's warning; spectral
  distance was on target in 0/4. Adding them to A only raised the background alert rate (from
  0.11 to 0.15 alerts per wallet-day; the structural-count baseline to 0.56).
- On this data, propagation surfaces a flagged lookalike's direct neighbours (the signer of
  the planting transaction and the token contract used, which the CG-POI evidence already
  names) and, two hops away, other counterparties that merely used the same token contract.
  No second lookalike was ever linked through a shared signer, and heat-kernel rankings
  largely coincide with hop distance (top-5 overlap 2–5 of 5). The neighbourhood graph is too shallow for
  diffusion to add information; expanding it would require reading counterparties' activity.
- Every background alert of the existing detector was a lookalike sharing 7–10 characters
  with a payee plus spoofed or zero-value transfers, i.e. very likely a genuine poisoning
  attempt, not a false alarm. The sample is too small for rates beyond descriptive use.
- Hawkes fitted better than Poisson on held-out data where there were enough events (2 of 13
  subjects), confirming burstiness, but it was not turned into a detector: the simpler
  temporal statistics already add nothing here.

## Cross-wallet poisoning campaigns (`campaigns/`, `campaign-cluster/1`): off by default

With `CRYPTOGUARD_CAMPAIGN_ANALYSIS=shadow`, CryptoGuard groups poisoning attempts on
different monitored wallets that share planting infrastructure and shows them as
"potentially related poisoning activity". It never creates a finding, changes a severity
or calls any address malicious; tested by taking the same snapshots with the setting off
and in shadow mode.

**Attempt.** One planting event (spoofed outgoing transfer, zero-value transfer, unsolicited
incoming transfer) that the existing detector attributes to a lookalike for that wallet.
The transaction signer (`tx.from`, read from the chain) is kept apart from the Transfer
log's `from`/`to` and from the emitting contract; a Transfer log is never treated as proof
that assets moved. Identity: keccak(chain | tx hash | log index | victim | lookalike).

**Relationships** (two attempts share an entity on the planting side; the victim and the
imitated payee never link):

| Shared entity | Strength | Merges |
|---|---|---|
| planting transaction | directly observed | yes |
| lookalike address | strongly supported | yes |
| verified planting signer (≤ 25 distinct lookalikes) | strongly supported | yes |
| narrow token contract, contract deployer | tentative | no (context) |
| popular token contract (USDT, USDC, WETH, DAI, WBTC), hub signer, block proximity | insufficient | no |

"Strongly supported" describes the evidence of shared infrastructure, not of one operator:
a planting key could belong to a service used by several attackers.

**Clusters.** Connected components of attempts over merging links. Each cluster states
its structure: `shared_entity` (every member shares one entity), `multiply_connected`, or
`chained` (an attempt or entity is an articulation point; members on either side may share
nothing directly), and chained clusters are at most *tentative*. IDs hash the exact
membership, so a changed cluster gets a new id; lineage (grown, split, merged) is reported.

**Expansion** (`campaigns expand`, budgeted and resumable): the planting signer's own
transactions near a known attempt (nonce search, then receipts), Transfer logs to and from
the lookalike around it, and the creator of narrow token contracts (code bisection; only
top-level deployments). An expanded event becomes an attempt only if the candidate target
had just paid an address the lookalike resembles (within 100 blocks, detector
thresholds); everything else stays an unverified candidate. Funding sources and
factory-created contracts are not visible over standard JSON-RPC and are reported as not
attempted.

**Point in time.** Historical analyses re-run the detector at the cutoff (a planting event
can qualify only after a later payment), use expansion tasks only once their seed entity
was recognised, and ignore deployers created later. Each rule has a regression test.

**Evaluation** ([CAMPAIGN_EVALUATION.md](CAMPAIGN_EVALUATION.md); 4 incidents, 9 background
wallets, one recorded expansion of 2,382 RPC requests). There is no independent label of
common control, so no precision or recall is claimed. Findings:

- Real cross-wallet links exist. Monitored wallets alone give 4 multi-wallet clusters,
  linked by verified planting signers; the expansion found 140 verified attempts on 100
  further wallets and raises that to 9. 13 planting transactions targeted several wallets
  at once.
- 23 of 54 attempts on monitored wallets used a planting signer already seen on another
  wallet earlier, including the plantings of two eventual theft recipients (each signer was
  already linked to 15 other targeted wallets).
- It never warned earlier than the existing detector: before 3 of the 4 thefts the
  recipient's cluster spanned several wallets, but only from the block of the detector's
  own warning or later.
- Guards matter: merging on every shared entity grows the largest cluster from 31 attempts
  on 12 wallets to 58 on 34; block proximity alone would add 95 unsupported links.
- Diffusion rankings agree with hop distance, shared-neighbour counts and PageRank (4.3–5
  of the top 5), and the spectral gap only restates what articulation points show; neither
  is used in clustering.

## Finality

`finalized` if the observed block number ≤ the provider's `finalized` block, otherwise
`not_finalized`; `unknown` if the provider does not support the tag.
