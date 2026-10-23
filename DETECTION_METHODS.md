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

## Finality

`finalized` if the observed block number ≤ the provider's `finalized` block, otherwise
`not_finalized`; `unknown` if the provider does not support the tag.
