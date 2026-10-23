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

## Finality

`finalized` if the observed block number ≤ the provider's `finalized` block, otherwise
`not_finalized`; `unknown` if the provider does not support the tag.
