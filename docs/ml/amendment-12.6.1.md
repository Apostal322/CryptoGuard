# Amendment 12.6.1: signer-recovery guards, authorization, bounded pages, presentation order

**Written:** 2026-11-09, with the code it describes. Phase 12.6.1 is a correctness and
operations phase, not a new hypothesis test, so nothing here is pre-registered. Every number in
`ML_CANDIDATE_RELIABILITY.md` §30–§39 comes from a study run on the commit that adds this file
(the run records its git SHA).

**Amends:** `protocol-12.6.md`, the R-SIG rule, the presentation order and the summary
contract. **Unchanged:** H1–H7, their pre-registered results (H5 still fails), the evidence
levels, the group identity, C0/C1/C2, the production detector and every frozen fixture.

**Code:** `ml/candidate_evidence.py` (`candidate-evidence/2`), `ml/reliability_study.py`
(`reliability-study/2`). Research only: nothing is wired into the detector or a warning.

## A1. R-SIG proves non-signing only, and only when the guard allows it

Absence from the wallet's signed set proves that the wallet did not **directly** sign a
transaction only when `absence_guard` finds all of the following:

1. The signed set is stated `complete`, with the stated count equal to the records held.
2. A legacy (`observation/1`) fixture documents the nonce bisection that its completeness
   claim rests on.
3. Recorded nonces are unique and consecutive. A gap means a nonce was consumed without a
   recorded transaction: a missing page, or an EIP-7702 authorization.
4. Every recorded transaction lies inside the window.
5. The account's code is known at the window start, and it is `0x` at every sample up to the
   cutoff. That rules out an EIP-7702 delegation designator and contract or smart-wallet code.
   Samples after the cutoff are ignored.

Otherwise the signer stays `unknown`, and an outgoing lookalike stays
`unverified_out_lookalike` (partially supported). A looked-up signer that contradicts the
signed set is `conflicting`. It is never treated as a reference and never as a spoof.

The recorder's 500-lookup cap (`max_sender_lookups`) limits signer **lookups**. It does not
limit the signed set, so R-SIG still applies to busy wallets.

## A2. Not signed is not unauthorized

A wallet can authorize a pull without signing the transaction that performs it, through an
ERC-20 allowance, a permit, or an EIP-7702 delegation. A fabricated log needs no authorization
at all. So every outgoing ERC-20 record now carries `authorization`:

- **Zero value, foreign signer:** `spoofed_out`, `authorization = not_required`. Nothing moved.
- **Nonzero value, foreign signer (looked up or by R-SIG):** `foreign_initiated_out`, plus
  `untrusted_token_out` when the emitter is known and not trusted. The record has
  `authorization = unknown`, and `authorization` is listed as missing. It is not called a spoof.

The evidence level is unchanged. It still describes the observed facts.

## A3. Presentation order reads no support level

Groups are presented by affix strength, then by the latest planting, then by address
(`presentation_key`). The support level and the missing list are never read. This follows
from the 12.6 separation of support from suspicion:

- a verified receipt cannot move a candidate up;
- a missing fact cannot move a candidate up or down.

The pre-registered support-first order is kept as `evidence_order_key`, only to reproduce H5.

**This is not validated.** The pilot and the ScamSniffer window are development data; they
informed the choice and cannot confirm it. Whether the order helps on new incidents is the
next experiment (§29 of the report). It is not claimed here.

## A4. Bounded summary and page access

`summarize(result, k)` returns:
- at most `k` items (1 ≤ k ≤ 1,000);
- the totals and `hidden_count`;
- a `truncated` flag and `next_offset`;
- a `result_digest` of the full result.

It no longer lists hidden identities, so its size no longer grows with the number of
candidates. The full evidence is reached through two functions:
- `page(result, offset, limit, expect_digest)`, which follows the project's
  `items`/`total`/`limit`/`offset` page convention and refuses a stale digest;
- `group_records(result, identity, offset, limit)`, which pages one group's records.

Nothing is deleted, and hidden candidates are still "not assessed as safe".
