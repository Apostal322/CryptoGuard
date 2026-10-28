"""Point-in-time behaviour of the recorded campaign dataset (real fixtures, no RPC)."""

from __future__ import annotations

from cryptoguard.campaigns.dataset import attempts_at, fixture_attempts, load_expansion
from cryptoguard.core.address import to_checksum_address

CASE = "eth-140-poisoning-2025-08-14"
RECIPIENT = to_checksum_address("0xC61756E0Ea2933Ad8ec8be11cb444c4215c23B86")


def test_attempts_are_re_derived_at_each_cutoff_not_filtered() -> None:
    subjects = fixture_attempts()
    s = next(x for x in subjects if x.subject_id == CASE)
    final = [a for a in s.attempts if a.lookalike == RECIPIENT]
    first = min(a.block_number for a in final)
    # Filtering the final attempts by block would claim the recipient was flagged at its first
    # planting; the detector at that block did not yet know the imitated payment.
    filtered = [a for a in final if a.block_number <= first]
    assert filtered
    assert [a for a in s.attempts_at(first) if a.lookalike == RECIPIENT] == []


def test_inputs_never_postdate_the_cutoff() -> None:
    subjects = fixture_attempts()
    for block in (19_789_008, 23_141_529, 24_047_559):
        assert all(a.block_number <= block for a in attempts_at(subjects, block))
    loaded = load_expansion()
    if loaded is not None:
        extra, deployers = loaded[0].usable_at(23_141_529)
        assert all(a.block_number <= 23_141_529 for a in extra)
        assert all(d.creation_block <= 23_141_529 for d in deployers.values())
