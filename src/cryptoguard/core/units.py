"""Exact integer-to-decimal formatting for display. No floating point is involved."""

from __future__ import annotations


def format_units(value: int, decimals: int) -> str:
    """Format an integer token amount with ``decimals`` places, trimming trailing zeros.

    >>> format_units(1_500_000_000_000_000_000, 18)
    '1.5'
    """
    if decimals < 0:
        raise ValueError("decimals must be non-negative")
    sign = "-" if value < 0 else ""
    whole, fraction = divmod(abs(value), 10**decimals)
    if decimals == 0 or fraction == 0:
        return f"{sign}{whole}"
    fraction_text = str(fraction).rjust(decimals, "0").rstrip("0")
    return f"{sign}{whole}.{fraction_text}"
