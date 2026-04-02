"""Tests for record ID sequence encoding (ENC-ISS-132).

Validates the alphanumeric rollover scheme: 001-999 (numeric), A01-Z99 (alpha),
and capacity guard at counter >= 3574.
"""
import sys
import os
import pytest

# Add the tracker_mutation Lambda to the path so we can import the functions.
sys.path.insert(0, os.path.dirname(__file__))
from lambda_function import _format_sequence, _parse_sequence, _SEQUENCE_CAPACITY


# ---------------------------------------------------------------------------
# _format_sequence tests
# ---------------------------------------------------------------------------

class TestFormatSequence:
    """Encoding: integer counter -> 3-char display sequence."""

    def test_numeric_range_low(self):
        assert _format_sequence(1) == "001"

    def test_numeric_range_mid(self):
        assert _format_sequence(42) == "042"

    def test_numeric_range_high(self):
        assert _format_sequence(999) == "999"

    def test_alpha_boundary_a01(self):
        assert _format_sequence(1000) == "A01"

    def test_alpha_a99(self):
        assert _format_sequence(1098) == "A99"

    def test_alpha_boundary_b01(self):
        assert _format_sequence(1099) == "B01"

    def test_alpha_mid_m50(self):
        # M is letter_index 12, number 50
        # counter = 1000 + (12 * 99) + (50 - 1) = 1000 + 1188 + 49 = 2237
        assert _format_sequence(2237) == "M50"

    def test_alpha_z01(self):
        # Z is letter_index 25, number 1
        # counter = 1000 + (25 * 99) + 0 = 1000 + 2475 = 3475
        assert _format_sequence(3475) == "Z01"

    def test_alpha_z99(self):
        # counter = 1000 + (25 * 99) + 98 = 3573
        assert _format_sequence(3573) == "Z99"

    def test_capacity_constant(self):
        assert _SEQUENCE_CAPACITY == 3573

    def test_capacity_exhausted(self):
        with pytest.raises(ValueError, match="capacity exhausted"):
            _format_sequence(3574)

    def test_capacity_exhausted_large(self):
        with pytest.raises(ValueError, match="capacity exhausted"):
            _format_sequence(10000)

    def test_zero_rejected(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            _format_sequence(0)

    def test_negative_rejected(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            _format_sequence(-1)

    def test_all_numeric_three_chars(self):
        for i in range(1, 1000):
            seq = _format_sequence(i)
            assert len(seq) == 3, f"Counter {i} produced {seq!r} (len {len(seq)})"
            assert seq.isdigit(), f"Counter {i} produced non-numeric {seq!r}"

    def test_all_alpha_three_chars(self):
        for i in range(1000, 3574):
            seq = _format_sequence(i)
            assert len(seq) == 3, f"Counter {i} produced {seq!r} (len {len(seq)})"
            assert seq[0].isalpha(), f"Counter {i} first char not alpha: {seq!r}"
            assert seq[1:].isdigit(), f"Counter {i} last 2 not digits: {seq!r}"


# ---------------------------------------------------------------------------
# _parse_sequence tests
# ---------------------------------------------------------------------------

class TestParseSequence:
    """Decoding: 3-char display sequence -> integer counter."""

    def test_numeric_low(self):
        assert _parse_sequence("001") == 1

    def test_numeric_mid(self):
        assert _parse_sequence("042") == 42

    def test_numeric_high(self):
        assert _parse_sequence("999") == 999

    def test_alpha_a01(self):
        assert _parse_sequence("A01") == 1000

    def test_alpha_a99(self):
        assert _parse_sequence("A99") == 1098

    def test_alpha_b01(self):
        assert _parse_sequence("B01") == 1099

    def test_alpha_z99(self):
        assert _parse_sequence("Z99") == 3573

    def test_legacy_overflow_1000(self):
        """Legacy 4-digit overflow IDs should parse as plain integers."""
        assert _parse_sequence("1000") == 1000

    def test_legacy_overflow_1022(self):
        assert _parse_sequence("1022") == 1022

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            _parse_sequence("")

    def test_invalid_rejected(self):
        with pytest.raises(ValueError):
            _parse_sequence("XYZ")


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Verify encode/decode round-trips for all valid counters."""

    def test_round_trip_numeric_range(self):
        for i in range(1, 1000):
            assert _parse_sequence(_format_sequence(i)) == i, f"Round-trip failed for {i}"

    def test_round_trip_alpha_range(self):
        for i in range(1000, 3574):
            assert _parse_sequence(_format_sequence(i)) == i, f"Round-trip failed for {i}"

    def test_round_trip_boundaries(self):
        boundaries = [1, 2, 999, 1000, 1098, 1099, 3475, 3573]
        for i in boundaries:
            seq = _format_sequence(i)
            parsed = _parse_sequence(seq)
            assert parsed == i, f"Boundary {i}: encoded={seq!r}, decoded={parsed}"


# ---------------------------------------------------------------------------
# Cross-component ID format validation
# ---------------------------------------------------------------------------

class TestRecordIdFormat:
    """Validate that generated IDs conform to XXX-YYY-NNN format."""

    def test_numeric_id_format(self):
        import re
        pattern = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-(\d{3}|[A-Z]\d{2})$")
        for counter in [1, 42, 999]:
            seq = _format_sequence(counter)
            rid = f"ENC-TSK-{seq}"
            assert pattern.match(rid), f"ID {rid!r} does not match format"

    def test_alpha_id_format(self):
        import re
        pattern = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-(\d{3}|[A-Z]\d{2})$")
        for counter in [1000, 1099, 2237, 3573]:
            seq = _format_sequence(counter)
            rid = f"ENC-ISS-{seq}"
            assert pattern.match(rid), f"ID {rid!r} does not match format"

    def test_legacy_overflow_does_not_match_strict(self):
        """Legacy 4-digit IDs should NOT match the strict 3-char pattern."""
        import re
        strict = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-(\d{3}|[A-Z]\d{2})$")
        assert not strict.match("ENC-TSK-1000")
        assert not strict.match("ENC-TSK-1022")

    def test_legacy_overflow_matches_lenient(self):
        """Legacy 4-digit IDs should match the lenient pattern (for backward compat)."""
        import re
        lenient = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-(?:[A-Z]\d{2}|\d{3,})$")
        assert lenient.match("ENC-TSK-1000")
        assert lenient.match("ENC-TSK-1022")
        assert lenient.match("ENC-TSK-A01")
        assert lenient.match("ENC-ISS-Z99")
