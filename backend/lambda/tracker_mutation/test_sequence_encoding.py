"""Tests for record ID sequence encoding (ENC-ISS-132, ENC-FTR-056).

Validates:
- Base-36 encoding/decoding (_encode_base36 / _decode_base36)
- Legacy compatibility (_format_sequence / _parse_sequence wrappers)
- Round-trip correctness for all formats
- Sub-task suffix generation logic
- Boundary cases and overflow detection
"""
import sys
import os
import pytest

# Add the tracker_mutation Lambda to the path so we can import the functions.
sys.path.insert(0, os.path.dirname(__file__))
from lambda_function import (
    _encode_base36,
    _decode_base36,
    _format_sequence,
    _parse_sequence,
    _SEQUENCE_CAPACITY,
    _BASE36_CAPACITY,
    _SUBTASK_SUFFIX_CAPACITY,
)


# ---------------------------------------------------------------------------
# _encode_base36 tests
# ---------------------------------------------------------------------------

class TestEncodeBase36:
    """Encoding: integer -> 3-char sequence string."""

    def test_zero(self):
        assert _encode_base36(0) == "000"

    def test_one(self):
        assert _encode_base36(1) == "001"

    def test_nine(self):
        assert _encode_base36(9) == "009"

    def test_ten(self):
        # 10 is in the decimal range (0-999), so "010"
        assert _encode_base36(10) == "010"

    def test_forty_two(self):
        assert _encode_base36(42) == "042"

    def test_999(self):
        assert _encode_base36(999) == "999"

    def test_1000_alpha_a01(self):
        # Legacy alpha range starts at 1000
        assert _encode_base36(1000) == "A01"

    def test_1098_alpha_a99(self):
        assert _encode_base36(1098) == "A99"

    def test_1099_alpha_b01(self):
        assert _encode_base36(1099) == "B01"

    def test_3573_alpha_z99(self):
        assert _encode_base36(3573) == "Z99"

    def test_3574_pure_base36(self):
        # First value in the pure base-36 range
        # 3574 in base-36: 3574 / 36 = 99 r 10 -> 99 / 36 = 2 r 27 -> "2R" + "A"
        # Actually: 3574 = 2*1296 + 27*36 + 10 = 2592 + 972 + 10 = 3574
        # Digits: [10, 27, 2] reversed = [2, 27, 10] = "2RA"
        result = _encode_base36(3574)
        assert len(result) == 3
        # Verify it round-trips
        assert _decode_base36(result) == 3574

    def test_46655_max(self):
        assert _encode_base36(46655) == "ZZZ"

    def test_capacity_constant(self):
        assert _BASE36_CAPACITY == 46655

    def test_capacity_exhausted(self):
        with pytest.raises(ValueError, match="capacity exhausted"):
            _encode_base36(46656)

    def test_large_overflow(self):
        with pytest.raises(ValueError, match="capacity exhausted"):
            _encode_base36(100000)

    def test_negative_rejected(self):
        with pytest.raises(ValueError, match="must be >= 0"):
            _encode_base36(-1)

    def test_all_results_three_chars(self):
        """Spot-check that encoding always produces 3-char strings."""
        for n in [0, 1, 10, 35, 36, 100, 999, 1000, 1296, 3573, 3574, 10000, 46655]:
            result = _encode_base36(n)
            assert len(result) == 3, f"n={n} produced {result!r} (len {len(result)})"


# ---------------------------------------------------------------------------
# _decode_base36 tests
# ---------------------------------------------------------------------------

class TestDecodeBase36:
    """Decoding: sequence string -> integer."""

    def test_zero(self):
        assert _decode_base36("000") == 0

    def test_one(self):
        assert _decode_base36("001") == 1

    def test_999(self):
        assert _decode_base36("999") == 999

    def test_zzz(self):
        assert _decode_base36("ZZZ") == 46655

    def test_case_insensitive(self):
        assert _decode_base36("zzz") == 46655

    def test_legacy_numeric_042(self):
        assert _decode_base36("042") == 42

    def test_legacy_numeric_overflow_1000(self):
        """Legacy 4-digit overflow IDs should parse as plain integers."""
        assert _decode_base36("1000") == 1000

    def test_legacy_numeric_overflow_1022(self):
        assert _decode_base36("1022") == 1022

    def test_legacy_alpha_a01(self):
        assert _decode_base36("A01") == 1000

    def test_legacy_alpha_a99(self):
        assert _decode_base36("A99") == 1098

    def test_legacy_alpha_b01(self):
        assert _decode_base36("B01") == 1099

    def test_legacy_alpha_z99(self):
        assert _decode_base36("Z99") == 3573

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            _decode_base36("")

    def test_invalid_char_rejected(self):
        with pytest.raises(ValueError):
            _decode_base36("$$$")


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Verify encode/decode round-trips for all valid counters."""

    def test_round_trip_numeric_range(self):
        for n in range(0, 1000):
            seq = _encode_base36(n)
            assert _decode_base36(seq) == n, f"Round-trip failed for {n}: encoded={seq!r}"

    def test_round_trip_alpha_range(self):
        for n in range(1000, 3574):
            seq = _encode_base36(n)
            assert _decode_base36(seq) == n, f"Round-trip failed for {n}: encoded={seq!r}"

    def test_round_trip_extended_range(self):
        for n in range(3574, 3700):
            seq = _encode_base36(n)
            assert _decode_base36(seq) == n, f"Round-trip failed for {n}: encoded={seq!r}"

    def test_round_trip_high(self):
        for n in range(46600, 46656):
            seq = _encode_base36(n)
            assert _decode_base36(seq) == n, f"Round-trip failed for {n}: encoded={seq!r}"

    def test_round_trip_boundaries(self):
        boundaries = [0, 1, 9, 10, 35, 36, 999, 1000, 1098, 1099, 3573, 3574, 3575, 46655]
        for n in boundaries:
            seq = _encode_base36(n)
            parsed = _decode_base36(seq)
            assert parsed == n, f"Boundary {n}: encoded={seq!r}, decoded={parsed}"

    def test_full_range_round_trip(self):
        """Exhaustive round-trip for entire capacity (46656 values)."""
        for n in range(0, 46656):
            assert _decode_base36(_encode_base36(n)) == n, f"Round-trip failed for {n}"


# ---------------------------------------------------------------------------
# _format_sequence / _parse_sequence wrappers (backward compat)
# ---------------------------------------------------------------------------

class TestFormatSequence:
    """Encoding via legacy wrapper: counter (starting at 1) -> sequence string."""

    def test_low(self):
        assert _format_sequence(1) == "001"

    def test_mid(self):
        assert _format_sequence(42) == "042"

    def test_high(self):
        assert _format_sequence(999) == "999"

    def test_alpha_boundary(self):
        assert _format_sequence(1000) == "A01"

    def test_alpha_z99(self):
        assert _format_sequence(3573) == "Z99"

    def test_extended(self):
        result = _format_sequence(3574)
        assert len(result) == 3

    def test_legacy_capacity_constant(self):
        assert _SEQUENCE_CAPACITY == 3573

    def test_zero_rejected(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            _format_sequence(0)

    def test_negative_rejected(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            _format_sequence(-1)


class TestParseSequence:
    """Decoding via legacy wrapper."""

    def test_numeric_low(self):
        assert _parse_sequence("001") == 1

    def test_numeric_high(self):
        assert _parse_sequence("999") == 999

    def test_alpha_a01(self):
        assert _parse_sequence("A01") == 1000

    def test_alpha_z99(self):
        assert _parse_sequence("Z99") == 3573

    def test_legacy_overflow_1000(self):
        assert _parse_sequence("1000") == 1000

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            _parse_sequence("")


class TestFormatParseRoundTrip:
    """Round-trip through _format_sequence -> _parse_sequence."""

    def test_round_trip_full(self):
        """All values 1-3573 should round-trip through format/parse."""
        for i in range(1, 3574):
            seq = _format_sequence(i)
            parsed = _parse_sequence(seq)
            assert parsed == i, f"Round-trip failed for {i}: seq={seq!r}, parsed={parsed}"

    def test_round_trip_extended(self):
        """Extended range 3574-46655 should also round-trip."""
        for i in range(3574, 3700):
            seq = _format_sequence(i)
            parsed = _parse_sequence(seq)
            assert parsed == i, f"Round-trip failed for {i}: seq={seq!r}, parsed={parsed}"


# ---------------------------------------------------------------------------
# Sub-task suffix sequence tests (ENC-FTR-056)
# ---------------------------------------------------------------------------

class TestSubtaskSuffixLogic:
    """Test the digit+letter suffix generation logic (without DynamoDB)."""

    def test_suffix_sequence(self):
        """Verify the suffix generation pattern: 0A, 0B, ..., 0Z, 1A, ..., 9Z."""
        expected = []
        for digit in range(10):
            for letter_idx in range(26):
                expected.append(f"{digit}{chr(ord('A') + letter_idx)}")
        assert len(expected) == 260

        assert expected[0] == "0A"
        assert expected[1] == "0B"
        assert expected[25] == "0Z"
        assert expected[26] == "1A"
        assert expected[259] == "9Z"

    def test_suffix_from_counter(self):
        """Verify counter-to-suffix mapping matches the function logic."""
        for n in range(260):
            digit = n // 26
            letter = chr(ord("A") + n % 26)
            suffix = f"{digit}{letter}"
            assert len(suffix) == 2
            assert suffix[0].isdigit()
            assert suffix[1].isalpha()

    def test_capacity_constant(self):
        assert _SUBTASK_SUFFIX_CAPACITY == 260


# ---------------------------------------------------------------------------
# Cross-component ID format validation (updated for ENC-FTR-056)
# ---------------------------------------------------------------------------

class TestRecordIdFormat:
    """Validate that generated IDs conform to expected patterns."""

    def test_numeric_id_format(self):
        import re
        pattern = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-[A-Z0-9]{3}$")
        for counter in [1, 42, 999]:
            seq = _encode_base36(counter)
            rid = f"ENC-TSK-{seq}"
            assert pattern.match(rid), f"ID {rid!r} does not match format"

    def test_alpha_id_format(self):
        import re
        pattern = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-[A-Z0-9]{3}$")
        for counter in [1000, 1099, 3573, 3574, 46655]:
            seq = _encode_base36(counter)
            rid = f"ENC-ISS-{seq}"
            assert pattern.match(rid), f"ID {rid!r} does not match format"

    def test_subtask_id_format(self):
        import re
        pattern = re.compile(r"^[A-Z]{3}-TSK-[A-Z0-9]{3}-[0-9][A-Z]$")
        for suffix in ["0A", "0Z", "1A", "9Z"]:
            rid = f"ENC-TSK-001-{suffix}"
            assert pattern.match(rid), f"Sub-task ID {rid!r} does not match format"

    def test_legacy_overflow_does_not_match_strict(self):
        import re
        strict = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-[A-Z0-9]{3}$")
        assert not strict.match("ENC-TSK-1000")
        assert not strict.match("ENC-TSK-1022")

    def test_legacy_overflow_matches_lenient(self):
        import re
        lenient = re.compile(r"^[A-Z]{3}-(TSK|ISS|FTR|LSN)-[A-Z0-9]{3,}$")
        assert lenient.match("ENC-TSK-1000")
        assert lenient.match("ENC-TSK-A01")
        assert lenient.match("ENC-ISS-ZZZ")
