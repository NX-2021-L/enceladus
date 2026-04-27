"""Unit tests for mentions_extraction.py — ENC-TSK-G34 AC-4 (>=95% coverage).

Run from backend/lambda/graph_sync/:
    python -m pytest test_mentions_extraction.py -v --cov=mentions_extraction
"""
from __future__ import annotations

import pytest

from mentions_extraction import (
    DEFAULT_ID_ALPHABET,
    MENTIONS_PROSE_FIELDS,
    extract_id_tokens,
    stamp_provenance,
    strip_code_fences,
)


# ---------------------------------------------------------------------------
# MENTIONS_PROSE_FIELDS (ENC-TSK-G43)
# ---------------------------------------------------------------------------
# The allowlist is the single source of truth shared between the live
# reconciler (graph_sync.lambda_function) and the daily drift audit
# (deploy_parity_validator). Drift between them would silently emit
# false-positive ENC-ISS records, so these guards are load-bearing.

class TestMentionsProseFields:
    def test_covers_all_governed_record_types(self):
        expected = {"task", "issue", "feature", "plan", "lesson",
                    "generation", "document"}
        assert set(MENTIONS_PROSE_FIELDS) == expected

    def test_every_record_type_has_title_and_description(self):
        for record_type, fields in MENTIONS_PROSE_FIELDS.items():
            assert "title" in fields, f"{record_type} missing title"
            assert "description" in fields, f"{record_type} missing description"

    def test_issue_includes_hypothesis_and_technical_notes(self):
        assert "hypothesis" in MENTIONS_PROSE_FIELDS["issue"]
        assert "technical_notes" in MENTIONS_PROSE_FIELDS["issue"]

    def test_document_includes_content(self):
        assert "content" in MENTIONS_PROSE_FIELDS["document"]

    def test_fields_are_immutable_tuples(self):
        for record_type, fields in MENTIONS_PROSE_FIELDS.items():
            assert isinstance(fields, tuple), f"{record_type}: expected tuple"


# ---------------------------------------------------------------------------
# strip_code_fences
# ---------------------------------------------------------------------------

class TestStripCodeFences:
    def test_empty_input(self):
        assert strip_code_fences("") == ""

    def test_none_safe(self):
        assert strip_code_fences(None) == ""  # type: ignore[arg-type]

    def test_no_fences_unchanged(self):
        text = "See ENC-TSK-G33 for context."
        assert strip_code_fences(text) == text

    def test_single_fence_stripped(self):
        text = "before\n```python\nENC-TSK-INSIDE\n```\nafter"
        out = strip_code_fences(text)
        assert "ENC-TSK-INSIDE" not in out
        assert "before" in out
        assert "after" in out

    def test_fence_with_lang_tag(self):
        text = "x ```json\n{\"id\": \"ENC-FTR-098\"}\n``` y"
        out = strip_code_fences(text)
        assert "ENC-FTR-098" not in out

    def test_multiple_fences(self):
        text = "```\nENC-TSK-A\n```\nkeep ENC-TSK-B\n```\nENC-TSK-C\n```"
        out = strip_code_fences(text)
        assert "ENC-TSK-A" not in out
        assert "ENC-TSK-C" not in out
        assert "ENC-TSK-B" in out

    def test_inline_backticks_preserved(self):
        # Single-backtick spans are NOT stripped -- intentional design.
        text = "Use the `ENC-TSK-G34` helper."
        assert "ENC-TSK-G34" in strip_code_fences(text)

    def test_unterminated_fence_left_intact(self):
        # An unterminated fence has no closing run, so the regex does not
        # match and content survives. Caller may still extract IDs.
        text = "```\nENC-TSK-OPEN\n(no closing fence)"
        out = strip_code_fences(text)
        assert "ENC-TSK-OPEN" in out


# ---------------------------------------------------------------------------
# extract_id_tokens
# ---------------------------------------------------------------------------

class TestExtractIdTokens:
    def test_empty_input(self):
        assert extract_id_tokens("") == set()

    def test_none_safe(self):
        assert extract_id_tokens(None) == set()  # type: ignore[arg-type]

    def test_single_task_id(self):
        assert extract_id_tokens("see ENC-TSK-G33 for context") == {"ENC-TSK-G33"}

    def test_all_default_prefixes(self):
        text = (
            "ENC-TSK-A01 ENC-ISS-B22 ENC-FTR-098 ENC-LSN-013 "
            "ENC-PLN-006 ENC-GEN-001 ENC-DPL-XYZ"
        )
        out = extract_id_tokens(text)
        assert out == {
            "ENC-TSK-A01", "ENC-ISS-B22", "ENC-FTR-098", "ENC-LSN-013",
            "ENC-PLN-006", "ENC-GEN-001", "ENC-DPL-XYZ",
        }

    def test_dedup_repeated(self):
        text = "ENC-TSK-G33 and again ENC-TSK-G33 plus ENC-TSK-G33."
        assert extract_id_tokens(text) == {"ENC-TSK-G33"}

    def test_document_id(self):
        text = "Source: DOC-59D2295AA7FD section 7.2"
        assert extract_id_tokens(text) == {"DOC-59D2295AA7FD"}

    def test_component_id(self):
        text = "Affects comp-enceladus-mcp-server runtime"
        assert extract_id_tokens(text) == {"comp-enceladus-mcp-server"}

    def test_mixed_prefixes(self):
        text = (
            "ENC-TSK-G35 wires ENC-TSK-G34 helper into graph_sync. "
            "Source: DOC-59D2295AA7FD. Affects comp-enceladus-mcp-server."
        )
        assert extract_id_tokens(text) == {
            "ENC-TSK-G35", "ENC-TSK-G34",
            "DOC-59D2295AA7FD", "comp-enceladus-mcp-server",
        }

    def test_word_boundary_prevents_partial_match(self):
        # Embedded in larger token must not match.
        text = "XENC-TSK-G33Y nope"
        assert extract_id_tokens(text) == set()

    def test_unknown_prefix_skipped(self):
        # ABC is not in the default alphabet.
        text = "ENC-ABC-001 should not match; ENC-TSK-001 should."
        assert extract_id_tokens(text) == {"ENC-TSK-001"}

    def test_lowercase_prefix_does_not_match(self):
        # Word-boundary regex is case-sensitive on the ENC-/DOC- prefix.
        assert extract_id_tokens("enc-tsk-001") == set()

    def test_id_at_start_and_end(self):
        text = "ENC-TSK-AAA middle ENC-TSK-BBB"
        assert extract_id_tokens(text) == {"ENC-TSK-AAA", "ENC-TSK-BBB"}

    def test_id_with_punctuation(self):
        text = "(see ENC-FTR-098), then [DOC-59D2295AA7FD]."
        assert extract_id_tokens(text) == {"ENC-FTR-098", "DOC-59D2295AA7FD"}

    def test_custom_alphabet_filters(self):
        # Custom alphabet limited to TSK only — ISS should not match.
        text = "ENC-TSK-001 ENC-ISS-002"
        assert extract_id_tokens(text, alphabet=("TSK",)) == {"ENC-TSK-001"}

    def test_custom_alphabet_includes_new_prefix(self):
        # Forward-compat: future record type with new prefix.
        text = "ENC-FOO-XYZ alongside ENC-TSK-001"
        assert extract_id_tokens(
            text, alphabet=("TSK", "FOO"),
        ) == {"ENC-FOO-XYZ", "ENC-TSK-001"}

    def test_default_alphabet_constant_unchanged(self):
        # Guards against accidental mutation of the default tuple.
        assert DEFAULT_ID_ALPHABET == (
            "TSK", "ISS", "FTR", "LSN", "PLN", "GEN", "DPL",
        )

    def test_doc_id_must_be_12_hex(self):
        # 11-char and 13-char digests are rejected; only 12-hex matches.
        assert extract_id_tokens("DOC-59D2295AA7F") == set()
        assert extract_id_tokens("DOC-59D2295AA7FDDD") == set()

    def test_three_or_four_char_suffix(self):
        # ENC-<TYPE>-<3 or 4 chars> matches; 2-char and 5-char do not.
        assert extract_id_tokens("ENC-TSK-AB") == set()
        assert extract_id_tokens("ENC-TSK-ABCDE") == set()
        assert extract_id_tokens("ENC-TSK-ABC") == {"ENC-TSK-ABC"}
        assert extract_id_tokens("ENC-TSK-ABCD") == {"ENC-TSK-ABCD"}


# ---------------------------------------------------------------------------
# stamp_provenance
# ---------------------------------------------------------------------------

class TestStampProvenance:
    def test_empty_payload(self):
        out = stamp_provenance({}, "description")
        assert out == {"source": "auto_mention", "extracted_from_field": "description"}

    def test_none_payload_safe(self):
        out = stamp_provenance(None, "title")  # type: ignore[arg-type]
        assert out == {"source": "auto_mention", "extracted_from_field": "title"}

    def test_default_source_is_auto_mention(self):
        out = stamp_provenance({"weight": 0.5}, "intent")
        assert out["source"] == "auto_mention"
        assert out["extracted_from_field"] == "intent"
        assert out["weight"] == 0.5

    def test_custom_source(self):
        out = stamp_provenance({}, "description", source="backfill")
        assert out["source"] == "backfill"

    def test_input_not_mutated(self):
        original = {"weight": 0.7, "ts": "2026-04-25"}
        stamp_provenance(original, "user_story")
        assert original == {"weight": 0.7, "ts": "2026-04-25"}

    def test_existing_source_overwritten(self):
        # Documented behavior: stamp_provenance owns these two keys.
        out = stamp_provenance(
            {"source": "stale", "extracted_from_field": "stale_field"},
            "description",
        )
        assert out["source"] == "auto_mention"
        assert out["extracted_from_field"] == "description"


# ---------------------------------------------------------------------------
# Integrated round-trip — strip + extract + stamp
# ---------------------------------------------------------------------------

class TestIntegratedFlow:
    def test_fenced_ids_excluded_unfenced_extracted(self):
        text = (
            "Reference ENC-TSK-G35 in prose.\n"
            "```python\n"
            "task_id = 'ENC-TSK-FENCED'\n"
            "```\n"
            "Also ENC-FTR-098 and DOC-59D2295AA7FD."
        )
        cleaned = strip_code_fences(text)
        tokens = extract_id_tokens(cleaned)
        assert tokens == {"ENC-TSK-G35", "ENC-FTR-098", "DOC-59D2295AA7FD"}
        assert "ENC-TSK-FENCED" not in tokens

    def test_provenance_for_extracted_set(self):
        cleaned = strip_code_fences("see ENC-FTR-098")
        tokens = extract_id_tokens(cleaned)
        edges = [stamp_provenance({}, "description") for _ in tokens]
        assert all(e["source"] == "auto_mention" for e in edges)
        assert all(e["extracted_from_field"] == "description" for e in edges)
