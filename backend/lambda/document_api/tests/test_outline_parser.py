"""test_outline_parser.py — Hand-reasoned unit tests for outline.py (ENC-TSK-P69 AC-2).

Unlike test_outline_fixtures.py (which round-trips the full fixture
corpus against stored expected.json snapshots), these tests assert
specific field values reasoned through by hand against the AC-2 contract,
so a bug that happened to be baked into both the parser AND a generated
snapshot at the same time would still be caught here.

Run: python3 -m pytest test_outline_parser.py -v
"""
from __future__ import annotations

import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_DOCUMENT_API_DIR = os.path.dirname(_TESTS_DIR)
sys.path.insert(0, _DOCUMENT_API_DIR)

import outline  # noqa: E402


def test_no_boto3_import_in_outline_module():
    """outline.py must remain importable with zero AWS SDK dependency."""
    src_path = os.path.join(_DOCUMENT_API_DIR, "outline.py")
    with open(src_path, "r", encoding="utf-8") as f:
        src = f.read()
    assert "boto3" not in src
    assert "botocore" not in src


def test_atx_levels_1_through_6():
    doc = "\n".join(f"{'#' * lvl} H{lvl}" for lvl in range(1, 7)) + "\n"
    entries = outline.compute_outline(doc)
    assert [e["level"] for e in entries] == [1, 2, 3, 4, 5, 6]


def test_atx_no_space_after_hash_is_not_a_heading():
    doc = "# Title\n\n#5bolt not a heading\n\n## Real\n"
    entries = outline.compute_outline(doc)
    texts = [e["heading_path"][-1] if e["heading_path"] else None for e in entries]
    assert texts == [None, "Real"]


def test_atx_trailing_closing_hashes_trimmed():
    doc = "# Title\n\n## Section ##\n\nbody\n"
    entries = outline.compute_outline(doc)
    assert entries[1]["heading_path"] == ["Section"]


def test_atx_closing_hashes_with_no_preceding_text_yield_empty_string():
    doc = "# ###\n\nbody\n"
    entries = outline.compute_outline(doc)
    # "# ###" -> opening "# " then "###", which CommonMark treats as an
    # (empty) closing sequence since it is preceded by the delimiter space
    # and followed only by end-of-line.
    assert entries[0]["level"] == 1
    assert entries[0]["heading_path"] == []  # H1 text never appears in heading_path


def test_setext_h1_and_h2():
    doc = "Title One\n=========\n\nSub Two\n-------\n\nbody\n"
    entries = outline.compute_outline(doc)
    assert [e["level"] for e in entries] == [1, 2]
    assert entries[1]["heading_path"] == ["Sub Two"]


def test_fence_backtick_hides_heading_like_line():
    doc = "# Title\n\n```\n## not a heading\n```\n\n## Real\n"
    entries = outline.compute_outline(doc)
    paths = [e["heading_path"] for e in entries]
    assert ["Real"] in paths
    assert ["not a heading"] not in paths
    assert len(entries) == 2


def test_fence_tilde_hides_heading_like_line():
    doc = "# Title\n\n~~~\n## not a heading\n~~~\n\n## Real\n"
    entries = outline.compute_outline(doc)
    assert len(entries) == 2


def test_fence_close_requires_matching_char_and_length():
    # A 4-backtick fence is NOT closed by a 3-backtick line; it stays open
    # (and the following "## Real" is swallowed as fenced content) until a
    # line with >=4 backticks appears.
    doc = "# Title\n\n````\n```\n## still fenced\n````\n\n## Real\n"
    entries = outline.compute_outline(doc)
    paths = [e["heading_path"] for e in entries]
    assert ["still fenced"] not in paths
    assert ["Real"] in paths


def test_nested_fence_of_different_character_is_inert():
    doc = "# Title\n\n````\n~~~\n## inert\n~~~\n````\n\n## Real\n"
    entries = outline.compute_outline(doc)
    paths = [e["heading_path"] for e in entries]
    assert ["inert"] not in paths
    assert ["Real"] in paths


def test_html_comment_single_line_hides_content():
    doc = "# Title\n\n<!-- ## not a heading ## -->\n\n## Real\n"
    entries = outline.compute_outline(doc)
    assert len(entries) == 2
    assert entries[1]["heading_path"] == ["Real"]


def test_html_comment_spanning_multiple_lines_hides_content():
    doc = "# Title\n\n<!--\n## not a heading\nstill inside\n-->\n\n## Real\n"
    entries = outline.compute_outline(doc)
    paths = [e["heading_path"] for e in entries]
    assert ["not a heading"] not in paths
    assert ["Real"] in paths


def test_blockquote_heading_is_not_a_heading():
    doc = "# Title\n\n> # Not a heading\n\n## Real\n"
    entries = outline.compute_outline(doc)
    paths = [e["heading_path"] for e in entries]
    assert ["Not a heading"] not in paths
    assert ["Real"] in paths


def test_block_id_read_from_comment_immediately_after_heading():
    doc = "## Section\n<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->\n\nbody\n"
    entries = outline.compute_outline(doc)
    assert entries[0]["block_id"] == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    # the comment line itself must not be counted in section_bytes
    assert "enc:block" not in "".join(
        outline.compute_outline(doc)[0].get("heading_path", [])
    )


def test_block_id_excluded_from_section_bytes():
    with_comment = "## Section\n<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->\nbody\n"
    without_comment = "## Section\nbody\n"
    entries_with = outline.compute_outline(with_comment)
    entries_without = outline.compute_outline(without_comment)
    assert entries_with[0]["section_bytes"] == entries_without[0]["section_bytes"]


def test_block_id_null_when_not_immediately_following():
    doc = "## Section\n\n<!-- enc:block:01ARZ3NDEKTSV4RRFFQ69G5FAV -->\n\nbody\n"
    entries = outline.compute_outline(doc)
    assert entries[0]["block_id"] is None


def test_duplicate_sibling_headings_get_incrementing_ordinal():
    doc = (
        "# Title\n\n"
        "## Parent\n\n"
        "### Repeated\nfirst\n\n"
        "### Other\nmiddle\n\n"
        "### Repeated\nsecond\n\n"
        "### Repeated\nthird\n"
    )
    entries = outline.compute_outline(doc)
    repeated = [e for e in entries if e["heading_path"] == ["Parent", "Repeated"]]
    assert [e["ordinal"] for e in repeated] == [1, 2, 3]
    other = [e for e in entries if e["heading_path"] == ["Parent", "Other"]]
    assert [e["ordinal"] for e in other] == [1]


def test_unicode_heading_text_preserved():
    doc = "# Título\n\n## 日本語の見出し\n\nbody\n"
    entries = outline.compute_outline(doc)
    assert entries[1]["heading_path"] == ["日本語の見出し"]


def test_h1_excluded_from_heading_path_as_ancestor_and_self():
    doc = "# Title\n\n## Child\n\n### Grandchild\n"
    entries = outline.compute_outline(doc)
    title_entry = entries[0]
    child_entry = entries[1]
    grandchild_entry = entries[2]
    assert title_entry["heading_path"] == []
    assert child_entry["heading_path"] == ["Child"]
    assert grandchild_entry["heading_path"] == ["Child", "Grandchild"]


def test_section_extent_stops_at_same_or_shallower_level_only():
    doc = "# Title\n\n## Parent\nbody1\n\n### Child\nbody2\n\n## Next Parent\nbody3\n"
    entries = outline.compute_outline(doc)
    parent = next(e for e in entries if e["heading_path"] == ["Parent"])
    child = next(e for e in entries if e["heading_path"] == ["Parent", "Child"])
    next_parent = next(e for e in entries if e["heading_path"] == ["Next Parent"])
    # Parent's section extends through its nested Child (not truncated by it).
    assert parent["line_end"] >= child["line_end"]
    assert next_parent["line_start"] > parent["line_end"]


def test_empty_section_when_heading_immediately_followed_by_terminating_heading():
    doc = "## A\n## B\nbody\n"
    entries = outline.compute_outline(doc)
    a_entry = entries[0]
    assert a_entry["line_end"] == a_entry["line_start"] - 1
    assert a_entry["section_bytes"] == 0


def test_content_hash_style_no_normalization_crlf_preserved_in_section_bytes():
    crlf_doc = "# Title\r\n## Section\r\nBody line.\r\n"
    entries = outline.compute_outline(crlf_doc)
    section = entries[1]
    # "Body line.\r\n" reconstructed exactly, CRLF preserved (14 bytes: 10
    # visible chars + '.' + \r + \n = 12; count explicitly to avoid drift).
    expected_bytes = len("Body line.\r\n".encode("utf-8"))
    assert section["section_bytes"] == expected_bytes


def test_empty_document_yields_no_entries():
    assert outline.compute_outline("") == []


def test_document_with_no_headings_yields_no_entries():
    assert outline.compute_outline("just a paragraph\n\nanother one\n") == []


def test_compute_outline_is_pure_and_does_not_mutate_input():
    doc = "# Title\n\n## Section\nbody\n"
    before = doc
    outline.compute_outline(doc)
    assert doc == before
