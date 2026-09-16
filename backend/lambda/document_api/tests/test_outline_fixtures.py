"""test_outline_fixtures.py — Fixture-corpus regression test for outline.py (ENC-TSK-P69 AC-5).

Walks backend/lambda/document_api/tests/fixtures/outline/, which pairs each
<name>.md with a <name>.expected.json capturing outline.compute_outline()'s
output for that document. The corpus is self-describing: fixture names
name the specific behavior they exercise (fences of both characters,
nested fences, setext both styles, HTML comments spanning lines,
duplicate sibling headings, Unicode heading text, trailing hashes,
headings inside blockquotes, block-id association, CRLF byte-exactness,
etc.) so it can be read and reused without this file, including by ELR
later (see outline.py's module docstring).

Byte-for-byte equality: expected.json files were written using the exact
canonical serialization this test reproduces from the live parser output
(json.dumps(entries, indent=2, ensure_ascii=False) + "\\n"), so the
assertion below is a literal string comparison, not just a value-equality
check.

Run: python3 -m pytest test_outline_fixtures.py -v
"""
from __future__ import annotations

import json
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_DOCUMENT_API_DIR = os.path.dirname(_TESTS_DIR)
sys.path.insert(0, _DOCUMENT_API_DIR)

import outline  # noqa: E402

FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures", "outline")


def _discover_fixture_names():
    names = sorted(
        fn[: -len(".md")]
        for fn in os.listdir(FIXTURES_DIR)
        if fn.endswith(".md")
    )
    return names


FIXTURE_NAMES = _discover_fixture_names()


def test_corpus_has_at_least_forty_fixtures():
    assert len(FIXTURE_NAMES) >= 40, (
        f"AC-5 requires a corpus of at least forty fixtures; found {len(FIXTURE_NAMES)}."
    )


def test_every_fixture_has_a_matching_expected_json():
    for name in FIXTURE_NAMES:
        expected_path = os.path.join(FIXTURES_DIR, f"{name}.expected.json")
        assert os.path.isfile(expected_path), f"missing expected.json for fixture '{name}'"


def _load_fixture(name: str):
    md_path = os.path.join(FIXTURES_DIR, f"{name}.md")
    expected_path = os.path.join(FIXTURES_DIR, f"{name}.expected.json")
    with open(md_path, "r", encoding="utf-8", newline="") as f:
        source = f.read()
    with open(expected_path, "r", encoding="utf-8") as f:
        expected_raw = f.read()
    return source, expected_raw


def test_all_fixtures_byte_for_byte():
    failures = []
    for name in FIXTURE_NAMES:
        source, expected_raw = _load_fixture(name)
        entries = outline.compute_outline(source)
        actual_raw = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"
        if actual_raw != expected_raw:
            failures.append(name)
    assert not failures, f"outline mismatch for fixtures: {failures}"


def test_all_fixtures_also_match_as_parsed_json():
    # Belt-and-suspenders: the byte-for-byte check above is the primary
    # AC-5 assertion, but also confirm value-level equality independent of
    # serialization formatting, in case a fixture's expected.json is ever
    # hand-edited with different (but semantically equal) whitespace.
    for name in FIXTURE_NAMES:
        source, expected_raw = _load_fixture(name)
        entries = outline.compute_outline(source)
        expected_entries = json.loads(expected_raw)
        assert entries == expected_entries, f"value mismatch for fixture '{name}'"
