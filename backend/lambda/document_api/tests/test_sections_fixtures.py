"""test_sections_fixtures.py — Conformance-corpus regression test for
sections.py (ENC-TSK-P71 AC-9), sibling to test_outline_fixtures.py.

Walks backend/lambda/document_api/tests/fixtures/sections/, which pairs
each <name>.md (the BEFORE document) with <name>.request.json (the
patch_section request: anchor/op/body/include_heading/rebase_headings) and
either:
  - <name>.expected_after.md — the AFTER document, with any freshly-stamped
    block-id ULID masked to a fixed placeholder token (ULID generation is
    intentionally nondeterministic — see sections.generate_ulid — so a
    fixture that exercises stamping records everything EXCEPT the literal
    ULID value byte-for-byte); or
  - <name>.expected.json's "error" object — the anchor-resolution failure
    (status/code) for a fixture that exercises ANCHOR_NOT_FOUND / AMBIGUOUS.

Covers ENC-TSK-P71 AC-9's required combination set: replace/append/prepend/
delete, include_heading=true, rebase_headings on/off, ambiguous, not-found.

Run: python3 -m pytest test_sections_fixtures.py -v
"""
from __future__ import annotations

import json
import os
import re
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_DOCUMENT_API_DIR = os.path.dirname(_TESTS_DIR)
sys.path.insert(0, _DOCUMENT_API_DIR)

import outline  # noqa: E402
import sections  # noqa: E402

FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures", "sections")
_BLOCK_ID_RE = re.compile(r"(<!-- enc:block:)[0-9A-Za-z]{26}( -->)")
_MASK = r"\1MASKED_ULID_MASKED_ULID00\2"


def _discover_fixture_names():
    return sorted(
        fn[: -len(".md")]
        for fn in os.listdir(FIXTURES_DIR)
        if fn.endswith(".md") and not fn.endswith(".expected_after.md")
    )


FIXTURE_NAMES = _discover_fixture_names()


def _mask(text: str) -> str:
    return _BLOCK_ID_RE.sub(_MASK, text)


def test_corpus_covers_required_combinations():
    required_substrings = [
        "replace", "append", "prepend", "delete",
        "include_heading", "rebase",  # both rebase on/off variants present
        "ambiguous", "not_found",
    ]
    joined = " ".join(FIXTURE_NAMES)
    missing = [s for s in required_substrings if s not in joined]
    assert not missing, f"AC-9 required combinations missing from corpus: {missing}"


def _run_fixture(name):
    with open(os.path.join(FIXTURES_DIR, f"{name}.md"), encoding="utf-8") as f:
        before_doc = f.read()
    with open(os.path.join(FIXTURES_DIR, f"{name}.request.json"), encoding="utf-8") as f:
        request_obj = json.load(f)

    entries = outline.compute_outline_with_spans(before_doc)
    try:
        entry = sections.resolve_anchor(entries, request_obj["anchor"])
    except sections.AnchorError as exc:
        return {"error": {"status": exc.status, "code": exc.code}}

    result = sections.apply_patch(
        before_doc, entry, request_obj["op"], request_obj.get("body"),
        include_heading=request_obj.get("include_heading", False),
        rebase_headings=request_obj.get("rebase_headings", True),
    )
    return {"content": _mask(result["content"])}


def test_all_fixtures_replay_correctly():
    failures = []
    for name in FIXTURE_NAMES:
        outcome = _run_fixture(name)
        expected_json_path = os.path.join(FIXTURES_DIR, f"{name}.expected.json")
        with open(expected_json_path, encoding="utf-8") as f:
            expected_record = json.load(f)

        if "error" in expected_record:
            if "error" not in outcome:
                failures.append(f"{name}: expected an error but got content")
                continue
            if outcome["error"] != {
                "status": expected_record["error"]["status"],
                "code": expected_record["error"]["code"],
            }:
                failures.append(f"{name}: error mismatch {outcome['error']} != {expected_record['error']}")
            continue

        if "error" in outcome:
            failures.append(f"{name}: got unexpected error {outcome['error']}")
            continue

        expected_after_path = os.path.join(FIXTURES_DIR, f"{name}.expected_after.md")
        with open(expected_after_path, encoding="utf-8") as f:
            expected_after = f.read()
        if outcome["content"] != expected_after:
            failures.append(name)

    assert not failures, f"sections fixture mismatch for: {failures}"


def test_no_duplicate_block_id_in_any_successful_fixture_output():
    for name in FIXTURE_NAMES:
        outcome = _run_fixture(name)
        if "content" not in outcome:
            continue
        ids = re.findall(r"<!-- enc:block:([0-9A-Za-z]{26}|MASKED_ULID_MASKED_ULID00) -->", outcome["content"])
        assert len(ids) == len(set(ids)), f"{name}: duplicate block_id in output"
