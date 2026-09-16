"""Conformance-corpus regression test for elr_lib.sections/elr_lib/vendor
(ENC-TSK-P78, T-B5, FR-B4-12, AC-2). Sibling to
backend/lambda/document_api/tests/test_outline_fixtures.py and
test_sections_fixtures.py -- this file replays the SAME fixture corpus
(copied verbatim from origin/v4/main at commit
tools/elr/elr_lib/vendor/PINS.json's "commit" into
tests/fixtures/{outline,sections}/) through elr_lib.sections instead of
the server's own outline.py/sections.py, and asserts byte-identical
output. If this test is green, elr_doc_patch.py's local dry-run preview
and post-write re-apply-and-verify step are provably computing exactly
what the server would.

Also asserts elr_lib/vendor/PINS.json matches the ON-DISK vendored
files' sha256 -- catches a hand-edit to a vendored file without needing
to re-run tools/elr/tools/vendor_document_api.py or reach the network.

Run: python3 -m pytest tests/test_sections_vendor.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import re

import elr_lib.sections as elr_sections

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_ELR_ROOT = os.path.dirname(_TESTS_DIR)

OUTLINE_FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures", "outline")
SECTIONS_FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures", "sections")
VENDOR_DIR = os.path.join(_ELR_ROOT, "elr_lib", "vendor")
PINS_PATH = os.path.join(VENDOR_DIR, "PINS.json")

_BLOCK_ID_RE = re.compile(r"(<!-- enc:block:)[0-9A-Za-z]{26}( -->)")
_MASK = r"\1MASKED_ULID_MASKED_ULID00\2"


def _mask(text: str) -> str:
    return _BLOCK_ID_RE.sub(_MASK, text)


# ---------------------------------------------------------------------------
# Vendor pin integrity
# ---------------------------------------------------------------------------


def test_pins_file_exists_and_has_both_modules():
    with open(PINS_PATH, encoding="utf-8") as f:
        pins = json.load(f)
    assert set(pins["files"]) == {"document_api_outline.py", "document_api_sections.py"}
    assert pins.get("commit")
    assert pins.get("ref")


def test_vendored_files_sha256_match_pins():
    with open(PINS_PATH, encoding="utf-8") as f:
        pins = json.load(f)
    mismatches = []
    for rel_path, expected_sha256 in pins["files"].items():
        full_path = os.path.join(VENDOR_DIR, rel_path)
        with open(full_path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != expected_sha256:
            mismatches.append((rel_path, expected_sha256, actual))
    assert not mismatches, f"vendored file(s) drifted from PINS.json: {mismatches}"


def test_vendored_sections_imports_outline_relatively():
    # The ONE documented, deliberate deviation from byte-identical
    # vendoring (see tools/elr/tools/vendor_document_api.py).
    path = os.path.join(VENDOR_DIR, "document_api_sections.py")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    assert "from . import document_api_outline as outline_mod" in text
    assert "\nimport outline as outline_mod" not in text


# ---------------------------------------------------------------------------
# Outline conformance corpus (byte-identical to
# backend/lambda/document_api/tests/fixtures/outline's own expected.json,
# computed by document_api's own outline.compute_outline() -- same
# serialization: json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
# ---------------------------------------------------------------------------


def _discover_outline_names():
    return sorted(fn[: -len(".md")] for fn in os.listdir(OUTLINE_FIXTURES_DIR) if fn.endswith(".md"))


OUTLINE_NAMES = _discover_outline_names()


def test_outline_corpus_has_at_least_forty_fixtures():
    assert len(OUTLINE_NAMES) >= 40, f"expected >=40 outline fixtures; found {len(OUTLINE_NAMES)}"


def test_outline_all_fixtures_byte_for_byte():
    failures = []
    for name in OUTLINE_NAMES:
        md_path = os.path.join(OUTLINE_FIXTURES_DIR, f"{name}.md")
        expected_path = os.path.join(OUTLINE_FIXTURES_DIR, f"{name}.expected.json")
        with open(md_path, "r", encoding="utf-8", newline="") as f:
            source = f.read()
        with open(expected_path, "r", encoding="utf-8") as f:
            expected_raw = f.read()
        entries = elr_sections.compute_outline(source)
        actual_raw = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"
        if actual_raw != expected_raw:
            failures.append(name)
    assert not failures, f"elr_lib.sections outline mismatch for fixtures: {failures}"


# ---------------------------------------------------------------------------
# Sections (anchor resolution + op application) conformance corpus
# ---------------------------------------------------------------------------


def _discover_sections_names():
    return sorted(
        fn[: -len(".md")]
        for fn in os.listdir(SECTIONS_FIXTURES_DIR)
        if fn.endswith(".md") and not fn.endswith(".expected_after.md")
    )


SECTIONS_NAMES = _discover_sections_names()


def test_sections_corpus_covers_required_combinations():
    required_substrings = [
        "replace", "append", "prepend", "delete",
        "include_heading", "rebase",
        "ambiguous", "not_found",
    ]
    joined = " ".join(SECTIONS_NAMES)
    missing = [s for s in required_substrings if s not in joined]
    assert not missing, f"required combinations missing from corpus: {missing}"


def _run_sections_fixture(name: str):
    with open(os.path.join(SECTIONS_FIXTURES_DIR, f"{name}.md"), encoding="utf-8") as f:
        before_doc = f.read()
    with open(os.path.join(SECTIONS_FIXTURES_DIR, f"{name}.request.json"), encoding="utf-8") as f:
        request_obj = json.load(f)

    entries = elr_sections.compute_outline_with_spans(before_doc)
    try:
        entry = elr_sections.resolve_anchor(entries, request_obj["anchor"])
    except elr_sections.AnchorError as exc:
        return {"error": {"status": exc.status, "code": exc.code}}

    result = elr_sections.apply_section_op(
        before_doc, entry, request_obj["op"], request_obj.get("body"),
        include_heading=request_obj.get("include_heading", False),
        rebase_headings=request_obj.get("rebase_headings", True),
    )
    return {"content": _mask(result["content"])}


def test_sections_all_fixtures_replay_correctly():
    failures = []
    for name in SECTIONS_NAMES:
        outcome = _run_sections_fixture(name)
        with open(os.path.join(SECTIONS_FIXTURES_DIR, f"{name}.expected.json"), encoding="utf-8") as f:
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

        with open(os.path.join(SECTIONS_FIXTURES_DIR, f"{name}.expected_after.md"), encoding="utf-8") as f:
            expected_after = f.read()
        if outcome["content"] != expected_after:
            failures.append(name)

    assert not failures, f"elr_lib.sections fixture mismatch for: {failures}"


def test_sections_no_duplicate_block_id_in_any_successful_fixture_output():
    for name in SECTIONS_NAMES:
        outcome = _run_sections_fixture(name)
        if "content" not in outcome:
            continue
        ids = re.findall(r"<!-- enc:block:([0-9A-Za-z]{26}|MASKED_ULID_MASKED_ULID00) -->", outcome["content"])
        assert len(ids) == len(set(ids)), f"{name}: duplicate block_id in output"


# ---------------------------------------------------------------------------
# ulid_factory injection (elr_lib.sections' own addition over the
# vendored engine -- not part of the upstream corpus)
# ---------------------------------------------------------------------------


def test_apply_section_op_ulid_factory_injection_is_deterministic_and_restores():
    content = "# Title\n\n## Section A\n\nbody\n"
    entries = elr_sections.compute_outline_with_spans(content)
    entry = elr_sections.resolve_anchor(entries, {"heading_path": ["Section A"]})

    fixed_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    result = elr_sections.apply_section_op(
        content, entry, "replace", "new body", ulid_factory=lambda *a, **k: fixed_id
    )
    assert result["block_id"] == fixed_id
    assert f"<!-- enc:block:{fixed_id} -->" in result["content"]

    # The vendored module's generate_ulid must be restored afterward --
    # calling apply_section_op again WITHOUT a factory must not reuse the
    # test's injected id.
    result2 = elr_sections.apply_section_op(content, entry, "replace", "new body 2")
    assert result2["block_id"] != fixed_id
    assert elr_sections._sections.generate_ulid is elr_sections._sections.generate_ulid  # sanity: attribute exists
