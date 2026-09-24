# ----------------------------------------------------------------------------
# VENDORED FILE -- DO NOT HAND-EDIT (ENC-TSK-P78, T-B5, FR-B4-12).
# Source:  backend/lambda/document_api/outline.py
# Ref:     origin/v4/main
# Commit:  ebcb349b6bf4e1a2b766920d9bc9c18672b50608
# SHA-256 of the unmodified upstream source bytes: 57ad5069eaeadbb7ff2cc4b63cc91e75cac2d3f8bfa1312f0d7277290e6d75af
#
# Re-vendor with: python3 tools/elr/tools/vendor_document_api.py --ref <ref>
# This file is byte-identical to the upstream source EXCEPT for one
# documented import fixup (see vendor_document_api.py's module
# docstring) needed because this copy lives in the elr_lib.vendor
# package rather than as a top-level module.
# ----------------------------------------------------------------------------
"""outline.py — Pure-function Markdown outline parser (ENC-TSK-P69 / FR-B1-1..8).

No AWS SDK imports. This module must remain importable in isolation (by unit
tests, and later by ELR via a `.build_extras` reference) with zero side
effects and zero network/filesystem access. It exposes a single public
entry point, `compute_outline(content: str) -> List[Dict[str, Any]]`.

Recognizes:
  - ATX headings, levels 1-6 (`# ... ######`), with an optional closing
    sequence of `#` characters trimmed along with surrounding whitespace.
  - Setext headings: a non-blank text line followed by an underline of
    `=` characters (level 1) or `-` characters (level 2).
  - Fenced code blocks opened by a run of >=3 backticks or >=3 tildes
    (leading indent 0-3 spaces), closed only by a line with the SAME
    fence character and a run length >= the opening run length (per
    CommonMark). Heading-like lines inside a fence — including inside a
    what looks like a nested fence of
    a different character, which is inert literal content until the
    *matching* close is seen — are ignored.
  - HTML comments (`<!-- ... -->`), including ones spanning multiple
    physical lines. Heading-like lines inside a comment are ignored.
  - Blockquotes: a line beginning with 0-3 spaces then `>` is never a
    heading, even if its content looks like one (`> # Not a heading`).

Block association:
  `block_id` is read from an HTML comment of the exact form
  `<!-- enc:block:ULID -->` (ULID = 26-char Crockford base32, case
  insensitive) on the line immediately following a heading's own line(s).
  That comment line is excluded from `section_bytes`. When absent,
  `block_id` is `None`.

Section extent:
  A heading's section runs from the line after the heading (and after its
  block-id comment, if present) through the line before the next heading
  whose level is <= this heading's level, or through EOF if there is no
  such heading. Because only same-or-shallower headings terminate a
  section, a parent heading's section includes the full text of its
  nested subsections. An empty section (heading immediately followed by
  another terminating heading, or by EOF) reports `section_bytes = 0` and
  `line_end = line_start - 1`.

heading_path / ordinal:
  `heading_path` is the list of heading texts from the top of the
  document down to and including this heading, EXCLUDING any level-1
  ("H1 title line") entries — neither as an ancestor nor as itself. This
  keeps the path free of the document's own title (already available as
  `document.title` on the digest projection) regardless of how many H1s a
  document happens to contain. The underlying parent/child nesting used
  to compute `heading_path` and `ordinal` is based on the *actual* heading
  levels (H1 is still a real node in the tree); only its text is filtered
  out of the rendered path.

  `ordinal` is the 1-based position of this heading among siblings with
  the *same heading text* under the same parent (not the general sibling
  index). Two headings with different text under the same parent both
  get ordinal 1; a third occurrence of a repeated text gets ordinal 3.
  This exists to disambiguate duplicate sibling headings, whose
  `heading_path` values are otherwise identical.

Byte counting:
  `content` is split on bare "\\n" (not `str.splitlines()`), so a
  trailing "\\r" from CRLF line endings is preserved as part of each
  line's own text and `section_bytes` reconstructs the *exact* original
  UTF-8 byte span for that line range (no normalization), matching the
  no-normalization contract used for `content_hash` elsewhere in
  document_api.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_ATX_RE = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*))?[ \t]*$")
_ATX_CLOSING_HASHES_RE = re.compile(r"(?:^|[ \t])#+[ \t]*$")
_FENCE_OPEN_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_SETEXT_H1_RE = re.compile(r"^ {0,3}=+[ \t]*$")
_SETEXT_H2_RE = re.compile(r"^ {0,3}-+[ \t]*$")
_BLOCKQUOTE_RE = re.compile(r"^ {0,3}>")
_SINGLE_LINE_COMMENT_RE = re.compile(r"^[ \t]*<!--.*-->[ \t]*$")
_BLOCK_ID_COMMENT_RE = re.compile(
    r"^[ \t]*<!--[ \t]*enc:block:([0-9A-HJKMNP-TV-Z]{26})[ \t]*-->[ \t]*$",
    re.IGNORECASE,
)


def _strip_atx(line: str) -> Optional[Tuple[int, str]]:
    """Return (level, trimmed text) for an ATX heading line, else None."""
    m = _ATX_RE.match(line)
    if not m:
        return None
    level = len(m.group(1))
    raw_text = (m.group(2) or "").strip()
    text = _ATX_CLOSING_HASHES_RE.sub("", raw_text).strip()
    return level, text


def _fence_close_re(fence_char: str, fence_len: int) -> "re.Pattern[str]":
    return re.compile(r"^ {0,3}%s{%d,}[ \t]*$" % (re.escape(fence_char), fence_len))


def _classify_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """Phase 1: scan CRLF-normalized lines, collecting ordered heading candidates.

    Each candidate: {level, text, start_ln, header_end_ln} using 1-based
    line numbers. `start_ln` is where the heading construct begins (its
    own text line for both ATX and setext); `header_end_ln` is the last
    line consumed by the heading construct (== start_ln for ATX, ==
    start_ln + 1 for setext, since that includes the underline).
    """
    n = len(lines)
    candidates: List[Dict[str, Any]] = []

    fence_char: Optional[str] = None
    fence_len = 0
    in_comment = False

    i = 0
    while i < n:
        line = lines[i]

        if fence_char is not None:
            if _fence_close_re(fence_char, fence_len).match(line):
                fence_char = None
                fence_len = 0
            i += 1
            continue

        if not in_comment:
            fm = _FENCE_OPEN_RE.match(line)
            if fm:
                seq = fm.group(1)
                fence_char = seq[0]
                fence_len = len(seq)
                i += 1
                continue

        if in_comment:
            if "-->" in line:
                in_comment = False
            i += 1
            continue

        if "<!--" in line:
            after = line[line.index("<!--"):]
            if "-->" not in after:
                in_comment = True
                i += 1
                continue
            if _SINGLE_LINE_COMMENT_RE.match(line):
                # A line that is entirely one (or more) HTML comment(s) — not
                # heading-like content, and not itself a block-id association
                # (that is resolved separately, relative to a heading).
                i += 1
                continue
            # Mixed inline comment + other content: fall through and evaluate
            # the raw line normally below (rare in practice).

        if _BLOCKQUOTE_RE.match(line):
            i += 1
            continue

        atx = _strip_atx(line)
        if atx is not None:
            level, text = atx
            candidates.append({
                "level": level,
                "text": text,
                "start_ln": i + 1,
                "header_end_ln": i + 1,
            })
            i += 1
            continue

        if line.strip() != "" and i + 1 < n:
            nxt = lines[i + 1]
            if _SETEXT_H1_RE.match(nxt):
                candidates.append({
                    "level": 1,
                    "text": line.strip(),
                    "start_ln": i + 1,
                    "header_end_ln": i + 2,
                })
                i += 2
                continue
            if _SETEXT_H2_RE.match(nxt):
                candidates.append({
                    "level": 2,
                    "text": line.strip(),
                    "start_ln": i + 1,
                    "header_end_ln": i + 2,
                })
                i += 2
                continue

        i += 1

    return candidates


def compute_outline_with_spans(content: str) -> List[Dict[str, Any]]:
    """Same entries as compute_outline(), PLUS two ENC-TSK-P71 additive
    fields per entry: `header_start_ln` / `header_end_ln` — the physical
    1-based line span of the heading construct itself (1 line for ATX, 2 for
    setext: text line + underline). This is a SEPARATE function (rather than
    adding the fields to compute_outline()'s own return) so the P69
    byte-for-byte conformance corpus (tests/fixtures/outline,
    test_outline_fixtures.py) stays byte-identical — that corpus is also the
    contract ELR vendors compute_outline() against. sections.py (ENC-TSK-P71)
    uses this variant to locate heading lines for block-id stamping and
    include_heading operations without a second, potentially-divergent scan.
    """
    if content is None:
        content = ""
    elif not isinstance(content, str):
        content = str(content)

    raw_lines = content.split("\n")
    # CRLF-normalized view used ONLY for pattern matching (fence/heading/
    # comment/blockquote detection); raw_lines (with any trailing "\r"
    # left attached) is used for exact byte reconstruction below.
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in raw_lines]
    n = len(raw_lines)

    candidates = _classify_lines(lines)

    # Phase 2: block_id + section extent (content_start/content_end) per
    # candidate, computed against the ordered candidate list.
    resolved: List[Dict[str, Any]] = []
    for idx, cand in enumerate(candidates):
        header_end_ln = cand["header_end_ln"]
        block_id = None
        if header_end_ln < n:
            next_line = lines[header_end_ln]  # 1-based header_end_ln == 0-based index of the NEXT line
            bm = _BLOCK_ID_COMMENT_RE.match(next_line)
            if bm:
                block_id = bm.group(1)
                content_start = header_end_ln + 2
            else:
                content_start = header_end_ln + 1
        else:
            content_start = header_end_ln + 1

        content_end = n
        for later in candidates[idx + 1:]:
            if later["level"] <= cand["level"]:
                content_end = later["start_ln"] - 1
                break

        if content_start > content_end:
            line_start = content_start
            line_end = content_start - 1
            section_bytes = 0
        else:
            line_start = content_start
            line_end = content_end
            section_text = "\n".join(raw_lines[line_start - 1:line_end])
            section_bytes = len(section_text.encode("utf-8"))

        resolved.append({
            "level": cand["level"],
            "text": cand["text"],
            "block_id": block_id,
            "line_start": line_start,
            "line_end": line_end,
            "section_bytes": section_bytes,
            # ENC-TSK-P71: kept internally (Phase 3 threads it through) but
            # NOT part of compute_outline()'s public per-entry shape — see
            # compute_outline_with_spans() below. Public compute_outline()
            # strips this key so the P69 byte-for-byte conformance corpus
            # (tests/fixtures/outline) is untouched by this addition.
            "header_start_ln": cand["start_ln"],
            "header_end_ln": header_end_ln,
        })

    # Phase 3: nesting (heading_path, ordinal) via a level-based stack. The
    # tree uses REAL levels (including H1) so parent/child + duplicate-
    # sibling bookkeeping is correct; H1 text is filtered out of the
    # rendered heading_path only (see module docstring).
    root = {"level": 0, "text": None, "seen": {}}
    stack: List[Dict[str, Any]] = [root]
    entries: List[Dict[str, Any]] = []

    for item in resolved:
        level = item["level"]
        text = item["text"]
        while len(stack) > 1 and stack[-1]["level"] >= level:
            stack.pop()
        parent = stack[-1]
        seen = parent["seen"]
        ordinal = seen.get(text, 0) + 1
        seen[text] = ordinal

        ancestor_texts = [f["text"] for f in stack[1:] if f["level"] != 1]
        heading_path = ancestor_texts + ([] if level == 1 else [text])

        entries.append({
            "heading_path": heading_path,
            "level": level,
            "ordinal": ordinal,
            "block_id": item["block_id"],
            "line_start": item["line_start"],
            "line_end": item["line_end"],
            "section_bytes": item["section_bytes"],
            "header_start_ln": item["header_start_ln"],
            "header_end_ln": item["header_end_ln"],
        })

        stack.append({"level": level, "text": text, "seen": {}})

    return entries


def compute_outline(content: str) -> List[Dict[str, Any]]:
    """Compute the ordered outline for a Markdown document body.

    Pure function: no I/O, no mutation of the input. See module docstring
    for the full field contract. Thin wrapper over
    compute_outline_with_spans() (ENC-TSK-P71) that strips the two additive
    header_start_ln/header_end_ln fields, so this function's return shape —
    and the tests/fixtures/outline byte-for-byte conformance corpus it must
    match — is completely unchanged by that addition.
    """
    detailed = compute_outline_with_spans(content)
    return [
        {k: v for k, v in entry.items() if k not in ("header_start_ln", "header_end_ln")}
        for entry in detailed
    ]
