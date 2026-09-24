# ----------------------------------------------------------------------------
# VENDORED FILE -- DO NOT HAND-EDIT (ENC-TSK-P78, T-B5, FR-B4-12).
# Source:  backend/lambda/document_api/sections.py
# Ref:     origin/v4/main
# Commit:  ebcb349b6bf4e1a2b766920d9bc9c18672b50608
# SHA-256 of the unmodified upstream source bytes: b0d682b78ccf6d18814c2d6289e88f62d508e728b00b742a2948cedf1195b94e
#
# Re-vendor with: python3 tools/elr/tools/vendor_document_api.py --ref <ref>
# This file is byte-identical to the upstream source EXCEPT for one
# documented import fixup (see vendor_document_api.py's module
# docstring) needed because this copy lives in the elr_lib.vendor
# package rather than as a top-level module.
# ----------------------------------------------------------------------------
"""sections.py — Pure section-patch engine (ENC-TSK-P71 / FR-B1-13..25).

No AWS SDK imports (stdlib + `outline` only), so this module can be vendored
by ELR via a `.build_extras` reference exactly the way outline.py is
(ENC-TSK-P69). It builds on `outline.compute_outline` for anchor resolution
and section-extent bookkeeping, and adds:

  - Anchor resolution (block_id / heading_path / ordinal), AC-2.
  - Section-op application (replace/append/prepend/delete), AC-3.
  - ATX heading rebasing for inserted body content, AC-4.
  - Block-id (ULID) stamping on an anchor's first patch, AC-5.
  - A tiny stdlib ULID generator (time + os.urandom, Crockford base32).
  - A unified-diff helper for dry_run previews, AC-7.

All functions here are pure: given a full document `content` string and an
outline entry (as returned by `outline.compute_outline`, which ENC-TSK-P71
additively extended with `header_start_ln` / `header_end_ln` so the heading
construct's own physical line span is available — see outline.py), they
return a new full-document string. No I/O, no mutation of inputs, no
knowledge of DynamoDB/S3/HTTP.

Heading/fence/setext detection for rebasing reuses outline module's private
regexes (`_FENCE_OPEN_RE`, `_fence_close_re`, `_strip_atx`, `_SETEXT_H1_RE`,
`_SETEXT_H2_RE`, `_BLOCKQUOTE_RE`) rather than duplicating them, so the two
modules can never disagree about what a heading/fence/setext-underline looks
like.

Scope notes (documented rather than silently guessed at):
  - `include_heading` is fully implemented for delete (removes heading +
    block comment along with the body) and for replace (the supplied `body`
    replaces the heading + comment + body span wholesale, so the caller can
    rename the heading in the same op — no auto block-id stamping happens
    in this case, since the module has no reliable way to tell which line
    of the caller-supplied body is "the heading"; a later patch without
    include_heading will stamp it). For append/prepend, include_heading has
    no additional effect beyond include_heading=false (this is a documented
    scope limitation, not an oversight — the "insert after/before existing
    content" semantics don't compose naturally with "start at the heading
    line" the way replace's wholesale substitution does).
  - rebase_headings is not applied to a replace+include_heading body (it is
    caller-controlled verbatim in that case).
"""

from __future__ import annotations

import difflib
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from . import document_api_outline as outline_mod

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_OPS = ("replace", "append", "prepend", "delete")
MAX_BODY_BYTES = 262_144  # AC-7: per-op `body` size cap


# ---------------------------------------------------------------------------
# ULID (tiny stdlib implementation — time + os.urandom, Crockford base32)
# ---------------------------------------------------------------------------

_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_ulid(_time_ms: Optional[int] = None, _rand_bytes: Optional[bytes] = None) -> str:
    """Generate a 26-character Crockford-base32 ULID.

    48-bit millisecond Unix timestamp (high bits) + 80 bits of os.urandom
    entropy (low bits) = 128 bits, encoded as 26 base32 characters (matches
    outline.py's `_BLOCK_ID_COMMENT_RE`, which accepts any 26-char Crockford
    base32 token case-insensitively — this generator always emits uppercase).
    `_time_ms` / `_rand_bytes` are test-only override hooks.
    """
    ts = _time_ms if _time_ms is not None else int(time.time() * 1000)
    rand = _rand_bytes if _rand_bytes is not None else os.urandom(10)
    value = ((ts & 0xFFFFFFFFFFFF) << 80) | int.from_bytes(rand, "big")
    chars = []
    for i in range(25, -1, -1):
        chars.append(_CROCKFORD_ALPHABET[(value >> (i * 5)) & 0x1F])
    return "".join(chars)


# ---------------------------------------------------------------------------
# Request-shape validation (AC-1)
# ---------------------------------------------------------------------------


def validate_op_and_body(op: str, body: Any) -> Optional[Tuple[str, str]]:
    """Returns None when (op, body) are consistent, else (code, message).

    delete + a supplied body -> OP_BODY_FORBIDDEN.
    replace/append/prepend + no (or empty) body -> OP_BODY_REQUIRED.
    """
    if op == "delete":
        if body is not None and body != "":
            return ("OP_BODY_FORBIDDEN", "`body` must not be supplied for op='delete'.")
        return None
    if body is None or not isinstance(body, str) or body == "":
        return ("OP_BODY_REQUIRED", f"`body` is required for op={op!r}.")
    return None


# ---------------------------------------------------------------------------
# Anchor resolution (AC-2)
# ---------------------------------------------------------------------------


class AnchorError(Exception):
    """Raised by resolve_anchor for the 404/409/400 anchor-resolution cases.

    `status`, `code`, `message` map directly onto the handler's _error(...)
    call; `details` are the extra kwargs (e.g. `outline=`, `candidates=`).
    """

    def __init__(self, status: int, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def _normalize_ws(text: Any) -> str:
    return " ".join(str(text if text is not None else "").split())


def _normalize_path(path: Optional[List[str]]) -> Tuple[str, ...]:
    return tuple(_normalize_ws(p) for p in (path or []))


def _candidate_view(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "heading_path": entry.get("heading_path"),
        "ordinal": entry.get("ordinal"),
        "block_id": entry.get("block_id"),
    }


def resolve_anchor(outline_entries: List[Dict[str, Any]], anchor: Dict[str, Any]) -> Dict[str, Any]:
    """AC-2 anchor resolution. Returns the matched outline entry dict, or
    raises AnchorError(status, code, message, **details)."""
    anchor = anchor or {}
    block_id = anchor.get("block_id")
    heading_path = anchor.get("heading_path")
    ordinal = anchor.get("ordinal")

    if block_id:
        matches = [e for e in outline_entries if e.get("block_id") == block_id]
        if not matches:
            raise AnchorError(
                404, "ANCHOR_NOT_FOUND",
                f"No section found for block_id '{block_id}'.",
                outline=outline_entries,
            )
        if len(matches) > 1:
            raise AnchorError(
                409, "ANCHOR_AMBIGUOUS",
                f"Multiple sections share block_id '{block_id}'.",
                candidates=[_candidate_view(e) for e in matches],
            )
        resolved = matches[0]
        if heading_path is not None:
            if _normalize_path(resolved.get("heading_path")) != _normalize_path(heading_path):
                hp_matches = [
                    e for e in outline_entries
                    if _normalize_path(e.get("heading_path")) == _normalize_path(heading_path)
                    and (ordinal is None or e.get("ordinal") == ordinal)
                ]
                candidates = [_candidate_view(resolved)] + [_candidate_view(e) for e in hp_matches]
                raise AnchorError(
                    409, "ANCHOR_AMBIGUOUS",
                    (
                        "block_id resolved to a different heading than the supplied "
                        "heading_path (both resolutions reported)."
                    ),
                    candidates=candidates,
                    resolution_by_block_id=_candidate_view(resolved),
                    resolution_by_heading_path=[_candidate_view(e) for e in hp_matches],
                )
        return resolved

    if heading_path:
        target = _normalize_path(heading_path)
        matches = [e for e in outline_entries if _normalize_path(e.get("heading_path")) == target]
        if ordinal is not None:
            matches = [e for e in matches if e.get("ordinal") == ordinal]
        if not matches:
            raise AnchorError(
                404, "ANCHOR_NOT_FOUND",
                "No heading matched the supplied heading_path.",
                outline=outline_entries,
            )
        if len(matches) > 1:
            raise AnchorError(
                409, "ANCHOR_AMBIGUOUS",
                "Multiple headings matched heading_path; supply ordinal or block_id to disambiguate.",
                candidates=[_candidate_view(e) for e in matches],
            )
        return matches[0]

    raise AnchorError(400, "ANCHOR_INVALID", "anchor requires block_id or heading_path.")


# ---------------------------------------------------------------------------
# Heading rebasing (AC-4) — reuses outline module's private regex family.
# ---------------------------------------------------------------------------


def _setext_to_atx(lines: List[str]) -> List[str]:
    out: List[str] = []
    fence_char = None
    fence_len = 0
    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        if fence_char is not None:
            out.append(ln)
            if outline_mod._fence_close_re(fence_char, fence_len).match(ln):
                fence_char = None
                fence_len = 0
            i += 1
            continue
        fm = outline_mod._FENCE_OPEN_RE.match(ln)
        if fm:
            seq = fm.group(1)
            fence_char = seq[0]
            fence_len = len(seq)
            out.append(ln)
            i += 1
            continue
        if not outline_mod._BLOCKQUOTE_RE.match(ln) and ln.strip() != "" and i + 1 < n:
            nxt = lines[i + 1]
            if outline_mod._SETEXT_H1_RE.match(nxt):
                out.append("# " + ln.strip())
                i += 2
                continue
            if outline_mod._SETEXT_H2_RE.match(nxt):
                out.append("## " + ln.strip())
                i += 2
                continue
        out.append(ln)
        i += 1
    return out


def rebase_body_headings(body_lines: List[str], target_level: int) -> List[str]:
    """AC-4: shift ATX headings in `body_lines` so the shallowest becomes
    `target_level` (already clamped to <=6 by the caller), preserving
    relative depth and clamping each individual shifted level at 6. Setext
    headings are converted to ATX first. Headings inside fenced code are
    left untouched. A no-op when body_lines contains no headings."""
    lines = _setext_to_atx(list(body_lines))

    levels: List[int] = []
    fence_char = None
    fence_len = 0
    for ln in lines:
        if fence_char is not None:
            if outline_mod._fence_close_re(fence_char, fence_len).match(ln):
                fence_char = None
                fence_len = 0
            continue
        fm = outline_mod._FENCE_OPEN_RE.match(ln)
        if fm:
            seq = fm.group(1)
            fence_char = seq[0]
            fence_len = len(seq)
            continue
        h = outline_mod._strip_atx(ln)
        if h is not None:
            levels.append(h[0])

    if not levels:
        return lines

    shallowest = min(levels)
    shift = target_level - shallowest
    if shift == 0:
        return lines

    out: List[str] = []
    fence_char = None
    fence_len = 0
    for ln in lines:
        if fence_char is not None:
            out.append(ln)
            if outline_mod._fence_close_re(fence_char, fence_len).match(ln):
                fence_char = None
                fence_len = 0
            continue
        fm = outline_mod._FENCE_OPEN_RE.match(ln)
        if fm:
            seq = fm.group(1)
            fence_char = seq[0]
            fence_len = len(seq)
            out.append(ln)
            continue
        h = outline_mod._strip_atx(ln)
        if h is not None:
            level, text = h
            new_level = max(1, min(6, level + shift))
            out.append(("#" * new_level) + (" " + text if text else ""))
        else:
            out.append(ln)
    return out


# ---------------------------------------------------------------------------
# Whitespace / blank-line helpers (AC-3)
# ---------------------------------------------------------------------------


def _rstrip_blank_tail(lines: List[str]) -> List[str]:
    out = list(lines)
    while out and out[-1].strip() == "":
        out.pop()
    return out


def _lstrip_blank_head(lines: List[str]) -> List[str]:
    out = list(lines)
    while out and out[0].strip() == "":
        out.pop(0)
    return out


def _strip_blank_edges(lines: List[str]) -> List[str]:
    return _lstrip_blank_head(_rstrip_blank_tail(lines))


def _join_seam(before: List[str], after: List[str]) -> List[str]:
    """AC-3: join two line-lists with EXACTLY one blank line between them
    when both are non-empty (collapsing any existing blank-line run at the
    seam first); a pure concat when either side is empty (nothing to
    separate the section body from)."""
    if not before or not after:
        return list(before) + list(after)
    b = _rstrip_blank_tail(before)
    a = _lstrip_blank_head(after)
    if not b or not a:
        return b + a
    return b + [""] + a


# ---------------------------------------------------------------------------
# Op application (AC-3, AC-4, AC-5)
# ---------------------------------------------------------------------------


def apply_patch(
    content: str,
    entry: Dict[str, Any],
    op: str,
    body: Optional[str],
    include_heading: bool = False,
    rebase_headings: bool = True,
) -> Dict[str, Any]:
    """Apply a single section op to `content` in memory. Pure — returns a
    new content string, never mutates `content` or `entry`.

    `entry` is an outline.compute_outline() entry for the resolved anchor
    (must carry the ENC-TSK-P71 additive header_start_ln/header_end_ln
    fields). Returns:
      {"content": <new full document text>,
       "block_id": <str|None>,   # the anchor's block_id after this op
       "stamped": <bool>,        # True if a NEW block_id was generated here
       "bytes_changed": <int>,   # abs(after_bytes - before_bytes)
       "before_bytes": <int>, "after_bytes": <int>}
    """
    if op not in VALID_OPS:
        raise ValueError(f"unsupported op: {op!r}")

    raw_lines = content.split("\n")

    header_start_idx = entry["header_start_ln"] - 1
    header_end_idx = entry["header_end_ln"] - 1
    line_start = entry["line_start"]
    line_end = entry["line_end"]
    has_body = line_start <= line_end
    body_start_idx = line_start - 1
    body_end_idx = line_end - 1

    existing_block_id = entry.get("block_id")
    comment_idx = (body_start_idx - 1) if existing_block_id else None

    heading_construct = raw_lines[header_start_idx:header_end_idx + 1]
    comment_line = [raw_lines[comment_idx]] if comment_idx is not None else []
    existing_body_lines = raw_lines[body_start_idx:body_end_idx + 1] if has_body else []

    prefix = raw_lines[:header_start_idx]
    suffix_start_idx = (body_end_idx + 1) if has_body else (header_end_idx + 1 + len(comment_line))
    suffix = raw_lines[suffix_start_idx:]

    target_level = min(6, entry["level"] + 1)

    def _prep(text: Optional[str]) -> List[str]:
        lines = [ln.rstrip() for ln in (text or "").split("\n")]
        lines = _strip_blank_edges(lines)
        if rebase_headings and lines:
            lines = rebase_body_headings(lines, target_level)
        return lines

    remove_heading = (op == "delete" and include_heading)
    replace_heading_via_body = (op == "replace" and include_heading)

    need_stamp = (
        existing_block_id is None
        and not remove_heading
        and not replace_heading_via_body
    )
    final_block_id: Optional[str] = existing_block_id
    stamped = False
    if need_stamp:
        final_block_id = generate_ulid()
        stamped = True

    if remove_heading or replace_heading_via_body:
        final_heading_block: List[str] = []
        final_block_id = None
    else:
        new_comment = (
            comment_line if existing_block_id
            else ([f"<!-- enc:block:{final_block_id} -->"] if need_stamp else [])
        )
        final_heading_block = heading_construct + new_comment

    if op == "delete":
        final_body_block: List[str] = []
    elif op == "replace":
        final_body_block = _prep(body)
    elif op == "append":
        trimmed_existing = _rstrip_blank_tail(existing_body_lines)
        final_body_block = _join_seam(trimmed_existing, _prep(body))
    else:  # prepend
        trimmed_existing = _lstrip_blank_head(existing_body_lines)
        final_body_block = _join_seam(_prep(body), trimmed_existing)

    left_context = prefix + final_heading_block
    if final_body_block:
        combined = _join_seam(left_context, final_body_block)
        combined = _join_seam(combined, suffix)
    else:
        combined = _join_seam(left_context, suffix)

    new_content = "\n".join(combined)
    before_bytes = len(content.encode("utf-8"))
    after_bytes = len(new_content.encode("utf-8"))

    return {
        "content": new_content,
        "block_id": final_block_id,
        "stamped": stamped,
        "bytes_changed": abs(after_bytes - before_bytes),
        "before_bytes": before_bytes,
        "after_bytes": after_bytes,
    }


# ---------------------------------------------------------------------------
# Dry-run preview (AC-7)
# ---------------------------------------------------------------------------


def unified_diff_for_patch(before_content: str, after_content: str, context: int = 2) -> str:
    """A unified diff of the affected region between two full-document
    strings (difflib naturally localizes hunks to the changed lines)."""
    before_lines = before_content.splitlines(keepends=False)
    after_lines = after_content.splitlines(keepends=False)
    diff = difflib.unified_diff(
        before_lines, after_lines, fromfile="before", tofile="after", lineterm="", n=context,
    )
    return "\n".join(diff)
