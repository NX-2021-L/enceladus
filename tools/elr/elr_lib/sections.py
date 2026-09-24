"""ELR section-patch conformance engine (ENC-TSK-P78, T-B5, FR-B4-12).

Thin adapter over the vendored copies of backend/lambda/document_api's
outline.py and sections.py (elr_lib/vendor/document_api_outline.py,
elr_lib/vendor/document_api_sections.py -- see
tools/elr/tools/vendor_document_api.py for how those are (re)generated
and PROVENANCE/PINS.json for what they are pinned against). This module
adds NO algorithmic logic of its own -- section extent, the four ops
(replace/append/prepend/delete), whitespace ownership, and heading
rebasing are exactly whatever the vendored modules compute, so
tests/test_sections_vendor.py's conformance corpus (the same 42 outline
+ 11 sections fixtures backend/lambda/document_api/tests uses,
byte-identical file-for-file) can hold both implementations to the exact
same standard.

Exposes: compute_outline, compute_outline_with_spans, resolve_anchor,
apply_section_op, validate_op_and_body, unified_diff_for_patch,
AnchorError, VALID_OPS, generate_ulid.

``apply_section_op``'s optional ``ulid_factory`` argument exists for two
reasons: (1) deterministic assertions in this package's own tests
without needing the fixture corpus's MASKED_ULID regex trick, and (2)
elr_doc_patch.py's real need -- after a live write, the SERVER may have
stamped a fresh block-id ULID (nondeterministically) into the section it
patched; to reproduce that EXACT after-content locally (for the
sha256-vs-content_hash consistency check), elr_doc_patch.py re-applies
the same op with a ulid_factory pinned to the server-echoed block_id
instead of generating a new, different random one. The vendored
generate_ulid() itself is untouched (still real time+os.urandom by
default) -- injection works by temporarily swapping the vendored
module's module-level generate_ulid attribute for the duration of one
apply_patch() call, then restoring it, so the vendored file's own source
never has to grow a parameter it upstream doesn't have.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .vendor import document_api_outline as _outline
from .vendor import document_api_sections as _sections

AnchorError = _sections.AnchorError
VALID_OPS = _sections.VALID_OPS
MAX_BODY_BYTES = _sections.MAX_BODY_BYTES


def compute_outline(content: str) -> List[Dict[str, Any]]:
    """Public outline shape (no header_start_ln/header_end_ln) -- what a
    manifest/digest reports. Byte-identical to document_api.outline's
    own compute_outline() over the same input (proven by the conformance
    corpus)."""
    return _outline.compute_outline(content)


def compute_outline_with_spans(content: str) -> List[Dict[str, Any]]:
    """The ENC-TSK-P71-extended shape (adds header_start_ln/
    header_end_ln), required by resolve_anchor()/apply_section_op()
    below -- mirrors document_api's own anchor-resolution call path."""
    return _outline.compute_outline_with_spans(content)


def resolve_anchor(outline_entries: List[Dict[str, Any]], anchor: Dict[str, Any]) -> Dict[str, Any]:
    """Returns the matched outline entry, or raises AnchorError(status,
    code, message, **details) -- details carries `outline=` for a 404 or
    `candidates=` for a 409, exactly as document_api.sections does."""
    return _sections.resolve_anchor(outline_entries, anchor)


def validate_op_and_body(op: str, body: Any) -> Optional["tuple[str, str]"]:
    return _sections.validate_op_and_body(op, body)


def generate_ulid(_time_ms: Optional[int] = None, _rand_bytes: Optional[bytes] = None) -> str:
    return _sections.generate_ulid(_time_ms, _rand_bytes)


def apply_section_op(
    content: str,
    entry: Dict[str, Any],
    op: str,
    body: Optional[str],
    *,
    include_heading: bool = False,
    rebase_headings: bool = True,
    ulid_factory: Optional[Callable[..., str]] = None,
) -> Dict[str, Any]:
    """Apply one section op to `content` for the resolved `entry`.
    Byte-identical to document_api.sections.apply_patch() over the same
    inputs (proven by the conformance corpus) -- same return shape:
    {content, block_id, stamped, bytes_changed, before_bytes, after_bytes}.

    `ulid_factory`, when given, temporarily REPLACES the vendored
    module's generate_ulid for the duration of this call only (restored
    in a finally block, so a raised AnchorError/exception from
    apply_patch itself -- there isn't one today, but defensively -- never
    leaves the module patched). See module docstring for why this
    exists.
    """
    if ulid_factory is None:
        return _sections.apply_patch(
            content, entry, op, body, include_heading=include_heading, rebase_headings=rebase_headings
        )

    original = _sections.generate_ulid
    _sections.generate_ulid = ulid_factory  # type: ignore[assignment]
    try:
        return _sections.apply_patch(
            content, entry, op, body, include_heading=include_heading, rebase_headings=rebase_headings
        )
    finally:
        _sections.generate_ulid = original  # type: ignore[assignment]


def unified_diff_for_patch(before_content: str, after_content: str, context: int = 2) -> str:
    return _sections.unified_diff_for_patch(before_content, after_content, context=context)
