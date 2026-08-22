#!/usr/bin/env python3
"""elr_doc_get.py -- ELR governed document fetch, disk-landing.

Kills the read-path overflow class (spec DOC-F2CF625B7556 AC-4): a
governed document's body can be arbitrarily large (the ENC-TSK-O51
target document is a 77K-char catalog). Printing that body to an
agent's context window is exactly the failure mode ELR exists to
avoid. This tool fetches the document over InternalClient (profile
"internal", api "document"), the SAME route
tools/enceladus-mcp-server/server.py:_documents_get uses
(GET /{document_id}?include_content=true with the
X-Coordination-Internal-Key header from elr_lib.config), writes the
body to local disk, and returns ONLY a compact digest -- the body
itself is NEVER printed to stdout/stderr.

Usage:
    python3 tools/elr/elr_doc_get.py DOC-841F5D649EEF
    python3 tools/elr/elr_doc_get.py DOC-841F5D649EEF --out-dir /tmp/elr-cache
    python3 tools/elr/elr_doc_get.py DOC-841F5D649EEF --json

Exit code is 0 when the document was fetched, saved, and its local
sha256 matches the server-reported content_hash; nonzero otherwise.
Even on failure a digest is still emitted (never a bare traceback) so
a caller always gets a stable, parseable result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow running this file directly (python3 tools/elr/elr_doc_get.py) without
# requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

DEFAULT_OUT_DIR = "~/.enceladus/elr/cache"

# ATX headings only, levels 1-3 ('#' through '###'), per the ELR doc-get
# contract -- deeper headings are noise for a navigation outline.
_HEADING_RE = re.compile(r"^(#{1,3})\s+(.+?)\s*$")


def build_parser() -> argparse.ArgumentParser:
    # ALL ELR CLIs must set allow_abbrev=False so partial/ambiguous flags
    # are never silently accepted.
    parser = argparse.ArgumentParser(
        prog="elr_doc_get",
        description=(
            "ELR governed document fetch: lands the document body on local "
            "disk and returns a compact digest only -- the body is never "
            "printed."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "document_id",
        help="The governed document ID to fetch (e.g. DOC-841F5D649EEF).",
    )
    parser.add_argument(
        "--out-dir",
        default=DEFAULT_OUT_DIR,
        help=f"Directory to save the document body into (default: {DEFAULT_OUT_DIR}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Emit the digest as JSON to stdout (default -- this CLI has no other output mode).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="Request timeout in seconds (default: 20).",
    )
    parser.add_argument(
        "--profile",
        default="internal",
        choices=["internal"],
        help="ELR profile to use (only 'internal' can reach the document API).",
    )
    return parser


def _extract_outline(content: str) -> List[Dict[str, Any]]:
    """Pull '#'-'###' ATX headings with 1-based line numbers.

    Headings inside fenced code blocks (``` or ~~~) are skipped -- a
    commented-out or example heading in a code fence is not real
    document structure. Mirrors the fence-tracking approach used by
    backend/lambda/document_api/lambda_function.py's compliance scorer
    (ENC-LSN-026), reimplemented standalone since ELR must run with
    stdlib only and never imports lambda code.
    """
    outline: List[Dict[str, Any]] = []
    in_fence = False
    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = _HEADING_RE.match(raw_line)
        if match:
            level = len(match.group(1))
            text = match.group(2).strip()
            outline.append({"level": level, "line": line_no, "text": text})
    return outline


def _extract_document_payload(body: Any) -> Dict[str, Any]:
    """Normalize the document API's response shape.

    _get_single() in backend/lambda/document_api/lambda_function.py
    returns {"success": True, "document": doc, **doc} -- the nested
    "document" object and the top-level spread carry the same fields.
    Prefer the nested object when present since it can never collide
    with envelope-only keys like "success".
    """
    if not isinstance(body, dict):
        return {}
    nested = body.get("document")
    if isinstance(nested, dict):
        return nested
    return body


def fetch_document(
    document_id: str,
    out_dir: str,
    *,
    timeout: int = 20,
    profile_name: str = "internal",
) -> Dict[str, Any]:
    config = get_profile(profile_name)
    client = InternalClient(config, timeout=timeout)
    key_sent = bool(config.key_for("document"))

    encoded_id = urllib.parse.quote(str(document_id), safe="")
    status, body = client.request(
        "GET",
        "document",
        f"/{encoded_id}",
        query={"include_content": "true"},
    )
    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    anomalies = list(anomalies)
    ok = 200 <= status < 300

    doc = _extract_document_payload(body)
    if not doc and isinstance(body, dict) and body.get("error"):
        anomalies.append(f"response_error: {body['error']}")

    resolved_document_id = doc.get("document_id") or document_id
    version = doc.get("version")
    compliance_score = doc.get("compliance_score")
    server_content_hash = doc.get("content_hash")
    content = doc.get("content")

    local_path: Optional[str] = None
    local_sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    outline: List[Dict[str, Any]] = []

    if ok:
        if not isinstance(content, str):
            ok = False
            anomalies.append("missing-document-body")
        else:
            out_dir_path = Path(out_dir).expanduser()
            out_dir_path.mkdir(parents=True, exist_ok=True)
            saved_path = out_dir_path / f"{resolved_document_id}.md"
            content_bytes = content.encode("utf-8")
            saved_path.write_bytes(content_bytes)

            local_path = str(saved_path)
            local_sha256 = hashlib.sha256(content_bytes).hexdigest()
            size_bytes = len(content_bytes)
            outline = _extract_outline(content)

            server_hash_normalized = str(server_content_hash or "").strip().lower()
            if not server_hash_normalized:
                anomalies.append("server-content-hash-missing")
            elif server_hash_normalized != local_sha256:
                # The server hash is computed over the byte-exact body
                # (backend/lambda/document_api/lambda_function.py's
                # hashlib.sha256(content_bytes).hexdigest()); comparing
                # against sha256 of the exact bytes we just saved is the
                # correct like-for-like check.
                anomalies.append("content-hash-mismatch")
                ok = False

    digest = build_digest(
        "elr_doc_get.fetch",
        ok,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        document_id=resolved_document_id,
        version=version,
        content_hash=server_content_hash,
        local_sha256=local_sha256,
        size_bytes=size_bytes,
        compliance_score=compliance_score,
        outline=outline if outline else None,
        local_path=local_path,
    )
    return digest


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    digest = fetch_document(
        args.document_id,
        args.out_dir,
        timeout=args.timeout,
        profile_name=args.profile,
    )
    # Digest-only: the document body is written to disk inside
    # fetch_document() and MUST NEVER be printed here.
    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
