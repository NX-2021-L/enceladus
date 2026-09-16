#!/usr/bin/env python3
"""elr_doc_digest.py -- ELR document manifest digest + side-file cache.

Spec: ENC-TSK-P78 (T-B5, FR-B4-11) AC-1. Calls documents.manifest (GET
/{document_id}/manifest -- {document_id, version, content_hash,
size_bytes, outline}) through the SAME InternalClient/"document" API
surface every other ELR document call uses, and writes the full manifest
response plus a `fetched_at` timestamp to
~/.enceladus/docs/{document_id}.digest.json (elr_lib.manifest).

That side file is the SOLE source of `if_match` for elr_doc_patch.py's
optimistic-concurrency section writes -- elr_doc_patch.py refuses to run
(exit 2) when it is absent or older than
elr_lib.manifest.STALE_AFTER_HOURS. elr_doc_get.py (ENC-TSK-O51) writes
the identical side-file shape on every successful fetch, so either
command keeps the cache fresh.

Usage:
    python3 tools/elr/elr_doc_digest.py DOC-841F5D649EEF
    python3 tools/elr/elr_doc_digest.py DOC-841F5D649EEF --docs-dir /tmp/elr-docs
    python3 tools/elr/elr_doc_digest.py DOC-841F5D649EEF --profile v4-gamma

Exit code is 0 when the manifest was fetched and the side file written;
nonzero otherwise. A digest is always emitted, never a bare traceback --
the manifest body (small: no document content) is safe to fold directly
into the digest's own stable fields, unlike elr_doc_get.py's document
body.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Allow running this file directly without requiring tools/elr to
# already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import manifest as elr_manifest  # noqa: E402
from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    # ALL ELR CLIs must set allow_abbrev=False so partial/ambiguous flags
    # are never silently accepted.
    parser = argparse.ArgumentParser(
        prog="elr_doc_digest",
        description=(
            "ELR governed document manifest fetch: writes a digest side "
            "file (~/.enceladus/docs/{document_id}.digest.json) and "
            "returns a compact digest -- the sole if_match source for "
            "elr_doc_patch.py."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "document_id",
        help="The governed document ID to fetch a manifest for (e.g. DOC-841F5D649EEF).",
    )
    parser.add_argument(
        "--docs-dir",
        default=elr_manifest.DEFAULT_DOCS_DIR,
        help=f"Directory for the digest side file (default: {elr_manifest.DEFAULT_DOCS_DIR}).",
    )
    parser.add_argument(
        "--json", action="store_true", default=True, help="Emit the digest as JSON (default -- always on)."
    )
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20).")
    parser.add_argument(
        "--profile",
        default=elr_profiles.PROFILE_PROD,
        choices=list(elr_profiles.VALID_ENVIRONMENT_PROFILES),
        help=(
            "ELR ENVIRONMENT profile (ENC-TSK-P77) -- which deployed "
            "Enceladus environment to read from (default: prod; "
            "ENCELADUS_PROFILE env var also selects this)."
        ),
    )
    return parser


def fetch_digest(
    document_id: str,
    docs_dir: str = elr_manifest.DEFAULT_DOCS_DIR,
    *,
    timeout: int = 20,
    profile_name: str = "internal",
    environment_profile_name: Optional[str] = None,
) -> Dict[str, Any]:
    config = get_profile(profile_name, environment_profile_name=environment_profile_name)
    client = InternalClient(config, timeout=timeout)
    key_sent = bool(config.key_for("document"))

    status, body = elr_manifest.fetch_manifest(client, document_id, timeout=timeout)
    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    anomalies = list(anomalies)

    body_dict = body if isinstance(body, dict) else {}
    ok = 200 <= status < 300 and bool(body_dict.get("document_id"))
    if not ok and isinstance(body, dict) and body.get("error"):
        anomalies.append(f"response_error: {body['error']}")
    elif not ok and 200 <= status < 300:
        anomalies.append("manifest-response-missing-document-id")

    side_path: Optional[str] = None
    if ok:
        side_path, _written = elr_manifest.write_side_file(document_id, body_dict, docs_dir=docs_dir)

    return build_digest(
        "elr_doc_digest.fetch",
        ok,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        document_id=body_dict.get("document_id") or document_id,
        version=body_dict.get("version"),
        content_hash=body_dict.get("content_hash"),
        size_bytes=body_dict.get("size_bytes"),
        outline=body_dict.get("outline"),
        digest_path=side_path,
    )


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    digest = fetch_digest(
        args.document_id,
        args.docs_dir,
        timeout=args.timeout,
        environment_profile_name=args.profile,
    )
    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
