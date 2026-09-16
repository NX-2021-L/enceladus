#!/usr/bin/env python3
"""elr_doc_patch.py -- ELR delta-only heading-anchored section patch client.

Spec: ENC-TSK-P78 (T-B5, FR-B4-11..14) AC-3/AC-4/AC-5. Patches ONE
heading-anchored section of a governed document (POST
/{document_id}/sections -- backend/lambda/document_api/lambda_function.py
:_handle_patch_section, vendored anchor/op engine at elr_lib.sections) by
sending only {project_id, anchor, op, body?, if_match, governance_hash,
include_heading?, rebase_headings?, idempotency_key?, caused_by?} --
NEVER the full document, whether the target document is 1KB or 1MB
(AC-5's delta-only contract).

if_match (the content_hash precondition) comes SOLELY from the digest
side file elr_doc_digest.py / elr_doc_get.py write to
~/.enceladus/docs/{document_id}.digest.json (elr_lib.manifest) -- this
script never re-derives it any other way, and refuses to run (exit 2)
when that side file is missing or older than
elr_lib.manifest.STALE_AFTER_HOURS (24h). elr_lib.plane_safety's
pre-flight (steps 1+2, the sentinel-identity hard gate) runs unchanged
before every real write, exactly as elr_publish.py already uses it.

Exit codes:
  0  success (write applied, or a clean --dry-run preview)
  1  generic refusal (local validation failure, plane-safety abort,
     unreachable/5xx/unexpected HTTP status, missing local body cache
     needed for --dry-run)
  2  precondition missing or stale -- remediation: run
     `elr_doc_digest.py --doc <ID>` (or `elr_doc_get.py <ID>`) first
  3  412 CONTENT_HASH_MISMATCH -- side file refreshed from the envelope;
     current_hash/current_version/recommended_next_actions reported
  5  404 ANCHOR_NOT_FOUND -- the server's outline is reported
  6  409 ANCHOR_AMBIGUOUS -- the server's candidates are reported

A digest is always emitted on stdout as the ONE JSON line, exactly like
every other ELR CLI; --dry-run's local unified diff (the only exception
to "digest-only" ELR CLIs make, since it is a deliberately small,
section-scoped preview the caller asked to see, not a document body
dump) is written to stderr, never stdout, so stdout stays machine-
parseable.

Usage:
    python3 tools/elr/elr_doc_patch.py --doc DOC-ID --anchor "Section A / Sub B" \\
        --op replace --body-file new_body.md
    echo "new body" | python3 tools/elr/elr_doc_patch.py --doc DOC-ID \\
        --block-id 01ARZ3NDEKTSV4RRFFQ69G5FAV --op append
    python3 tools/elr/elr_doc_patch.py --doc DOC-ID --anchor "Section A" \\
        --op delete --dry-run

Python 3.11 standard library only (+ elr_lib). Nothing here imports
server.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow running this file directly without requiring tools/elr to
# already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import manifest as elr_manifest  # noqa: E402
from elr_lib import plane_safety  # noqa: E402
from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib import sections as elr_sections  # noqa: E402
from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

DEFAULT_PROJECT = "enceladus"
HEADING_PATH_SEPARATOR = " / "

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_PRECONDITION_MISSING_OR_STALE = 2
EXIT_CONTENT_HASH_MISMATCH = 3
EXIT_ANCHOR_NOT_FOUND = 5
EXIT_ANCHOR_AMBIGUOUS = 6

_DIGEST_REMEDIATION = "digest side file missing or stale -- run elr_doc_digest.py --doc {document_id} first"


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


def _anchor_view(entry: Dict[str, Any]) -> Dict[str, Any]:
    """The small {heading_path, level, ordinal, block_id} shape the
    server's own anchor_resolved echoes -- used for the local dry-run
    preview so its shape matches a real 200 response's anchor_resolved.
    """
    return {
        "heading_path": entry.get("heading_path"),
        "level": entry.get("level"),
        "ordinal": entry.get("ordinal"),
        "block_id": entry.get("block_id"),
    }


def parse_heading_path(raw: str) -> List[str]:
    return [part.strip() for part in raw.split(HEADING_PATH_SEPARATOR) if part.strip()]


def build_anchor(
    *, heading_path_raw: Optional[str], block_id: Optional[str], ordinal: Optional[int]
) -> Dict[str, Any]:
    anchor: Dict[str, Any] = {}
    if block_id:
        anchor["block_id"] = block_id
    if heading_path_raw:
        anchor["heading_path"] = parse_heading_path(heading_path_raw)
    if ordinal is not None:
        anchor["ordinal"] = ordinal
    return anchor


def estimate_request_bytes(headers: Dict[str, str], payload: Dict[str, Any]) -> int:
    """AC-5: the total wire size a real POST would use -- header lines
    ("Key: Value\\r\\n") plus the JSON body, measured the same way for
    both the digest field and the byte-budget test. This never includes
    document content beyond the one section `body` the caller supplied.
    """
    body_bytes = json.dumps(payload).encode("utf-8")
    header_bytes = sum(len(f"{k}: {v}\r\n".encode("utf-8")) for k, v in headers.items())
    return header_bytes + len(body_bytes)


def _request_headers(config: Any) -> Dict[str, str]:
    """Mirrors InternalClient.request()'s own header construction (AC-5
    measures what will actually be sent -- see InternalClient.request in
    elr_lib.transport) without needing a live client instance.
    """
    from elr_lib import config as elr_config

    headers = {"Accept": "application/json", "User-Agent": config.user_agent, "Content-Type": "application/json"}
    key = config.key_for("document")
    if key:
        headers[elr_config.INTERNAL_AUTH_HEADER] = key
    return headers


def _local_body_cache(document_id: str, docs_dir: str) -> Optional[str]:
    path = elr_manifest.body_cache_path(document_id, docs_dir)
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _write_local_body_cache(document_id: str, docs_dir: str, content: str) -> str:
    path = elr_manifest.body_cache_path(document_id, docs_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def _refetch_and_cache_body(
    client: InternalClient, document_id: str, docs_dir: str, *, timeout: int
) -> Tuple[bool, Optional[str]]:
    """Best-effort GET of the full body to re-sync the local cache after
    a local-reapply hash mismatch. Returns (ok, local_path)."""
    encoded = urllib.parse.quote(document_id, safe="")
    status, body = client.request("GET", "document", f"/{encoded}", query={"include_content": "true"})
    if status != 200 or not isinstance(body, dict):
        return False, None
    nested = body.get("document")
    doc = nested if isinstance(nested, dict) else body
    content = doc.get("content")
    if not isinstance(content, str):
        return False, None
    path = _write_local_body_cache(document_id, docs_dir, content)
    return True, path


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------


def patch_section(
    document_id: str,
    anchor: Dict[str, Any],
    op: str,
    body: Optional[str],
    *,
    include_heading: bool = False,
    rebase_headings: bool = True,
    dry_run: bool = False,
    idempotency_key: Optional[str] = None,
    caused_by: Optional[str] = None,
    project: str = DEFAULT_PROJECT,
    docs_dir: str = elr_manifest.DEFAULT_DOCS_DIR,
    timeout: int = 20,
    profile_name: str = "internal",
    environment_profile_name: Optional[str] = None,
    diff_stream: Any = None,
) -> Tuple[Dict[str, Any], int]:
    """Returns (digest, exit_code). Never raises -- every failure path
    (local validation, missing precondition, plane-safety abort,
    network/HTTP failure, anchor-resolution failure) returns a digest,
    exactly like every other ELR CLI's library function.
    """
    operation = "elr_doc_patch.patch"
    diff_stream = diff_stream if diff_stream is not None else sys.stderr

    # --- local validation (mirrors the server's own AC-1 gate; never
    # spends a round trip on a request the server would 400 anyway) -----
    validation_error = elr_sections.validate_op_and_body(op, body)
    if validation_error:
        code, message = validation_error
        return (
            build_digest(operation, False, "local", anomalies=[f"{code}: {message}"], document_id=document_id),
            EXIT_REFUSED,
        )
    if body and len(body.encode("utf-8")) > elr_sections.MAX_BODY_BYTES:
        return (
            build_digest(
                operation,
                False,
                "local",
                anomalies=[f"BODY_TOO_LARGE: body exceeds {elr_sections.MAX_BODY_BYTES} bytes"],
                document_id=document_id,
            ),
            EXIT_REFUSED,
        )

    # --- AC-3: if_match comes SOLELY from the digest side file ----------
    side_file = elr_manifest.read_side_file(document_id, docs_dir=docs_dir)
    side_document_id = (side_file or {}).get("document_id")
    stale = elr_manifest.is_stale((side_file or {}).get("fetched_at"))
    if not side_file or side_document_id != document_id or stale:
        return (
            build_digest(
                operation,
                False,
                "local",
                anomalies=["precondition-missing-or-stale"],
                document_id=document_id,
                remediation=_DIGEST_REMEDIATION.format(document_id=document_id),
            ),
            EXIT_PRECONDITION_MISSING_OR_STALE,
        )
    if_match = str(side_file.get("content_hash") or "")
    if not if_match:
        return (
            build_digest(
                operation,
                False,
                "local",
                anomalies=["precondition-missing-or-stale", "digest-side-file-missing-content-hash"],
                document_id=document_id,
                remediation=_DIGEST_REMEDIATION.format(document_id=document_id),
            ),
            EXIT_PRECONDITION_MISSING_OR_STALE,
        )

    # --- --dry-run: pure local preview, NO network call of any kind -----
    if dry_run:
        local_body = _local_body_cache(document_id, docs_dir)
        if local_body is None:
            return (
                build_digest(
                    operation,
                    False,
                    "dry-run",
                    anomalies=["local-body-cache-missing"],
                    document_id=document_id,
                    remediation=(
                        f"no local body cache at {elr_manifest.body_cache_path(document_id, docs_dir)} -- "
                        "run elr_doc_get.py --docs-dir/--out-dir pointed at this docs-dir first"
                    ),
                ),
                EXIT_REFUSED,
            )
        entries = elr_sections.compute_outline_with_spans(local_body)
        try:
            entry = elr_sections.resolve_anchor(entries, anchor)
        except elr_sections.AnchorError as exc:
            return _anchor_error_digest(operation, exc, document_id)

        result = elr_sections.apply_section_op(
            local_body, entry, op, body, include_heading=include_heading, rebase_headings=rebase_headings
        )
        diff = elr_sections.unified_diff_for_patch(local_body, result["content"])
        print(diff, file=diff_stream)
        return (
            build_digest(
                operation,
                True,
                "dry-run",
                anomalies=["dry-run-no-network-write"],
                document_id=document_id,
                anchor_resolved=_anchor_view({**entry, "block_id": result["block_id"]}),
                bytes_changed=result["bytes_changed"],
            ),
            EXIT_OK,
        )

    # --- real write: plane-safety pre-flight (unchanged), governance_hash,
    # POST, exit-code dispatch on the response ----------------------------
    config = get_profile(profile_name, environment_profile_name=environment_profile_name)
    client = InternalClient(config, timeout=timeout)
    key_sent = bool(config.key_for("document"))

    pre_state = plane_safety.run_pre_write(client, project, timeout=timeout)
    if pre_state["abort"]:
        return (
            build_digest(
                operation,
                False,
                "local",
                anomalies=[pre_state["abort_reason"]],
                document_id=document_id,
                plane_safety=plane_safety.build_report(pre_state, None, write_ok=None),
            ),
            EXIT_REFUSED,
        )

    health_status, health_body = client.health()
    governance_hash = health_body.get("governance_hash") if isinstance(health_body, dict) else None
    if health_status != 200 or not governance_hash:
        return (
            build_digest(
                operation,
                False,
                health_status,
                anomalies=["governance-hash-unavailable"],
                document_id=document_id,
                plane_safety=plane_safety.build_report(pre_state, None, write_ok=None),
            ),
            EXIT_REFUSED,
        )

    payload: Dict[str, Any] = {
        "project_id": project,
        "anchor": anchor,
        "op": op,
        "if_match": if_match,
        "governance_hash": governance_hash,
    }
    if op != "delete":
        payload["body"] = body
    if include_heading:
        payload["include_heading"] = True
    if not rebase_headings:
        payload["rebase_headings"] = False
    if idempotency_key:
        payload["idempotency_key"] = idempotency_key
    if caused_by:
        payload["caused_by"] = caused_by

    request_bytes = estimate_request_bytes(_request_headers(config), payload)

    encoded_id = urllib.parse.quote(document_id, safe="")
    status, resp_body = client.request("POST", "document", f"/{encoded_id}/sections", payload=payload)
    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    anomalies = list(anomalies)
    resp = resp_body if isinstance(resp_body, dict) else {}

    if status == 200 and resp.get("success"):
        return _success_digest(
            operation, document_id, resp, anomalies, posture, status,
            request_bytes=request_bytes, pre_state=pre_state,
            client=client, docs_dir=docs_dir, op=op, body=body,
            include_heading=include_heading, rebase_headings=rebase_headings, anchor=anchor,
            if_match=if_match, timeout=timeout,
        )

    if status == 412:
        current_hash = resp.get("current_hash")
        current_version = resp.get("current_version")
        recommended = resp.get("recommended_next_actions") or []
        elr_manifest.update_side_file(
            document_id, {"content_hash": current_hash, "version": current_version}, docs_dir=docs_dir
        )
        anomalies.append("content-hash-mismatch-412")
        return (
            build_digest(
                operation, False, status,
                identity_posture=posture, anomalies=anomalies, document_id=document_id,
                current_hash=current_hash, current_version=current_version,
                recommended_next_actions=list(recommended), request_bytes=request_bytes,
            ),
            EXIT_CONTENT_HASH_MISMATCH,
        )

    if status == 404:
        anomalies.append("anchor-not-found-404")
        return (
            build_digest(
                operation, False, status,
                identity_posture=posture, anomalies=anomalies, document_id=document_id,
                outline=resp.get("outline"), request_bytes=request_bytes,
            ),
            EXIT_ANCHOR_NOT_FOUND,
        )

    if status == 409:
        anomalies.append("anchor-ambiguous-409")
        return (
            build_digest(
                operation, False, status,
                identity_posture=posture, anomalies=anomalies, document_id=document_id,
                candidates=resp.get("candidates"), request_bytes=request_bytes,
            ),
            EXIT_ANCHOR_AMBIGUOUS,
        )

    if isinstance(resp_body, dict) and resp_body.get("error"):
        anomalies.append(f"response_error: {resp_body['error']}")
    return (
        build_digest(
            operation, False, status,
            identity_posture=posture, anomalies=anomalies, document_id=document_id,
            request_bytes=request_bytes,
        ),
        EXIT_REFUSED,
    )


def _anchor_error_digest(operation: str, exc: "elr_sections.AnchorError", document_id: str) -> Tuple[Dict[str, Any], int]:
    if exc.status == 404:
        return (
            build_digest(
                operation, False, exc.status, anomalies=[f"{exc.code}-local"],
                document_id=document_id, outline=exc.details.get("outline"),
            ),
            EXIT_ANCHOR_NOT_FOUND,
        )
    if exc.status == 409:
        return (
            build_digest(
                operation, False, exc.status, anomalies=[f"{exc.code}-local"],
                document_id=document_id, candidates=exc.details.get("candidates"),
            ),
            EXIT_ANCHOR_AMBIGUOUS,
        )
    return (
        build_digest(operation, False, exc.status, anomalies=[f"{exc.code}-local: {exc.message}"], document_id=document_id),
        EXIT_REFUSED,
    )


def _success_digest(
    operation: str,
    document_id: str,
    resp: Dict[str, Any],
    anomalies: List[str],
    posture: str,
    status: int,
    *,
    request_bytes: int,
    pre_state: Dict[str, Any],
    client: InternalClient,
    docs_dir: str,
    op: str,
    body: Optional[str],
    include_heading: bool,
    rebase_headings: bool,
    anchor: Dict[str, Any],
    if_match: str,
    timeout: int,
) -> Tuple[Dict[str, Any], int]:
    version = resp.get("version")
    content_hash = resp.get("content_hash")
    event_id = resp.get("event_id")
    anchor_resolved = resp.get("anchor_resolved")
    bytes_changed = resp.get("bytes_changed")
    outline = resp.get("outline")

    elr_manifest.update_side_file(
        document_id,
        {"document_id": document_id, "version": version, "content_hash": content_hash, "outline": outline},
        docs_dir=docs_dir,
    )

    # --- AC-3: re-apply the SAME op to the local body cache (if present)
    # and assert local sha256 == the server's returned content_hash -----
    local_body = _local_body_cache(document_id, docs_dir)
    if local_body is not None:
        local_before_sha = hashlib.sha256(local_body.encode("utf-8")).hexdigest()
        if local_before_sha == if_match:
            entries = elr_sections.compute_outline_with_spans(local_body)
            try:
                entry = elr_sections.resolve_anchor(entries, anchor)
            except elr_sections.AnchorError:
                entry = None
            resolved_block_id = (anchor_resolved or {}).get("block_id")
            ulid_factory = (lambda *_a, _bid=resolved_block_id, **_k: _bid) if resolved_block_id else None
            local_after_sha = None
            if entry is not None:
                result = elr_sections.apply_section_op(
                    local_body, entry, op, body,
                    include_heading=include_heading, rebase_headings=rebase_headings,
                    ulid_factory=ulid_factory,
                )
                local_after_sha = hashlib.sha256(result["content"].encode("utf-8")).hexdigest()
            if entry is not None and local_after_sha == content_hash:
                _write_local_body_cache(document_id, docs_dir, result["content"])
            else:
                anomalies.append("local-reapply-hash-mismatch")
                _refetch_and_cache_body(client, document_id, docs_dir, timeout=timeout)
        else:
            anomalies.append("local-body-cache-stale-skipped-reapply")
            _refetch_and_cache_body(client, document_id, docs_dir, timeout=timeout)
    # else: no local body cache -- nothing to re-apply, "if present" per AC-3.

    post_state = plane_safety.build_report(pre_state, None, write_ok=True)
    return (
        build_digest(
            operation, True, status,
            identity_posture=posture, anomalies=anomalies, document_id=document_id,
            version=version, content_hash=content_hash, event_id=event_id,
            anchor_resolved=anchor_resolved, bytes_changed=bytes_changed, outline=outline,
            request_bytes=request_bytes, plane_safety=post_state,
        ),
        EXIT_OK,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elr_doc_patch",
        description=(
            "ELR delta-only heading-anchored section patch client -- sends ONLY "
            "{anchor, op, body, if_match, governance_hash}, never the full document "
            "(DOC-F2CF625B7556, ENC-TSK-P78 T-B5)."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--doc", required=True, dest="document_id", help="The governed document ID to patch.")

    anchor_group = parser.add_mutually_exclusive_group(required=True)
    anchor_group.add_argument(
        "--anchor",
        dest="anchor_heading_path",
        default=None,
        help=f"Heading path, segments separated by '{HEADING_PATH_SEPARATOR}' (e.g. 'Section A{HEADING_PATH_SEPARATOR}Sub B').",
    )
    anchor_group.add_argument("--block-id", dest="block_id", default=None, help="A stamped section block_id (ULID).")

    parser.add_argument("--ordinal", type=int, default=None, help="Disambiguate duplicate sibling headings.")
    parser.add_argument("--op", required=True, choices=list(elr_sections.VALID_OPS), help="Section operation.")
    parser.add_argument("--body-file", default=None, help="Path to the new section body (else read from stdin).")
    parser.add_argument("--include-heading", action="store_true", default=False, help="Include the heading line in the op.")
    parser.add_argument("--no-rebase", action="store_true", default=False, help="Disable heading rebasing (default: rebase on).")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Render a local diff; no network write.")
    parser.add_argument("--idempotency-key", default=None, help="Optional idempotency key for a retried write.")
    parser.add_argument("--caused-by", default=None, help="Optional causation reference for the write's history event.")
    parser.add_argument("--project", default=DEFAULT_PROJECT, help=f"project_id (default: {DEFAULT_PROJECT}).")
    parser.add_argument(
        "--docs-dir",
        default=elr_manifest.DEFAULT_DOCS_DIR,
        help=f"Directory holding the digest side file + local body cache (default: {elr_manifest.DEFAULT_DOCS_DIR}).",
    )
    parser.add_argument("--json", action="store_true", default=True, help="Emit the digest as JSON (default -- always on).")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20).")
    parser.add_argument(
        "--profile",
        default=elr_profiles.PROFILE_PROD,
        choices=list(elr_profiles.VALID_ENVIRONMENT_PROFILES),
        help="ELR ENVIRONMENT profile (default: prod; ENCELADUS_PROFILE env var also selects this).",
    )
    return parser


def _resolve_body(args: argparse.Namespace) -> Optional[str]:
    if args.body_file:
        return Path(args.body_file).expanduser().read_text(encoding="utf-8")
    if args.op == "delete":
        return None
    return sys.stdin.read()


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    anchor = build_anchor(heading_path_raw=args.anchor_heading_path, block_id=args.block_id, ordinal=args.ordinal)
    body = _resolve_body(args)

    digest, exit_code = patch_section(
        args.document_id,
        anchor,
        args.op,
        body,
        include_heading=args.include_heading,
        rebase_headings=not args.no_rebase,
        dry_run=args.dry_run,
        idempotency_key=args.idempotency_key,
        caused_by=args.caused_by,
        project=args.project,
        docs_dir=args.docs_dir,
        timeout=args.timeout,
        environment_profile_name=args.profile,
    )
    # Digest-only on stdout (the dry-run diff, if any, already went to
    # stderr inside patch_section()) -- one JSON line, always.
    print(json.dumps(digest, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
