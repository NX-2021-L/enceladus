#!/usr/bin/env python3
"""elr_publish.py -- ELR dual-proof governed document write path.

Spec: DOC-F2CF625B7556 A.9, ENC-FTR-134 AC-5/AC-8 (ENC-TSK-O54). WRITES
to the production docstore -- the highest-care ELR operation to date.

Flow:

  0. PRE-FLIGHT: validate the intended documents.put payload through
     elr_validate.py's library interface (fetch_dictionary + load_overlay
     + validate_entity_payload) BEFORE any network write is attempted.
     Validated against TWO dictionary entities: "document.create" (the
     entity that actually, mechanically encodes title/content
     non-empty via Layer 1 min_length constraints -- verified live
     2026-08-22; the same-named rule under "document.idea" is prose-only,
     dictionary type "rule", which elr_validate's Layer 1 deliberately
     skips as non-scalar, so it is NOT a mechanical gate there) and
     "document.<subtype>" (the subtype-specific enum/shape, e.g.
     document.doc pins document_subtype to the literal "doc"). Either
     entity refusing aborts before any write. If the dictionary itself
     is unreachable, this FAILS CLOSED -- refused, not "forwardable".

  1. PLANE-SAFETY five-step wrap (elr_lib.plane_safety) around the
     write: steps 1+2 run before documents.put and HARD-GATE on a
     sentinel-identity mismatch (wrong-plane detection); steps 4+5 run
     after a successful write to corroborate its effect.

  2. documents.put with the SOURCE BYTES UNCHANGED (the source file may
     embed a self-reference placeholder token -- its own not-yet-minted
     document_id -- which cannot be known before this call). Captures
     the minted document_id and the server's echoed content_hash.
     PROOF 1 (hash_echo): content_hash == sha256(source bytes),
     byte-exact through the JSON transport round trip.

  3. If the source contains the placeholder: a CONCURRENCY GUARD runs
     BEFORE documents.patch -- a metadata-only re-read whose content_hash
     is compared against the PUT's echoed content_hash. A mismatch (or
     an unreachable re-read) means another writer could have landed in
     the gap between put and patch, or that the pre-patch state can no
     longer be trusted either way; both HALT-AND-SURFACE: the composed
     (substituted) body is preserved to disk, documents.patch is NEVER
     called, and the digest reports a refusal (ok: false).

  4. documents.patch with the placeholder substituted for the minted
     document_id.

  5. VERIFY-BY-REREAD (never re-send, ENC-TSK-O54/A.8): fetch the
     stored document fresh and reverse-substitute (minted id ->
     placeholder). PROOF 2 (reverse_substitution): sha256 of the
     reverse-substituted body == sha256 of the ORIGINAL source bytes.
     This single re-read is unconditional -- run whether the patch's
     own HTTP response was a clean success, a clean failure, or
     ambiguous (status 0 / 5xx, which could mean the write landed or
     didn't). documents.patch is called AT MOST ONCE per run; a
     re-send is never attempted no matter how the immediate response
     read.

  6. Digest-only output: document_id, version, size_bytes, content_hash,
     source_sha256, reverse_substituted_sha256, proofs {hash_echo,
     reverse_substitution: pass|fail|skip}, compliance_score (surfaced
     unconditionally -- transport success and artifact quality are
     different things), plane_safety report, anomalies. Bodies are
     NEVER printed, whether the run succeeds, is refused, or halts.

Usage:
    python3 tools/elr/elr_publish.py source.md --title "My Doc"
    python3 tools/elr/elr_publish.py source.md --title "My Doc" \\
        --subtype idea --related "ENC-TSK-1,ENC-FTR-2" --keywords "a,b"

Exit code is 0 only when the write is verified by both proofs; nonzero
on any pre-flight refusal, plane-safety abort, put failure, or
concurrency halt. A digest is always emitted, never a bare traceback.

Python 3.11 standard library only. Nothing here imports server.py; ELR
must run standalone on any workstation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow running this file directly (python3 tools/elr/elr_publish.py)
# without requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import plane_safety  # noqa: E402
from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402

# elr_validate.py is a sibling ELR CLI, not an elr_lib module -- imported
# directly per this tool's explicit charter: PRE-FLIGHT reuses
# elr_validate's LIBRARY interface (fetch_dictionary / load_overlay /
# validate_entity_payload) rather than reimplementing dictionary
# validation. This is the one intentional exception to "every elr_*.py
# only imports elr_lib".
import elr_validate as ev  # noqa: E402

DEFAULT_PLACEHOLDER = "{DOCID}"
DEFAULT_PRESERVE_DIR = "~/.enceladus/elr/preserved"

# The entity that mechanically encodes "title/content non-empty" via
# Layer 1 (real min_length:1 constraints on both) -- verified live
# 2026-08-22 against the governance dictionary. document.<subtype>
# entities (document.doc, document.idea, ...) do NOT carry title/content
# fields at all; they only carry subtype-specific shape (e.g. the
# document_subtype enum pin).
_CORE_VALIDATION_ENTITY = "document.create"


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


def _extract_document(body: Any) -> Dict[str, Any]:
    """Mirrors elr_doc_get.py's _extract_document_payload (and
    elr_lib.plane_safety's private copy): the nested "document" object
    and the top-level spread carry the same fields.
    """
    if not isinstance(body, dict):
        return {}
    nested = body.get("document")
    if isinstance(nested, dict):
        return nested
    return body


def _refusal(operation: str, reason: str, **extra: Any) -> Dict[str, Any]:
    """Mirrors elr_validate.py's _refusal_digest shape exactly, so every
    ELR refusal (validation, plane-safety abort, concurrency halt, put
    failure) looks the same to a caller: {operation, ok: false,
    refusal: {reason, missing_fields, violations}, **extra}.
    """
    digest: Dict[str, Any] = {
        "operation": operation,
        "ok": False,
        "refusal": {
            "reason": reason,
            "missing_fields": list(extra.pop("missing_fields", None) or []),
            "violations": list(extra.pop("violations", None) or []),
        },
    }
    digest.update(extra)
    return digest


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def check_concurrency(
    client: InternalClient, encoded_document_id: str, expected_hash: str
) -> "tuple[Optional[str], int, str]":
    """The concurrency guard run immediately before documents.patch: one
    metadata-only re-read, compared against the hash captured from the
    documents.put echo. Returns (conflict_reason, status, observed_hash);
    conflict_reason is None only when it is safe to proceed to patch.

    Extracted as its own function (not inlined in publish_document) so
    the exact production comparison can be exercised directly -- e.g.
    by a concurrency drill against an already-minted live document --
    without reimplementing it ad hoc.
    """
    guard_status, guard_body = client.request(
        "GET", "document", f"/{encoded_document_id}", query={"include_content": "false"}
    )
    guard_doc = _extract_document(guard_body)
    guard_hash = str(guard_doc.get("content_hash") or "").strip().lower()

    if guard_status != 200:
        return "concurrency-guard-unreachable", guard_status, guard_hash
    if guard_hash != expected_hash:
        return "concurrent-edit-detected", guard_status, guard_hash
    return None, guard_status, guard_hash


def _preserve_body(preserve_dir: str, document_id: str, content: str) -> str:
    """Write a HALTed (never-sent) composed body to disk for recovery.
    Path shape: <preserve_dir>/<DOC-ID>.<ts>.md. Never overwrites --
    the timestamp component guarantees a fresh path per halt.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(preserve_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{document_id}.{ts}.md"
    out_path.write_text(content, encoding="utf-8")
    return str(out_path)


# ---------------------------------------------------------------------------
# PRE-FLIGHT: elr_validate library interface
# ---------------------------------------------------------------------------


def _preflight_validate(
    project: str, title: str, content: str, subtype: str, *, timeout: int
) -> "tuple[Optional[Dict[str, Any]], List[str]]":
    """Returns (refusal_digest_or_None, anomalies). refusal_digest is
    None only when both the core (document.create) and subtype-specific
    (document.<subtype>) validations pass. FAILS CLOSED when the live
    dictionary itself cannot be pulled -- that refusal is returned
    immediately, never treated as "proceed anyway".
    """
    dict_result = ev.fetch_dictionary(timeout=timeout)
    if not dict_result["ok"]:
        return (
            _refusal(
                "elr_publish.publish",
                "dictionary_unreachable",
                violations=[{"path": "dictionary", "reason": dict_result["error"]}],
                auth_path=dict_result["auth_path"],
                source_route=dict_result["source_route"],
                status=dict_result["status"],
            ),
            [],
        )

    overlay_entries, overlay_anomaly = ev.load_overlay()
    dictionary = dict_result["dictionary"]

    core_digest = ev.validate_entity_payload(
        _CORE_VALIDATION_ENTITY,
        {"project_id": project, "title": title, "content": content},
        "documents.put",
        dictionary,
        overlay_entries,
        overlay_anomaly,
    )
    subtype_entity = f"document.{subtype}"
    subtype_digest = ev.validate_entity_payload(
        subtype_entity,
        {"document_subtype": subtype},
        "documents.put",
        dictionary,
        overlay_entries,
        overlay_anomaly,
    )

    if not core_digest["ok"] or not subtype_digest["ok"]:
        violations: List[Dict[str, Any]] = []
        missing: List[str] = []
        for sub_digest in (core_digest, subtype_digest):
            if not sub_digest["ok"]:
                violations.extend(sub_digest["refusal"]["violations"])
                missing.extend(sub_digest["refusal"]["missing_fields"])
        return (
            _refusal(
                "elr_publish.publish",
                "validation_failed",
                missing_fields=sorted(set(missing)),
                violations=violations,
                dictionary_version=dictionary.get("version"),
            ),
            [],
        )

    anomalies = list(core_digest.get("anomalies") or []) + list(subtype_digest.get("anomalies") or [])
    return None, anomalies


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------


def publish_document(
    source_file: str,
    title: str,
    *,
    subtype: str = "doc",
    project: str = "enceladus",
    keywords: Optional[List[str]] = None,
    related: Optional[List[str]] = None,
    placeholder: str = DEFAULT_PLACEHOLDER,
    timeout: int = 20,
    profile_name: str = "internal",
    preserve_dir: str = DEFAULT_PRESERVE_DIR,
) -> Dict[str, Any]:
    operation = "elr_publish.publish"

    try:
        source_path = Path(source_file).expanduser()
        source_bytes = source_path.read_bytes()
    except OSError as exc:
        return _refusal(
            operation, "source_file_unreadable", violations=[{"path": "source_file", "reason": str(exc)}]
        )

    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _refusal(operation, "source_not_utf8", violations=[{"path": "source_file", "reason": str(exc)}])

    source_sha256 = hashlib.sha256(source_bytes).hexdigest()

    # --- 0. PRE-FLIGHT ------------------------------------------------------
    refusal, preflight_anomalies = _preflight_validate(project, title, source_text, subtype, timeout=timeout)
    if refusal is not None:
        refusal["source_sha256"] = source_sha256
        return refusal

    config = get_profile(profile_name)
    client = InternalClient(config, timeout=timeout)
    key_sent = bool(config.key_for("document"))

    # --- 1. PLANE-SAFETY steps 1+2 (pre-write, hard gate) --------------------
    pre_state = plane_safety.run_pre_write(client, project, timeout=timeout)
    if pre_state["abort"]:
        return _refusal(
            operation,
            pre_state["abort_reason"],
            violations=[
                {
                    "path": "plane_safety.sentinel",
                    "reason": (
                        f"sentinel {plane_safety.SENTINEL_DOCUMENT_ID} did not echo through the "
                        "surface about to be written -- refusing to write to a plane that may not "
                        "be the intended one"
                    ),
                }
            ],
            plane_safety=plane_safety.build_report(pre_state, None, write_ok=None),
            source_sha256=source_sha256,
        )

    # --- 2. documents.put (the write; PROOF 1 source) ------------------------
    put_payload: Dict[str, Any] = {
        "project_id": project,
        "title": title,
        "content": source_text,
        "document_subtype": subtype,
    }
    if subtype == "doc":
        # Defensive no-op: only takes effect if the semantic
        # handoff-detection guard fires on title/content; otherwise
        # ignored and not stored (per the live dictionary's
        # document.doc.confirm_subtype definition).
        put_payload["confirm_subtype"] = True
    if keywords:
        put_payload["keywords"] = list(keywords)
    if related:
        put_payload["related_items"] = list(related)

    put_status, put_body = client.request("PUT", "document", "", payload=put_payload)
    posture, posture_anomalies = classify_internal_posture(key_sent=key_sent, status_code=put_status)
    anomalies: List[str] = list(preflight_anomalies) + list(posture_anomalies)

    put_ok = 200 <= put_status < 300
    put_doc = _extract_document(put_body)
    minted_document_id = put_doc.get("document_id") or (
        put_body.get("document_id") if isinstance(put_body, dict) else None
    )
    put_content_hash = put_doc.get("content_hash")
    put_size_bytes = put_doc.get("size_bytes")
    put_compliance_score = put_doc.get("compliance_score") if "compliance_score" in put_doc else None

    if not put_ok or not minted_document_id:
        anomalies.append(f"put_failed_http_{put_status}" if not put_ok else "put-response-missing-document-id")
        return _refusal(
            operation,
            "put_failed",
            violations=[{"path": "documents.put", "reason": f"status={put_status}"}],
            status=put_status,
            identity_posture=posture,
            anomalies=anomalies,
            plane_safety=plane_safety.build_report(pre_state, None, write_ok=False),
            source_sha256=source_sha256,
        )

    hash_echo_pass = bool(put_content_hash) and str(put_content_hash).strip().lower() == source_sha256
    if not hash_echo_pass:
        anomalies.append("put-content-hash-mismatch" if put_content_hash else "put-content-hash-missing")

    encoded_id = urllib.parse.quote(minted_document_id, safe="")
    has_placeholder = placeholder in source_text

    patch_performed = False
    proof2_status = "skip"
    reverse_sha256: Optional[str] = None
    final_content_hash = put_content_hash
    final_size_bytes = put_size_bytes
    final_version = put_doc.get("version")
    final_compliance_score = put_compliance_score
    final_status = put_status

    if has_placeholder:
        # --- 3. CONCURRENCY GUARD (metadata-only re-read) --------------------
        conflict_reason, guard_status, guard_hash = check_concurrency(
            client, encoded_id, str(put_content_hash or "").strip().lower()
        )
        expected_hash = str(put_content_hash or "").strip().lower()

        if conflict_reason:
            patched_content = source_text.replace(placeholder, minted_document_id)
            preserved_path = _preserve_body(preserve_dir, minted_document_id, patched_content)
            anomalies.append(conflict_reason)
            # The create still landed -- corroborate its effect even
            # though the patch never happens (steps 4+5 still apply).
            post_state = plane_safety.run_post_write(client, project, minted_document_id, pre_state, timeout=timeout)
            return _refusal(
                operation,
                conflict_reason,
                violations=[
                    {
                        "path": "content_hash",
                        "reason": (
                            f"pre-patch reread hash {guard_hash!r} != put-echo hash "
                            f"{expected_hash!r} (reread status={guard_status})"
                        ),
                    }
                ],
                status=guard_status,
                identity_posture=posture,
                anomalies=anomalies,
                document_id=minted_document_id,
                preserved_path=preserved_path,
                proofs={"hash_echo": "pass" if hash_echo_pass else "fail", "reverse_substitution": "not-attempted"},
                plane_safety=plane_safety.build_report(pre_state, post_state, write_ok=True),
                source_sha256=source_sha256,
            )

        # --- 4. documents.patch (called AT MOST ONCE) -------------------------
        patched_content = source_text.replace(placeholder, minted_document_id)
        patch_status, patch_body = client.request(
            "PATCH", "document", f"/{encoded_id}", payload={"content": patched_content}
        )
        patch_performed = True
        final_status = patch_status

        ambiguous = patch_status == 0 or patch_status >= 500
        if ambiguous:
            anomalies.append("ambiguous-patch-echo")
        elif not (200 <= patch_status < 300):
            anomalies.append(f"patch_failed_http_{patch_status}")

        if 200 <= patch_status < 300 and isinstance(patch_body, dict):
            final_version = patch_body.get("version", final_version)
            final_compliance_score = patch_body.get("compliance_score", final_compliance_score)

        # --- 5. VERIFY-BY-REREAD (unconditional; never re-send) ---------------
        reread_status, reread_body = client.request(
            "GET", "document", f"/{encoded_id}", query={"include_content": "true"}
        )
        reread_doc = _extract_document(reread_body)
        stored_content = reread_doc.get("content")

        if reread_status != 200 or not isinstance(stored_content, str):
            proof2_status = "fail"
            anomalies.append("verify-reread-failed")
        elif minted_document_id not in stored_content:
            # The reverse-substitution hash check alone cannot tell
            # "the patch applied cleanly and there was never a
            # placeholder collision" apart from "the patch never
            # actually applied" -- when nothing was substituted,
            # reverse-substituting is a no-op and would trivially
            # reproduce the source hash either way. Require positive
            # evidence the substitution really happened: the minted id
            # must actually be present in what got read back.
            proof2_status = "fail"
            anomalies.append("patch-did-not-apply-minted-id-absent")
        else:
            reconstructed = stored_content.replace(minted_document_id, placeholder)
            reverse_sha256 = hashlib.sha256(reconstructed.encode("utf-8")).hexdigest()
            proof2_status = "pass" if reverse_sha256 == source_sha256 else "fail"
            if proof2_status == "fail":
                anomalies.append("reverse-substitution-hash-mismatch")
            final_content_hash = reread_doc.get("content_hash", final_content_hash)
            final_size_bytes = reread_doc.get("size_bytes", final_size_bytes)
            final_version = reread_doc.get("version", final_version)
            if "compliance_score" in reread_doc:
                final_compliance_score = reread_doc.get("compliance_score")
            if ambiguous and proof2_status == "pass":
                anomalies.append("ambiguous-patch-echo-recovered-via-reread")

    # --- PLANE-SAFETY steps 4+5 (post-write corroboration) --------------------
    post_state = plane_safety.run_post_write(client, project, minted_document_id, pre_state, timeout=timeout)
    plane_report = plane_safety.build_report(pre_state, post_state, write_ok=True)
    for anomaly in plane_report.get("anomalies") or []:
        if anomaly not in anomalies:
            anomalies.append(anomaly)

    if not has_placeholder:
        # No self-reference to patch -- harvest version/content_hash/
        # compliance_score from the post-write presence probe already
        # fetched for plane-safety step 4, instead of an extra call.
        target_probe = ((post_state.get("step4_post_probe") or {}).get("target")) or {}
        final_version = target_probe.get("version", final_version)
        final_content_hash = target_probe.get("content_hash", final_content_hash) or final_content_hash
        final_size_bytes = target_probe.get("size_bytes", final_size_bytes) or final_size_bytes
        if target_probe.get("compliance_score") is not None:
            final_compliance_score = target_probe.get("compliance_score")
        anomalies.append("no-placeholder-in-source-patch-skipped")

    proofs = {"hash_echo": "pass" if hash_echo_pass else "fail", "reverse_substitution": proof2_status}
    write_ok = hash_echo_pass and proof2_status in ("pass", "skip")

    return build_digest(
        operation,
        write_ok,
        final_status,
        identity_posture=posture,
        anomalies=anomalies,
        document_id=minted_document_id,
        version=final_version,
        content_hash=final_content_hash,
        size_bytes=final_size_bytes,
        compliance_score=final_compliance_score,
        source_sha256=source_sha256,
        reverse_substituted_sha256=reverse_sha256,
        proofs=proofs,
        plane_safety=plane_report,
        patch_performed=patch_performed,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    # allow_abbrev=False everywhere in ELR -- A.8's argparse prefix trap.
    parser = argparse.ArgumentParser(
        prog="elr_publish",
        description=(
            "ELR dual-proof governed document write path: pre-flight validation, "
            "five-step plane-safety, and a client-side concurrency guard around "
            "documents.put + documents.patch (DOC-F2CF625B7556 A.9)."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("source_file", help="Path to the markdown source file to publish.")
    parser.add_argument("--title", required=True, help="Document title.")
    parser.add_argument("--subtype", default="doc", help="document_subtype (default: doc).")
    parser.add_argument("--project", default="enceladus", help="project_id (default: enceladus).")
    parser.add_argument("--keywords", default=None, help="Comma-separated keyword list.")
    parser.add_argument("--related", default=None, help="Comma-separated related_items list.")
    parser.add_argument(
        "--placeholder",
        default=DEFAULT_PLACEHOLDER,
        help=f"Self-reference placeholder token the source may embed (default: {DEFAULT_PLACEHOLDER}).",
    )
    parser.add_argument(
        "--json", action="store_true", default=True, help="Emit the digest as JSON (default -- always on)."
    )
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20).")
    parser.add_argument(
        "--profile",
        default="internal",
        choices=["internal"],
        help="ELR profile to use (only 'internal' can reach the document API).",
    )
    parser.add_argument(
        "--preserve-dir",
        default=DEFAULT_PRESERVE_DIR,
        help=f"Directory for HALT-preserved composed bodies (default: {DEFAULT_PRESERVE_DIR}).",
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    digest = publish_document(
        args.source_file,
        args.title,
        subtype=args.subtype,
        project=args.project,
        keywords=_split_csv(args.keywords),
        related=_split_csv(args.related),
        placeholder=args.placeholder,
        timeout=args.timeout,
        profile_name=args.profile,
        preserve_dir=args.preserve_dir,
    )
    # Digest-only: bodies (source, composed, stored, preserved) are
    # NEVER printed here, on any path.
    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
