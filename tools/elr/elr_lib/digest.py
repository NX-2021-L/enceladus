"""ELR digest schema.

ELR is digest-first: every transport helper reports a small, stable
summary of what happened instead of echoing the full payload body. This
module owns that shape so every caller (the smoke CLI, future ELR
subcommands, tests) produces byte-for-byte-comparable digests.

Stable keys (always present): operation, ok, status, identity_posture,
anomalies.

Optional keys (present only when the caller supplies a non-None value):
content_hash, size_bytes, counts, record_ids, local_path,
compliance_score, document_id, version, local_sha256, outline, rows.

No other keys are accepted -- passing anything else raises ValueError so
a future caller cannot silently smuggle a full response body into a
"digest" and defeat the digest-first contract.

``rows`` (added for ENC-TSK-O52 / elr_batch_get.py) carries per-item
COMPACT summary dicts for a batch operation -- e.g.
{id, kind, ok, status_or_version, title} -- never full record bodies.
It is still subject to the same digest-first discipline as every other
field: small, stable, no raw payloads.

``proofs``, ``plane_safety``, ``source_sha256``, ``reverse_substituted_sha256``,
and ``patch_performed`` (added for ENC-TSK-O54 / elr_publish.py) carry the
dual-proof write path's small, stable summaries: proofs is a
{hash_echo, reverse_substitution} pass/fail/skip map (never body bytes);
plane_safety is the five-step pre/post-write report (status/ok booleans
and small ids/versions per step, never full response bodies);
source_sha256 / reverse_substituted_sha256 are hex digests; patch_performed
is a bool. Same digest-first discipline applies -- small and stable, no
raw payload bodies.

``dest``, ``source_ref``, ``manifest_version``, ``files_verified``,
``files_failed``, ``mismatched``, and ``refusal`` (added for ENC-TSK-O55 /
elr_sync.py) carry the hash-pinned manifest distribution path's small,
stable summaries: dest/source_ref are small path/sha strings;
manifest_version echoes the manifest's own version marker;
files_verified/files_failed are counts; mismatched is a small list of
relative paths that failed verification (never file bodies); refusal
mirrors the {reason, missing_fields, violations} shape every other ELR
CLI's local refusal helper already uses, folded into build_digest so
elr_sync can reuse ONE digest builder for both its success and its
refuse-activation paths.

``profile``, ``governance_hash``, ``prefix_map_source``, and
``unclassified`` (added for ENC-TSK-P77 / elr_smoke.py's elr.smoke_digest
schema) carry: the ENVIRONMENT profile name ("prod"/"v4-gamma") the run
used; the live governance_hash echoed by the health endpoint body;
"none" for prefix_map_source until ENC-TSK-P74's ELR half lands; and an
always-present (possibly empty) list of unclassified items reserved for
that same follow-up.

``ca_bundle`` and ``remediation`` (added for ENC-TSK-P76 / elr_lib.tls)
carry the TLS CA-bundle resolution report: ca_bundle is the small
{source, path} dict every transport client resolves at construction time
(never the bundle's contents); remediation is present only when
ca_bundle.source == "missing" and is always the exact string
elr_lib.tls.REMEDIATION_MESSAGE.

``session_id``, ``agent_type_id``, and ``sci_ttl_remaining_s`` (added for
ENC-TSK-P75 / elr_lib.identity) carry the credential-bound identity
posture's small, stable summary: the live ENC-SES session_id and
ENC-AGT agent_type_id this run resolved (or reused), and the remaining
seconds before its Session Claim ID (sci) expires. The sci VALUE itself
is never a digest field -- only its remaining-lifetime is, so a digest
can prove a live SCI is held without becoming a bearer credential in its
own right.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional

VALID_IDENTITY_POSTURES = ("credential-bound", "internal-key", "bearer", "server-held-keys", "unknown")

_OPTIONAL_FIELDS = (
    "content_hash",
    "size_bytes",
    "counts",
    "record_ids",
    "local_path",
    "compliance_score",
    "document_id",
    "version",
    "local_sha256",
    "outline",
    "rows",
    "proofs",
    "plane_safety",
    "source_sha256",
    "reverse_substituted_sha256",
    "patch_performed",
    "dest",
    "source_ref",
    "manifest_version",
    "files_verified",
    "files_failed",
    "mismatched",
    "refusal",
    "session_id",
    "agent_type_id",
    "sci_ttl_remaining_s",
    "ca_bundle",
    "remediation",
    "profile",
    "governance_hash",
    "prefix_map_source",
    "unclassified",
)

_STABLE_KEYS = ("operation", "ok", "status", "identity_posture", "anomalies")


def build_digest(operation: str, ok: bool, status: int, **fields: Any) -> Dict[str, Any]:
    """Build a stable-shape digest dict.

    Required positional: operation (str), ok (bool), status (int/str
    status code or code-like value).

    Recognized keyword fields:
      identity_posture -- one of VALID_IDENTITY_POSTURES (default "unknown")
      anomalies         -- iterable of strings (default [])
      content_hash, size_bytes, counts, record_ids, local_path,
      compliance_score, rows -- optional, included only when not None.

    Any other keyword raises ValueError.
    """
    identity_posture = fields.pop("identity_posture", "unknown")
    if identity_posture not in VALID_IDENTITY_POSTURES:
        raise ValueError(
            f"invalid identity_posture {identity_posture!r}; expected one of {VALID_IDENTITY_POSTURES}"
        )

    raw_anomalies = fields.pop("anomalies", None) or []
    anomalies: List[str] = [str(a) for a in raw_anomalies]

    unknown_fields = set(fields) - set(_OPTIONAL_FIELDS)
    if unknown_fields:
        raise ValueError(
            f"build_digest() got unsupported field(s) {sorted(unknown_fields)}; "
            "digest-first contract forbids passing full payload bodies -- "
            f"allowed optional fields are {_OPTIONAL_FIELDS}"
        )

    digest: Dict[str, Any] = {
        "operation": str(operation),
        "ok": bool(ok),
        "status": status,
        "identity_posture": identity_posture,
        "anomalies": anomalies,
    }

    for key in _OPTIONAL_FIELDS:
        if key in fields and fields[key] is not None:
            digest[key] = fields[key]

    return digest


def content_digest(data: bytes) -> Dict[str, Any]:
    """Cheap sha256 + size summary for bytes, for content_hash/size_bytes fields."""
    return {
        "content_hash": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "size_bytes": len(data),
    }


def stable_keys() -> Iterable[str]:
    return _STABLE_KEYS


def optional_fields() -> Iterable[str]:
    return _OPTIONAL_FIELDS
