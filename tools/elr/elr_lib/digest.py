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
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional

VALID_IDENTITY_POSTURES = ("internal-key", "bearer", "server-held-keys", "unknown")

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
