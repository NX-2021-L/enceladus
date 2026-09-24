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
{id, kind, ok, outcome, http_status, project_id, status_or_version, title}
-- never full record bodies.
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

``profile`` and ``governance_hash`` (added for ENC-TSK-P77 / elr_smoke.py's
elr.smoke_digest schema) carry the ENVIRONMENT profile name
("prod"/"v4-gamma") the run used and the live governance_hash echoed by
the health endpoint body. The two ENC-TSK-P90 prefix-resolution fields
that used to sit beside them (the map's provenance, and the client-side
list of record ids that map could not classify) were REMOVED by
ENC-TSK-Q10 (ENC-ISS-791): ELR no longer holds any prefix->project map --
the server resolves a record's project from its id on the tracker
sentinel route (elr_batch_get.PROJECT_SENTINEL) -- so there is no map
provenance to report and no client-side verdict to list; an id the
server cannot resolve is a per-row outcome "not_found" in ``rows``.

``removed_paths`` (added for ENC-TSK-Q10 AC-9 / elr_sync.py) is the small
list of local file paths a successful ``pull`` deleted on upgrade --
today only the dead ENC-TSK-P90 prefix-map cache
(elr_sync.STALE_PREFIX_MAP_RELATIVE under the user's home), when a stale
copy exists. Always a list of path strings, never file contents; empty
when nothing needed removing.

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

``digest_path``, ``anchor_resolved``, ``bytes_changed``, ``event_id``,
``current_hash``, ``current_version``, ``recommended_next_actions``, and
``candidates`` (added for ENC-TSK-P78 / elr_doc_digest.py, elr_doc_get.py,
elr_doc_patch.py) carry the section-patch delta-only write path's small,
stable summaries: digest_path is the ~/.enceladus/docs/{id}.digest.json
side-file path a run wrote or refreshed (elr_lib.manifest); anchor_resolved
is the small {heading_path, ordinal, block_id} view of the section a patch
targeted; bytes_changed is the abs(after-before) byte delta a successful
patch reports; event_id is the server's event id for an applied patch;
current_hash/current_version/recommended_next_actions are the small
remediation fields echoed by a 412 CONTENT_HASH_MISMATCH envelope; candidates
is the small list of {heading_path, ordinal, block_id} views echoed by a 409
ANCHOR_AMBIGUOUS envelope. ``request_bytes`` is the measured wire size
(headers + JSON body) of the one POST a real (non-dry-run) patch sends --
proof the delta-only contract holds regardless of how large the target
document is. Same digest-first discipline as every other field -- small
and stable, never a raw document body.

``count``, ``exhausted``, ``count_truncated``, ``pages``, ``as_of``, and
``by_type`` (added for ENC-TSK-Q16 / elr_list.py's ``--census`` mode) carry
the U1 bounded-census payload's own small, stable summary fields verbatim
(the full census response is written to a local side file under
--lists-dir; these six are the ONLY census fields echoed to stdout).

``n`` and ``next_cursor`` (also ENC-TSK-Q16, elr_list.py's ``--page``/
``--pages`` modes) are the single-page/loop counterparts of census's
count/pages: n is the number of ids written to the local ids file by this
run, next_cursor is the raw list route's own opaque continuation cursor
(never decoded or re-derived client-side) when the server reports one.
``lower_bound`` and ``page_truncated`` are small booleans, present only
when True: lower_bound means a ``--pages N`` run fetched fewer pages than
its census side file actually has, so its accumulated id count is a
lower bound, not a total; page_truncated means the raw page(s) just
fetched left more rows unread than were written to the local ids file.
page_truncated is read from the raw list route's own ``page_truncated``
response field when the server reports one (the authoritative signal,
since it can diverge from next_cursor presence); only a server that
omits the field (pre-U1) falls back to the next_cursor-presence
heuristic.
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
    "removed_paths",
    "session_id",
    "agent_type_id",
    "sci_ttl_remaining_s",
    "ca_bundle",
    "remediation",
    "profile",
    "governance_hash",
    "digest_path",
    "anchor_resolved",
    "bytes_changed",
    "event_id",
    "current_hash",
    "current_version",
    "recommended_next_actions",
    "candidates",
    "request_bytes",
    "count",
    "exhausted",
    "count_truncated",
    "pages",
    "as_of",
    "by_type",
    "n",
    "next_cursor",
    "lower_bound",
    "page_truncated",
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
