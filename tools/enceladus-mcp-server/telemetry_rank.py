"""Convergence Surface read-path projection helpers (ENC-FTR-086 / ENC-TSK-I83).

Pure, dependency-free helpers backing the MCP ``search(action='telemetry.rank')``
read action. This module is deliberately ISOLATED:

* It imports nothing from any governance Lambda (coordination_api,
  governance_audit, governance_drift_check, recompute_governance) and nothing
  from this MCP server module. Governance code, in turn, never imports this
  module nor the convergence-telemetry counter table. That topology is the
  architectural enforcement of Locked Design Decision D1 in DOC-E3F5E025B3D9
  ("soft prior, never hard gate"): the convergence surface is queryable by
  agents but structurally invisible to governance gates.
* All ranking logic is expressed as pure functions over plain dicts so it can
  be exercised without network or AWS access.

The Phase-2 read surface computes frequency rankings either from a dedicated
counter table GSI (when ENC-FTR-086 Phase-1 is deployed and surfaced via the
caller) or, as a forward-compatible fallback, directly from the governed
tracker records that are the source of truth. Both paths emit the identical
D3 row shape so the MCP contract is stable across the Phase-1 cutover.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Versioned per Locked Design Decision D2 (canonicalization is versioned; a
# function change requires a governed migration + a version bump that callers
# can detect at the response boundary).
CANONICALIZATION_VERSION = "v1"
SCHEMA_VERSION = "telemetry.rank.v1"

# Default and ceiling for the ranked-page size.
DEFAULT_LIMIT = 10
MAX_LIMIT = 100

# Number of distinct raw (pre-canonicalization) value samples carried per row
# for the D3 rich-signal payload (ENC-TSK-I83 AC-2).
RAW_VALUE_SAMPLE_CAP = 3

# Canonical telemetry-eligibility map. Mirrors the governance dictionary
# ``telemetry.eligible_fields`` entity (the dictionary is the policy source of
# truth; this is the in-process fallback so the read surface is functional on
# gamma before the live dictionary sync lands). Keyed by attribute_name ->
# resolution metadata.
ELIGIBLE_FIELDS: Dict[str, Dict[str, Any]] = {
    "category": {
        "record_type": "task",
        "entity": "tracker.task",
        "vocabulary_bounded": True,
    },
    "components": {
        "record_type": "task",
        "entity": "tracker.task",
        "vocabulary_bounded": True,
        "list_valued": True,
    },
    "subtypepattern": {
        "record_type": "document",
        "entity": "document.doc",
        "vocabulary_bounded": True,
    },
}

# Author identity is resolved best-effort from these record fields in order.
_AUTHOR_FIELDS = ("created_by", "author", "owner")

# Timestamps are read best-effort from these fields.
_FIRST_SEEN_FIELDS = ("created_at",)
_LAST_SEEN_FIELDS = ("updated_at", "created_at")

_NON_ALNUM_EDGE = re.compile(r"^[^0-9a-z]+|[^0-9a-z]+$")
_WS_OR_UNDERSCORE = re.compile(r"[\s_]+")


def canonicalize(value: Any) -> str:
    """Canonicalize a raw attribute value (Locked Design Decision D2, v1).

    Policy: Unicode NFC, lowercase, collapse runs of whitespace or underscores
    to a single hyphen, then strip leading/trailing non-alphanumerics. Applied
    identically to stored values and query inputs. Returns "" for values that
    canonicalize to empty (callers skip empties).
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = unicodedata.normalize("NFC", text)
    text = text.lower()
    text = _WS_OR_UNDERSCORE.sub("-", text)
    text = _NON_ALNUM_EDGE.sub("", text)
    return text


def is_eligible(attribute_name: str) -> bool:
    return attribute_name in ELIGIBLE_FIELDS


def resolve_record_type(attribute_name: str, explicit: Optional[str] = None) -> str:
    """Resolve the record_type for an attribute, honoring an explicit override."""
    if explicit:
        return explicit
    meta = ELIGIBLE_FIELDS.get(attribute_name) or {}
    return str(meta.get("record_type") or "task")


def _first_present(record: Dict[str, Any], fields: Iterable[str]) -> str:
    for f in fields:
        v = record.get(f)
        if v:
            return str(v)
    return ""


def _author_of(record: Dict[str, Any]) -> str:
    author = _first_present(record, _AUTHOR_FIELDS)
    if author:
        return author
    ws = record.get("write_source")
    if isinstance(ws, dict):
        prov = ws.get("provider") or ws.get("channel")
        if prov:
            return str(prov)
    return "unknown"


def _iter_attribute_values(record: Dict[str, Any], attribute_name: str) -> List[Any]:
    """Yield the raw value(s) of an attribute on a record.

    List-valued attributes (e.g. ``components``) contribute one occurrence per
    element; scalar attributes contribute a single occurrence.
    """
    raw = record.get(attribute_name)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [v for v in raw if v is not None and str(v).strip() != ""]
    if str(raw).strip() == "":
        return []
    return [raw]


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"offset:{int(offset)}".encode("utf-8")).decode("ascii")


def decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        decoded = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        if decoded.startswith("offset:"):
            return max(0, int(decoded.split(":", 1)[1]))
    except Exception:
        return 0
    return 0


def _sorted_rows(buckets: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build D3 rows from aggregation buckets, ranked count-desc, value-asc."""
    rows: List[Dict[str, Any]] = []
    for canonical_value, agg in buckets.items():
        rows.append(
            {
                "canonical_value": canonical_value,
                "count": agg["count"],
                "raw_count": agg["count"],
                "raw_value_samples": agg["raw_samples"][:RAW_VALUE_SAMPLE_CAP],
                "first_seen": agg["first_seen"] or None,
                "last_seen": agg["last_seen"] or None,
                "distinct_author_count": len(agg["authors"]),
            }
        )
    # Deterministic order: highest count first, ties broken by canonical value.
    rows.sort(key=lambda r: (-r["count"], r["canonical_value"]))
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx
    return rows


def rank_records(
    records: Iterable[Dict[str, Any]],
    attribute_name: str,
    *,
    limit: int = DEFAULT_LIMIT,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute a frequency-ranked leaderboard over an attribute (compute-on-read).

    Pure function: aggregates canonicalized attribute values across ``records``
    and returns the D3 payload (rows + pagination + schema/canonicalization
    version). Never raises on individual malformed records — they are skipped.
    """
    effective_limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    offset = decode_cursor(cursor)

    buckets: Dict[str, Dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        author = _author_of(record)
        first_seen = _first_present(record, _FIRST_SEEN_FIELDS)
        last_seen = _first_present(record, _LAST_SEEN_FIELDS)
        for raw in _iter_attribute_values(record, attribute_name):
            canonical = canonicalize(raw)
            if not canonical:
                continue
            agg = buckets.get(canonical)
            if agg is None:
                agg = {
                    "count": 0,
                    "raw_samples": [],
                    "authors": set(),
                    "first_seen": "",
                    "last_seen": "",
                }
                buckets[canonical] = agg
            agg["count"] += 1
            agg["authors"].add(author)
            raw_str = str(raw)
            if raw_str not in agg["raw_samples"] and len(agg["raw_samples"]) < RAW_VALUE_SAMPLE_CAP:
                agg["raw_samples"].append(raw_str)
            if first_seen and (not agg["first_seen"] or first_seen < agg["first_seen"]):
                agg["first_seen"] = first_seen
            if last_seen and last_seen > agg["last_seen"]:
                agg["last_seen"] = last_seen

    all_rows = _sorted_rows(buckets)
    total = len(all_rows)
    page = all_rows[offset : offset + effective_limit]
    next_cursor = encode_cursor(offset + effective_limit) if (offset + effective_limit) < total else None

    return {
        "rows": page,
        "total_distinct_values": total,
        "next_cursor": next_cursor,
        "schema_version": SCHEMA_VERSION,
        "canonicalization_version": CANONICALIZATION_VERSION,
    }


def rank_counter_items(
    items: Iterable[Dict[str, Any]],
    *,
    limit: int = DEFAULT_LIMIT,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the D3 payload from pre-aggregated counter-table items (Phase-1 GSI).

    Each item is expected to already carry a canonical value and counters from
    the ``enceladus-convergence-telemetry`` table. Missing fields degrade
    gracefully. This keeps the MCP response shape identical whether the rows are
    computed-on-read or served from the dedicated counter table.
    """
    effective_limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    offset = decode_cursor(cursor)

    rows: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        canonical = item.get("canonical_value") or item.get("canonical") or ""
        if not canonical:
            continue
        count = int(item.get("count") or item.get("raw_count") or 0)
        raw_samples = item.get("raw_value_samples") or item.get("raw_samples") or []
        if not isinstance(raw_samples, list):
            raw_samples = [str(raw_samples)]
        rows.append(
            {
                "canonical_value": str(canonical),
                "count": count,
                "raw_count": count,
                "raw_value_samples": [str(s) for s in raw_samples][:RAW_VALUE_SAMPLE_CAP],
                "first_seen": item.get("first_seen") or None,
                "last_seen": item.get("last_seen") or None,
                "distinct_author_count": int(item.get("distinct_author_count") or 0),
            }
        )

    rows.sort(key=lambda r: (-r["count"], r["canonical_value"]))
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx

    total = len(rows)
    page = rows[offset : offset + effective_limit]
    next_cursor = encode_cursor(offset + effective_limit) if (offset + effective_limit) < total else None

    return {
        "rows": page,
        "total_distinct_values": total,
        "next_cursor": next_cursor,
        "schema_version": SCHEMA_VERSION,
        "canonicalization_version": CANONICALIZATION_VERSION,
    }


def degraded_payload(reason: str = "") -> Dict[str, Any]:
    """Standard degraded response (Locked Design Decision: degradation)."""
    payload: Dict[str, Any] = {
        "rows": [],
        "total_distinct_values": 0,
        "next_cursor": None,
        "schema_version": SCHEMA_VERSION,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "degraded": True,
    }
    if reason:
        payload["degraded_reason"] = reason
    return payload
