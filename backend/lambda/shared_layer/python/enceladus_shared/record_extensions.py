"""Feed + tracker record extensions (ENC-TSK-K26 / ENC-TSK-A57).

Attaches typed_relationships and computed context_node metadata to tracker
records served by feed_query and tracker_mutation GET handlers.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

HALF_LIFE_SECONDS = {
    "task": 604800,
    "issue": 259200,
    "feature": 2592000,
    "plan": 2592000,
    "lesson": 15552000,
    "document": 7776000,
}


def compute_freshness(updated_at_iso: Optional[str], record_type: str) -> float:
    if not updated_at_iso:
        return 0.5
    try:
        iso = updated_at_iso
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = max(0.0, datetime.now(timezone.utc).timestamp() - dt.timestamp())
    except (ValueError, TypeError):
        return 0.5
    half_life = HALF_LIFE_SECONDS.get(record_type, 604800)
    return math.exp(-math.log(2) * age / half_life)


def _text_blob(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get("title") or ""),
        str(record.get("description") or ""),
        str(record.get("observation") or ""),
        str(record.get("insight") or ""),
    ]
    return " ".join(p for p in parts if p).strip()


def compute_information_density(record: Dict[str, Any]) -> float:
    blob = _text_blob(record)
    if not blob:
        return 0.0
    # Normalize to [0,1] with 2k chars as saturation (ENC-FTR-050 scale).
    return min(1.0, len(blob) / 2000.0)


def compute_structural_importance(
    record_id: str,
    edges_by_source: Dict[str, List[Dict[str, Any]]],
    max_degree: int,
) -> float:
    """Absolute degree normalized by project max (DOC-310B93107B60 absolute metric)."""
    degree = len(edges_by_source.get(record_id, []))
    for edges in edges_by_source.values():
        for edge in edges:
            if edge.get("target_id") == record_id:
                degree += 1
    if max_degree <= 0:
        return 0.0
    return min(1.0, degree / max_degree)


def compute_max_degree(edges_by_source: Dict[str, List[Dict[str, Any]]]) -> int:
    inbound: Dict[str, int] = {}
    for source_id, edges in edges_by_source.items():
        degree = len(edges)
        for edge in edges:
            target = edge.get("target_id")
            if target:
                inbound[target] = inbound.get(target, 0) + 1
        degree += inbound.get(source_id, 0)
        inbound[source_id] = max(inbound.get(source_id, 0), len(edges))
    if not inbound:
        return 1
    return max(max(inbound.values()), 1)


def build_context_node_meta(
    record: Dict[str, Any],
    record_type: str,
    record_id: str,
    edges_by_source: Dict[str, List[Dict[str, Any]]],
    max_degree: int,
) -> Dict[str, float]:
    access_raw = record.get("context_access_count") or record.get("access_frequency") or 0
    try:
        access_frequency = int(access_raw)
    except (TypeError, ValueError):
        access_frequency = 0
    return {
        "freshness_score": round(compute_freshness(record.get("updated_at"), record_type), 4),
        "structural_importance": round(
            compute_structural_importance(record_id, edges_by_source, max_degree), 4
        ),
        "information_density": round(compute_information_density(record), 4),
        "access_frequency": access_frequency,
    }


def attach_record_extensions(
    records: List[Dict[str, Any]],
    id_key: str,
    record_type: str,
    edges_by_source: Dict[str, List[Dict[str, Any]]],
    max_degree: Optional[int] = None,
) -> None:
    if max_degree is None:
        max_degree = compute_max_degree(edges_by_source)
    for record in records:
        record_id = str(record.get(id_key) or "")
        if not record_id:
            continue
        edges = edges_by_source.get(record_id, [])
        if edges:
            record["typed_relationships"] = edges
        record["context_node"] = build_context_node_meta(
            record, record_type, record_id, edges_by_source, max_degree
        )


def query_typed_relationships_for_projects(
    ddb,
    table_name: str,
    project_ids: List[str],
    *,
    ddb_str: Callable[[Dict[str, Any], str], str],
    ddb_float: Callable[[Dict[str, Any], str], float],
    source_ids_by_project: Optional[Dict[str, List[str]]] = None,
    stats: Optional[Dict[str, int]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Query all outgoing typed edges for the given projects.

    ENC-TSK-M55: source_ids_by_project, when provided, range-bounds each
    project's Query to the sort-key span of the page's actual source records
    (see relationship_store.build_page_sk_ranges). Callers that omit it keep
    the full-history behavior unchanged.
    """
    # ENC-TSK-M55: bare import first — the vendored flat copy in the function
    # zip must win over the stale published-layer package copy (.build_extras
    # pattern, see PLN-006 catalog durable facts).
    try:
        from relationship_store import (  # type: ignore
            build_page_sk_ranges,
            iter_project_relationship_items,
            range_bounding_disabled,
        )
    except ImportError:
        from enceladus_shared.relationship_store import (
            build_page_sk_ranges,
            iter_project_relationship_items,
            range_bounding_disabled,
        )

    sk_ranges_by_project: Optional[Dict[str, List[Any]]] = None
    if source_ids_by_project and not range_bounding_disabled():
        sk_ranges_by_project = {
            pid: build_page_sk_ranges(ids)
            for pid, ids in source_ids_by_project.items()
            if ids
        }

    edges_by_source: Dict[str, List[Dict[str, Any]]] = {}
    for raw in iter_project_relationship_items(
        ddb,
        table_name,
        project_ids,
        ser_s=lambda value: {"S": value},
        sk_ranges_by_project=sk_ranges_by_project,
        stats=stats,
    ):
        sk = ddb_str(raw, "record_id")
        if not sk or not sk.startswith("rel#"):
            continue
        parts = sk.split("#", 4)
        if len(parts) < 4:
            continue
        _, source_id, rel_type, target_id = parts[0], parts[1], parts[2], parts[3]
        if ddb_str(raw, "status") == "archived":
            continue
        edge = {
            "relationship_type": rel_type,
            "target_id": target_id,
            "weight": ddb_float(raw, "weight"),
            "confidence": ddb_float(raw, "confidence"),
            "reason": ddb_str(raw, "reason") or None,
            "created_at": ddb_str(raw, "created_at") or None,
        }
        edges_by_source.setdefault(source_id, []).append(edge)
    return edges_by_source


def query_edges_for_record(
    ddb,
    table_name: str,
    project_id: str,
    source_id: str,
    *,
    ddb_str: Callable[[Dict[str, Any], str], str],
    ddb_float: Callable[[Dict[str, Any], str], float],
) -> List[Dict[str, Any]]:
    """Query outgoing typed edges for a single source record."""
    try:
        from relationship_store import query_relationship_raw_items  # type: ignore
    except ImportError:
        from enceladus_shared.relationship_store import query_relationship_raw_items

    prefix = f"rel#{source_id}#"
    raw_items, _ = query_relationship_raw_items(
        ddb,
        table_name,
        project_id,
        prefix,
        ser_s=lambda value: {"S": value},
    )
    edges: List[Dict[str, Any]] = []
    for raw in raw_items:
        sk = ddb_str(raw, "record_id")
        if not sk or not sk.startswith("rel#"):
            continue
        parts = sk.split("#", 4)
        if len(parts) < 4:
            continue
        _, _src, rel_type, target_id = parts
        if ddb_str(raw, "status") == "archived":
            continue
        edges.append(
            {
                "relationship_type": rel_type,
                "target_id": target_id,
                "weight": ddb_float(raw, "weight"),
                "confidence": ddb_float(raw, "confidence"),
                "reason": ddb_str(raw, "reason") or None,
                "created_at": ddb_str(raw, "created_at") or None,
            }
        )
    return edges
