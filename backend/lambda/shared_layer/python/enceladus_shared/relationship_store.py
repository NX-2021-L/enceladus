"""Typed relationship edge storage (ENC-TSK-L13 / B65 Ph4).

Dual-write migration from devops-project-tracker rel# rows to the dedicated
enceladus-relationships table. Reads merge the relationships table first and
fall back to the tracker table for keys not yet present in the new store.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

PutItem = Dict[str, Any]
TransactItem = Dict[str, Any]


def relationships_table_name() -> Optional[str]:
    raw = os.environ.get("RELATIONSHIPS_TABLE", "").strip()
    return raw or None


def dual_write_enabled() -> bool:
    return relationships_table_name() is not None


def relationships_authoritative() -> bool:
    """ENC-TSK-M55 component 1: when true, the relationships table is a verified
    superset of the tracker table's rel# rows and the legacy fallback pass in
    iter_project_relationship_items is skipped. Set per environment via CFN
    (gamma verified 2026-07-11; prod unverified, stays false)."""
    raw = os.environ.get("RELATIONSHIPS_TABLE_AUTHORITATIVE", "").strip().lower()
    return raw in ("1", "true", "yes")


def range_bounding_disabled() -> bool:
    """ENC-TSK-M55 component 2 kill switch (rollback lever short of git revert)."""
    raw = os.environ.get("FEED_EDGE_RANGE_BOUND_DISABLED", "").strip().lower()
    return raw in ("1", "true", "yes")


# Sorts after every ASCII suffix of a rel#{source_id}# key, so the upper bound
# of a BETWEEN range includes all of that source's edges.
_RANGE_UPPER_SENTINEL = "￿"


def build_page_sk_ranges(
    source_ids: Iterable[str],
    *,
    rel_prefix: str = "rel#",
    max_ranges: Optional[int] = None,
) -> List[Tuple[str, str]]:
    """ENC-TSK-M55 component 2: sort-key BETWEEN bounds covering every edge of
    the given source records.

    Groups the page's source IDs by record-type prefix (the ID up to its last
    hyphen), then coalesces adjacent groups down to max_ranges. Every source's
    rel#{source_id}#... keys fall inside the returned bounds by construction;
    recency-consistency of the ID scheme only affects how narrow the spans are.
    max_ranges defaults to FEED_EDGE_RANGE_MAX_CLUSTERS (1): at current edge
    volume (~385 rows total, 2026-07-11) sequential Query round-trips dominate
    scanned bytes, so one range per project minimizes total calls.
    """
    ids = sorted({str(s) for s in source_ids if s})
    if not ids:
        return []
    if max_ranges is None:
        try:
            max_ranges = int(os.environ.get("FEED_EDGE_RANGE_MAX_CLUSTERS", "1"))
        except ValueError:
            max_ranges = 1
    max_ranges = max(1, max_ranges)

    groups: List[List[str]] = []
    current_key: Optional[str] = None
    for rid in ids:
        key = rid.rsplit("-", 1)[0] if "-" in rid else rid
        if key != current_key:
            groups.append([rid, rid])
            current_key = key
        else:
            groups[-1][1] = rid

    if len(groups) > max_ranges:
        chunk = -(-len(groups) // max_ranges)  # ceil division
        groups = [
            [groups[i][0], groups[min(i + chunk - 1, len(groups) - 1)][1]]
            for i in range(0, len(groups), chunk)
        ]

    return [
        (f"{rel_prefix}{lo}#", f"{rel_prefix}{hi}#{_RANGE_UPPER_SENTINEL}")
        for lo, hi in groups
    ]


def write_target_tables(tracker_table: str) -> List[str]:
    rel_table = relationships_table_name()
    if rel_table and rel_table != tracker_table:
        return [rel_table, tracker_table]
    return [tracker_table]


def build_create_transact_puts(
    tracker_table: str,
    forward_item: PutItem,
    inverse_item: PutItem,
) -> List[TransactItem]:
    items: List[TransactItem] = []
    for table in write_target_tables(tracker_table):
        items.extend(
            [
                {
                    "Put": {
                        "TableName": table,
                        "Item": forward_item,
                        "ConditionExpression": "attribute_not_exists(record_id)",
                    }
                },
                {
                    "Put": {
                        "TableName": table,
                        "Item": inverse_item,
                        "ConditionExpression": "attribute_not_exists(record_id)",
                    }
                },
            ]
        )
    return items


def build_archive_transact_updates(
    tracker_table: str,
    *,
    project_id_attr: PutItem,
    forward_sk: str,
    inverse_sk: str,
    archived_at_attr: PutItem,
) -> List[TransactItem]:
    items: List[TransactItem] = []
    for table in write_target_tables(tracker_table):
        for sk in (forward_sk, inverse_sk):
            items.append(
                {
                    "Update": {
                        "TableName": table,
                        "Key": {
                            "project_id": project_id_attr,
                            "record_id": {"S": sk},
                        },
                        "UpdateExpression": "SET #st = :archived, archived_at = :now",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {
                            ":archived": {"S": "archived"},
                            ":now": archived_at_attr,
                        },
                        "ConditionExpression": "attribute_exists(record_id)",
                    }
                }
            )
    return items


def build_delete_transact_deletes(
    tracker_table: str,
    *,
    project_id_attr: PutItem,
    forward_sk: str,
    inverse_sk: str,
) -> List[TransactItem]:
    items: List[TransactItem] = []
    for table in write_target_tables(tracker_table):
        for sk in (forward_sk, inverse_sk):
            items.append(
                {
                    "Delete": {
                        "TableName": table,
                        "Key": {
                            "project_id": project_id_attr,
                            "record_id": {"S": sk},
                        },
                        "ConditionExpression": "attribute_exists(record_id)",
                    }
                }
            )
    return items


def _paginate_prefix(
    ddb,
    table_name: str,
    project_id: str,
    sk_prefix: str,
    *,
    ser_s: Callable[[str], PutItem],
    limit: Optional[int] = None,
    exclusive_start_key: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    kwargs: Dict[str, Any] = {
        "TableName": table_name,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": ser_s(project_id),
            ":prefix": ser_s(sk_prefix),
        },
    }
    if limit is not None:
        kwargs["Limit"] = limit
    if exclusive_start_key:
        kwargs["ExclusiveStartKey"] = exclusive_start_key
    resp = ddb.query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")


def query_relationship_raw_items(
    ddb,
    tracker_table: str,
    project_id: str,
    sk_prefix: str,
    *,
    ser_s: Callable[[str], PutItem],
    limit: Optional[int] = None,
    exclusive_start_key: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Query relationship rows; relationships table wins on SK conflicts."""
    rel_table = relationships_table_name()
    if not rel_table:
        return _paginate_prefix(
            ddb,
            tracker_table,
            project_id,
            sk_prefix,
            ser_s=ser_s,
            limit=limit,
            exclusive_start_key=exclusive_start_key,
        )

    primary_items, primary_cursor = _paginate_prefix(
        ddb,
        rel_table,
        project_id,
        sk_prefix,
        ser_s=ser_s,
        limit=limit,
        exclusive_start_key=exclusive_start_key,
    )
    merged: Dict[str, Dict[str, Any]] = {}
    for raw in primary_items:
        sk = raw.get("record_id", {}).get("S", "")
        if sk:
            merged[sk] = raw

    if exclusive_start_key is None:
        legacy_items, _ = _paginate_prefix(
            ddb,
            tracker_table,
            project_id,
            sk_prefix,
            ser_s=ser_s,
        )
        for raw in legacy_items:
            sk = raw.get("record_id", {}).get("S", "")
            if sk and sk not in merged:
                merged[sk] = raw

    return list(merged.values()), primary_cursor


def iter_project_relationship_items(
    ddb,
    tracker_table: str,
    project_ids: Iterable[str],
    *,
    ser_s: Callable[[str], PutItem],
    rel_prefix: str = "rel#",
    sk_ranges_by_project: Optional[Dict[str, List[Tuple[str, str]]]] = None,
    stats: Optional[Dict[str, int]] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield all relationship raw items for projects (feed/extensions path).

    ENC-TSK-M55: when sk_ranges_by_project supplies BETWEEN bounds for a
    project (from build_page_sk_ranges), each range replaces the full-history
    begins_with scan; projects without ranges keep the legacy scan. When the
    relationships table is authoritative (verified per environment), the
    tracker-table fallback pass is skipped entirely. `stats`, if given, is
    incremented in place: query_count / items_seen / scanned_count.
    """
    rel_table = relationships_table_name()
    skip_legacy_pass = rel_table is not None and relationships_authoritative()
    for pid in project_ids:
        if not pid:
            continue
        merged: Dict[str, Dict[str, Any]] = {}
        if skip_legacy_pass:
            tables = [rel_table]
        else:
            tables = [rel_table, tracker_table] if rel_table else [tracker_table]
        ranges = (sk_ranges_by_project or {}).get(pid) or None
        for table in tables:
            if not table:
                continue
            if ranges:
                key_variants = [
                    (
                        "project_id = :pid AND record_id BETWEEN :lo AND :hi",
                        {":pid": ser_s(pid), ":lo": ser_s(lo), ":hi": ser_s(hi)},
                    )
                    for lo, hi in ranges
                ]
            else:
                key_variants = [
                    (
                        "project_id = :pid AND begins_with(record_id, :rel_prefix)",
                        {":pid": ser_s(pid), ":rel_prefix": ser_s(rel_prefix)},
                    )
                ]
            paginator = ddb.get_paginator("query")
            for key_condition, attr_values in key_variants:
                for page in paginator.paginate(
                    TableName=table,
                    KeyConditionExpression=key_condition,
                    ExpressionAttributeValues=attr_values,
                ):
                    if stats is not None:
                        stats["query_count"] = stats.get("query_count", 0) + 1
                        stats["items_seen"] = stats.get("items_seen", 0) + len(
                            page.get("Items", [])
                        )
                        stats["scanned_count"] = stats.get("scanned_count", 0) + int(
                            page.get("ScannedCount", 0) or 0
                        )
                    for raw in page.get("Items", []):
                        sk = raw.get("record_id", {}).get("S", "")
                        if sk.startswith("rel#") and sk not in merged:
                            merged[sk] = raw
        yield from merged.values()
