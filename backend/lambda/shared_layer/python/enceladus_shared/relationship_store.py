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
) -> Iterable[Dict[str, Any]]:
    """Yield all relationship raw items for projects (feed/extensions path)."""
    rel_table = relationships_table_name()
    for pid in project_ids:
        if not pid:
            continue
        merged: Dict[str, Dict[str, Any]] = {}
        tables = [rel_table, tracker_table] if rel_table else [tracker_table]
        for table in tables:
            if not table:
                continue
            paginator = ddb.get_paginator("query")
            for page in paginator.paginate(
                TableName=table,
                KeyConditionExpression="project_id = :pid AND begins_with(record_id, :rel_prefix)",
                ExpressionAttributeValues={
                    ":pid": ser_s(pid),
                    ":rel_prefix": ser_s(rel_prefix),
                },
            ):
                for raw in page.get("Items", []):
                    sk = raw.get("record_id", {}).get("S", "")
                    if sk.startswith("rel#") and sk not in merged:
                        merged[sk] = raw
        yield from merged.values()
