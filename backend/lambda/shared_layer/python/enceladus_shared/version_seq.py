"""Monotonic feed version_seq allocation (ENC-TSK-L27)."""

from __future__ import annotations

from typing import Any, Dict, Tuple

FEED_SCOPE = "global"
FEED_TOMBSTONE_PROJECT = "__feed__"
FEED_TOMBSTONE_RECORD_TYPE = "feed_tombstone"
VERSION_SEQ_COUNTER_PROJECT = "__feed__"
VERSION_SEQ_COUNTER_RECORD = "counter#version_seq"


def version_seq_attr(seq: int) -> Dict[str, Dict[str, str]]:
    return {
        "version_seq": {"N": str(int(seq))},
        "feed_scope": {"S": FEED_SCOPE},
    }


def allocate_version_seq(ddb: Any, table_name: str) -> int:
    """Atomically allocate the next monotonic version_seq."""
    counter_key = {
        "project_id": {"S": VERSION_SEQ_COUNTER_PROJECT},
        "record_id": {"S": VERSION_SEQ_COUNTER_RECORD},
    }
    resp = ddb.update_item(
        TableName=table_name,
        Key=counter_key,
        UpdateExpression=(
            "SET next_num = if_not_exists(next_num, :zero) + :one, "
            "feed_scope = :scope, record_type = :counter_type, "
            "item_id = if_not_exists(item_id, :counter_item_id)"
        ),
        ExpressionAttributeValues={
            ":zero": {"N": "0"},
            ":one": {"N": "1"},
            ":scope": {"S": FEED_SCOPE},
            ":counter_type": {"S": "counter"},
            ":counter_item_id": {"S": "COUNTER-VERSION-SEQ"},
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp.get("Attributes") or {}
    return int(attrs.get("next_num", {"N": "0"})["N"])


def version_seq_update_clause(seq: int) -> Tuple[str, Dict[str, Dict[str, str]]]:
    expr = ", version_seq = :vseq, feed_scope = :fscope"
    values = {
        ":vseq": {"N": str(int(seq))},
        ":fscope": {"S": FEED_SCOPE},
    }
    return expr, values


def tombstone_item(
    *,
    seq: int,
    project_id: str,
    record_id: str,
    item_id: str,
    record_type: str,
    updated_at: str,
) -> Dict[str, Dict[str, str]]:
    return {
        "project_id": {"S": FEED_TOMBSTONE_PROJECT},
        "record_id": {"S": f"tombstone#{seq}"},
        "record_type": {"S": FEED_TOMBSTONE_RECORD_TYPE},
        "feed_scope": {"S": FEED_SCOPE},
        "version_seq": {"N": str(int(seq))},
        "item_id": {"S": item_id or record_id.split("#", 1)[-1]},
        "target_project_id": {"S": project_id},
        "target_record_id": {"S": record_id},
        "target_record_type": {"S": record_type},
        "updated_at": {"S": updated_at},
    }
