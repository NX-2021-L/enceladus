"""Bundled version_seq helpers for tracker_mutation (ENC-TSK-L27)."""

from __future__ import annotations

from typing import Any, Dict, Tuple

FEED_SCOPE = "global"
VERSION_SEQ_COUNTER_PROJECT = "__feed__"
VERSION_SEQ_COUNTER_RECORD = "counter#version_seq"


def version_seq_attr(seq: int) -> Dict[str, Dict[str, str]]:
    return {
        "version_seq": {"N": str(int(seq))},
        "feed_scope": {"S": FEED_SCOPE},
    }


def allocate_version_seq(ddb: Any, table_name: str) -> int:
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
    return (
        ", version_seq = :vseq, feed_scope = :fscope",
        {
            ":vseq": {"N": str(int(seq))},
            ":fscope": {"S": FEED_SCOPE},
        },
    )


def sequenced_governed_write_clause(
    seq: int,
) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """Pure composition half of the sequencing rule (ENC-TSK-S94).

    Given an ALREADY-allocated ``seq``, return the appendable ``SET`` fragment and
    its values. Split out from :func:`sequenced_governed_write_parts` so a caller
    that allocates through its own seam -- tracker_mutation, whose
    ``_version_seq_update_parts`` records the number on the write-attribution
    context and whose tests monkeypatch ``allocate_version_seq`` -- shares the
    composition without giving up that seam.

    See :func:`sequenced_governed_write_parts` for the caller contract: append
    inside ``SET``, before any ``ADD``, and never assign ``write_kind`` yourself.
    """
    expr, values = version_seq_update_clause(seq)
    values = dict(values)
    values[":vsq_wkind"] = {"S": "governed"}
    return expr + ", write_kind = :vsq_wkind", values


def sequenced_governed_write_parts(
    ddb: Any, table_name: str
) -> Tuple[str, Dict[str, Dict[str, str]], int]:
    """ENC-ISS-908 / ENC-TSK-S94 -- the single sequencing rule for a governed write.

    Allocates the next version_seq and returns ``(set_fragment, values, seq)``.
    ``set_fragment`` is APPENDABLE: it begins with ``", "`` and is meant to be
    concatenated onto an existing ``SET`` clause. It marks the write as

      * *sequenced* -- ``version_seq`` + ``feed_scope``, so the Query on
        version-seq-index behind ``GET /api/v1/feed/delta`` sees the write and a
        client that missed the push event can heal it; and
      * *governed* -- ``write_kind``, so the DynamoDB-stream event-source
        filters do not drop the resulting MODIFY as a marker write.

    Caller contract:

      1. Append the fragment INSIDE the ``SET`` clause and BEFORE any ``ADD``
         clause. A ``SET`` assignment placed after ``" ADD ..."`` is invalid
         UpdateExpression syntax -- ENC-TSK-P49, where every governed task close
         failed on exactly that ordering.
      2. Do NOT also assign ``write_kind`` in the same UpdateExpression.
         DynamoDB rejects an expression naming one document path twice ("Two
         document paths overlap").

    ``version_seq`` is a MONOTONE CURSOR, never a counter. Allocation is its own
    UpdateItem and runs before the caller's (often conditional) write, so a
    ConditionalCheckFailed burns a number and leaves a gap in the sequence. Gaps
    are harmless to a ``version_seq > :cursor`` Query and to the client's
    25-sequence-unit heal re-read; no consumer may derive a count, a total or a
    rate from ``version_seq``.
    """
    seq = allocate_version_seq(ddb, table_name)
    expr, values = sequenced_governed_write_clause(seq)
    return expr, values, seq
