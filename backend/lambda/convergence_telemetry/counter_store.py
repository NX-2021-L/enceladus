"""Convergence Surface counter store + record logic (ENC-FTR-086 / ENC-TSK-I82).

This module holds the storage-agnostic counting core so the lifecycle behaviour
(canonical-value increment, 10k capacity cap with lowest-count eviction, and
per-deduplication-id idempotency) is unit-testable without AWS. Two concrete
stores implement the same protocol:

* ``InMemoryCounterStore`` — used by the unit tests (ENC-TSK-I82 AC-4, AC-5).
* ``DynamoCounterStore`` — the runtime store backed by the
  ``enceladus-convergence-telemetry`` DynamoDB table.

Table schema (AC-1):
    PK  attribute_name   "{project_id}#{record_type}#{field}"
    SK  canonical_value
    count (N), first_seen, last_seen, authors (SS), canon_version, expires_at (N TTL)
    GSI attribute_name-index: HASH attribute_name, RANGE count
        (count-ordered — drives both ranking reads and lowest-count eviction)

Idempotency markers live in a reserved partition namespace so they never
pollute the per-attribute distinct-value counts used for eviction.
"""

from __future__ import annotations

import os
from typing import Dict, Optional, Protocol, Tuple

# Capacity cap per attribute partition (ENC-FTR-086 AC-6 / ENC-TSK-I82 AC-4).
DEFAULT_CAP = 10000

# Reserved PK prefix for per-dedup-id idempotency markers. The "#" keeps them in
# a partition that the {project}#{type}#{field} attribute partitions can never
# collide with, so distinct_count() of a real attribute never sees a marker.
IDEMPOTENCY_PREFIX = "__idem__#"


class CounterStore(Protocol):
    """Storage protocol for the convergence counter logic."""

    def get(self, attribute_name: str, canonical_value: str) -> Optional[Dict]:
        ...

    def put_new(
        self,
        attribute_name: str,
        canonical_value: str,
        observed_at: str,
        author: str,
        expires_at: int,
    ) -> None:
        ...

    def increment(
        self,
        attribute_name: str,
        canonical_value: str,
        observed_at: str,
        author: str,
        expires_at: int,
    ) -> None:
        ...

    def distinct_count(self, attribute_name: str) -> int:
        ...

    def lowest(self, attribute_name: str) -> Optional[Tuple[str, int]]:
        ...

    def delete(self, attribute_name: str, canonical_value: str) -> None:
        ...

    def mark_processed(self, dedup_id: str, expires_at: int) -> bool:
        """Atomically claim a dedup id. True if newly claimed, False if seen before."""
        ...


def record_observation(
    store: CounterStore,
    attribute_name: str,
    canonical_value: str,
    *,
    dedup_id: str,
    observed_at: str,
    author: str = "",
    expires_at: int = 0,
    cap: int = DEFAULT_CAP,
) -> Dict:
    """Idempotently record one canonical-value observation.

    Behaviour:
      1. Idempotency (AC-5): the first call for ``dedup_id`` proceeds; any later
         call with the same id is a no-op returning ``status="duplicate"``.
      2. Eviction (AC-4): inserting a *new* canonical value when the attribute
         partition is already at ``cap`` first evicts the lowest-count entry, so
         the partition never exceeds ``cap`` distinct values.
      3. Increment: an existing canonical value's count is incremented.
    """
    if not store.mark_processed(dedup_id, expires_at):
        return {"status": "duplicate", "dedup_id": dedup_id}

    existing = store.get(attribute_name, canonical_value)
    evicted: Optional[str] = None

    if existing is None:
        if store.distinct_count(attribute_name) >= cap:
            low = store.lowest(attribute_name)
            if low is not None:
                store.delete(attribute_name, low[0])
                evicted = low[0]
        store.put_new(attribute_name, canonical_value, observed_at, author, expires_at)
        new_count = 1
    else:
        store.increment(attribute_name, canonical_value, observed_at, author, expires_at)
        new_count = int(existing.get("count", 0)) + 1

    return {
        "status": "recorded",
        "attribute_name": attribute_name,
        "canonical_value": canonical_value,
        "count": new_count,
        "evicted": evicted,
    }


class InMemoryCounterStore:
    """Dict-backed CounterStore for unit tests (no AWS)."""

    def __init__(self) -> None:
        # {attribute_name: {canonical_value: {count, first_seen, last_seen, authors:set, expires_at}}}
        self._data: Dict[str, Dict[str, Dict]] = {}
        self._processed: Dict[str, int] = {}

    def get(self, attribute_name: str, canonical_value: str) -> Optional[Dict]:
        item = self._data.get(attribute_name, {}).get(canonical_value)
        return dict(item) if item is not None else None

    def put_new(self, attribute_name, canonical_value, observed_at, author, expires_at) -> None:
        authors = {author} if author else set()
        self._data.setdefault(attribute_name, {})[canonical_value] = {
            "count": 1,
            "first_seen": observed_at,
            "last_seen": observed_at,
            "authors": authors,
            "expires_at": expires_at,
        }

    def increment(self, attribute_name, canonical_value, observed_at, author, expires_at) -> None:
        item = self._data[attribute_name][canonical_value]
        item["count"] += 1
        item["last_seen"] = observed_at
        item["expires_at"] = expires_at
        if author:
            item["authors"].add(author)

    def distinct_count(self, attribute_name: str) -> int:
        return len(self._data.get(attribute_name, {}))

    def lowest(self, attribute_name: str) -> Optional[Tuple[str, int]]:
        partition = self._data.get(attribute_name, {})
        if not partition:
            return None
        # Lowest count first; tie-break on oldest last_seen (age-weighted), then value.
        value = min(
            partition.items(),
            key=lambda kv: (kv[1]["count"], kv[1].get("last_seen", ""), kv[0]),
        )[0]
        return value, partition[value]["count"]

    def delete(self, attribute_name: str, canonical_value: str) -> None:
        self._data.get(attribute_name, {}).pop(canonical_value, None)

    def mark_processed(self, dedup_id: str, expires_at: int) -> bool:
        if dedup_id in self._processed:
            return False
        self._processed[dedup_id] = expires_at
        return True


class DynamoCounterStore:
    """DynamoDB-backed CounterStore for the runtime Lambda."""

    def __init__(self, table_name: Optional[str] = None, region: Optional[str] = None):
        import boto3

        self.table_name = table_name or os.environ["CONVERGENCE_TABLE"]
        region = region or os.environ.get("DYNAMODB_REGION") or os.environ.get("AWS_REGION", "us-west-2")
        self._table = boto3.resource("dynamodb", region_name=region).Table(self.table_name)

    def get(self, attribute_name: str, canonical_value: str) -> Optional[Dict]:
        resp = self._table.get_item(
            Key={"attribute_name": attribute_name, "canonical_value": canonical_value}
        )
        item = resp.get("Item")
        if item is None:
            return None
        return {"count": int(item.get("count", 0)), **item}

    def put_new(self, attribute_name, canonical_value, observed_at, author, expires_at) -> None:
        item = {
            "attribute_name": attribute_name,
            "canonical_value": canonical_value,
            "count": 1,
            "first_seen": observed_at,
            "last_seen": observed_at,
            "canon_version": _canon_version(),
            "expires_at": int(expires_at),
        }
        if author:
            item["authors"] = set([author])
        self._table.put_item(Item=item)

    def increment(self, attribute_name, canonical_value, observed_at, author, expires_at) -> None:
        from boto3.dynamodb.conditions import Attr

        update = "ADD #c :one SET last_seen = :ts, expires_at = :exp, canon_version = :cv"
        names = {"#c": "count"}
        values = {
            ":one": 1,
            ":ts": observed_at,
            ":exp": int(expires_at),
            ":cv": _canon_version(),
        }
        if author:
            update += " ADD authors :author"
            values[":author"] = set([author])
        self._table.update_item(
            Key={"attribute_name": attribute_name, "canonical_value": canonical_value},
            UpdateExpression=update,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    def distinct_count(self, attribute_name: str) -> int:
        from boto3.dynamodb.conditions import Key

        total = 0
        kwargs = {
            "KeyConditionExpression": Key("attribute_name").eq(attribute_name),
            "Select": "COUNT",
        }
        while True:
            resp = self._table.query(**kwargs)
            total += resp.get("Count", 0)
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return total

    def lowest(self, attribute_name: str) -> Optional[Tuple[str, int]]:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            IndexName="attribute_name-index",
            KeyConditionExpression=Key("attribute_name").eq(attribute_name),
            ScanIndexForward=True,  # ascending count -> lowest first
            Limit=1,
        )
        items = resp.get("Items") or []
        if not items:
            return None
        item = items[0]
        return item["canonical_value"], int(item.get("count", 0))

    def delete(self, attribute_name: str, canonical_value: str) -> None:
        self._table.delete_item(
            Key={"attribute_name": attribute_name, "canonical_value": canonical_value}
        )

    def mark_processed(self, dedup_id: str, expires_at: int) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._table.put_item(
                Item={
                    "attribute_name": IDEMPOTENCY_PREFIX + dedup_id,
                    "canonical_value": "_",
                    "expires_at": int(expires_at),
                },
                ConditionExpression="attribute_not_exists(attribute_name)",
            )
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise


def _canon_version() -> int:
    from canonicalize import CANON_VERSION

    return CANON_VERSION
