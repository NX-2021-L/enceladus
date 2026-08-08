"""Read the governed record store for the governance analytics mart.

BRD B3-R3, first clause: *read the governed record store*. This module is the
read half; ``mart_project`` is the projection half and
``enceladus_shared.warehouse_registration`` is the write half.

Five governed sources, all read-only:

===========================  ===========================================
``devops-project-tracker``   tasks, issues, features, plans, lessons, ...
``documents``                docstore metadata (bodies live in S3)
``agent-sessions``           ENC-SES-* allocations and claims
``agent-types``              ENC-AGT-* surface / model dimension
``coordination-requests``    dispatch requests (session extraction shape)
===========================  ===========================================

Full ``Scan`` rather than incremental ``Query``: the refresh is a FULL REFRESH
by contract (``DOC-1E1EC5B7CE02``), so reading everything every run is the
point, not an inefficiency to optimise away. It is also what makes the
new-project sync gap DVP-ISS-088 describes structurally impossible -- a scan
has no per-project registration step to forget. At ~6.3k tracker records and
~25 MB the whole corpus is a few seconds of reads.

Nothing here writes. Nothing here launches a crawler. There is no EventBridge
per-mutation trigger anywhere in this path -- the job is invoked by a
*schedule*, reads current state, and rebuilds every table from scratch.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterator, List, Mapping, Optional

__all__ = [
    "TRACKER_TABLE",
    "DOCUMENTS_TABLE",
    "AGENT_SESSIONS_TABLE",
    "AGENT_TYPES_TABLE",
    "COORDINATION_TABLE",
    "GovernanceCorpus",
    "scan_table",
    "load_corpus",
    "is_sentinel",
]

# Table names resolve exactly as the owning Lambdas resolve them: env var with
# the same hardcoded default, so gamma (`${EnvironmentSuffix}`) works without a
# second convention.
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
AGENT_SESSIONS_TABLE = os.environ.get("AGENT_SESSIONS_TABLE", "agent-sessions")
AGENT_TYPES_TABLE = os.environ.get("AGENT_TYPES_TABLE", "agent-types")
COORDINATION_TABLE = os.environ.get("COORDINATION_TABLE", "coordination-requests")

#: Monotonic-counter sentinel rows share the tables with real records
#: (`counter#ENC-SES`, `counter#ENC-AGT`, and `record_type == "counter"` in the
#: tracker). They are allocator state, not governed records, and counting them
#: would inflate every node and record count in the mart.
_SENTINEL_PREFIX = "counter#"


def is_sentinel(item: Mapping[str, Any]) -> bool:
    """True for allocator sentinel rows, which are never governed records."""
    if item.get("record_type") == "counter":
        return True
    for key in ("session_id", "agent_type_id", "record_id", "document_id"):
        value = item.get(key)
        if isinstance(value, str) and value.startswith(_SENTINEL_PREFIX):
            return True
    return False


def _deserializer():
    from boto3.dynamodb.types import TypeDeserializer

    return TypeDeserializer()


def _decode(value: Any) -> Any:
    """Normalise DynamoDB-deserialised values into plain Python.

    ``TypeDeserializer`` returns ``Decimal`` for every ``N``. Left alone those
    reach the Parquet writer, where the library would coerce them per the
    DECLARED type -- but ``Decimal`` also breaks arithmetic against floats in
    the projection, so it is flattened here, once, at the boundary.
    """
    from decimal import Decimal

    if isinstance(value, Decimal):
        as_int = int(value)
        return as_int if value == as_int else float(value)
    if isinstance(value, list):
        return [_decode(item) for item in value]
    if isinstance(value, dict):
        return {key: _decode(item) for key, item in value.items()}
    if isinstance(value, set):
        return [_decode(item) for item in value]
    return value


def scan_table(client, table: str, drop_sentinels: bool = True) -> List[Dict[str, Any]]:
    """Full paginated scan of one governed table. Read-only."""
    deserializer = _deserializer()
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"TableName": table}
    while True:
        response = client.scan(**kwargs)
        for raw in response.get("Items", []):
            item = {key: _decode(deserializer.deserialize(value)) for key, value in raw.items()}
            if drop_sentinels and is_sentinel(item):
                continue
            items.append(item)
        cursor = response.get("LastEvaluatedKey")
        if not cursor:
            return items
        kwargs["ExclusiveStartKey"] = cursor


class GovernanceCorpus:
    """Everything the mart projects from, read once per refresh."""

    __slots__ = ("records", "documents", "sessions", "agent_types", "coordination_requests")

    def __init__(
        self,
        records: List[Dict[str, Any]],
        documents: List[Dict[str, Any]],
        sessions: List[Dict[str, Any]],
        agent_types: List[Dict[str, Any]],
        coordination_requests: List[Dict[str, Any]],
    ):
        self.records = records
        self.documents = documents
        self.sessions = sessions
        self.agent_types = agent_types
        self.coordination_requests = coordination_requests

    @property
    def agent_type_index(self) -> Dict[str, Dict[str, Any]]:
        """agent_type_id -> its dimension row (surface, model, cost_tier)."""
        return {
            str(entry.get("agent_type_id")): entry
            for entry in self.agent_types
            if entry.get("agent_type_id")
        }

    def counts(self) -> Dict[str, int]:
        return {
            "records": len(self.records),
            "documents": len(self.documents),
            "sessions": len(self.sessions),
            "agent_types": len(self.agent_types),
            "coordination_requests": len(self.coordination_requests),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return "GovernanceCorpus(%s)" % self.counts()


def load_corpus(dynamodb_client=None, region: Optional[str] = None) -> GovernanceCorpus:
    """Read all five governed sources. Read-only, full scan, every project."""
    if dynamodb_client is None:
        import boto3

        dynamodb_client = boto3.client("dynamodb", region_name=region or os.environ.get("AWS_REGION", "us-west-2"))
    return GovernanceCorpus(
        records=scan_table(dynamodb_client, TRACKER_TABLE),
        documents=scan_table(dynamodb_client, DOCUMENTS_TABLE),
        sessions=scan_table(dynamodb_client, AGENT_SESSIONS_TABLE),
        agent_types=scan_table(dynamodb_client, AGENT_TYPES_TABLE),
        coordination_requests=scan_table(dynamodb_client, COORDINATION_TABLE),
    )
