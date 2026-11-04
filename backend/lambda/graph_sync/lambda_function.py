"""devops-graph-sync Lambda -- DynamoDB stream consumer for Neo4j AuraDB graph index.

Triggered by SQS FIFO queue (devops-graph-sync-queue.fifo) which receives
events from an EventBridge Pipe connected to the devops-project-tracker
DynamoDB Stream.

ENC-TSK-L85: EventBridge Pipes with a DynamoDB Streams source were confirmed
account-wide non-functional (StateReason=No records processed, zero
throughput -- see ENC-ISS-497, same root cause already fixed for
search-index via ENC-TSK-L84). On gamma, CDC now runs via direct
AWS::Lambda::EventSourceMapping on the tracker and documents DynamoDB
streams (GraphSyncTrackerStreamTrigger / GraphSyncDocumentsStreamTrigger).
This handler accepts BOTH event shapes so the old SQS-fed path
(GraphSyncSqsTrigger, disabled on gamma but left enabled on prod/v3, not
deleted) and the new direct-stream path can coexist during rollback windows:
  - SQS-wrapped: event.Records[].body is a JSON string containing the raw
    DynamoDB stream record. Failure identifier = SQS messageId.
  - Direct DynamoDB Streams ESM: event.Records[] IS the raw stream record
    (eventName/dynamodb at the top level, no body/messageId). Failure
    identifier = dynamodb.SequenceNumber per the DynamoDB Streams
    ReportBatchItemFailures contract (NOT eventID).

Flow (prod/v3, unchanged):
  DynamoDB Streams -> EventBridge Pipe -> SQS FIFO -> This Lambda
  -> MERGE/DELETE Cypher operations against AuraDB Free
Flow (gamma):
  DynamoDB Streams -> Lambda EventSourceMapping (direct) -> This Lambda
  -> MERGE/DELETE Cypher operations against AuraDB Free

The graph is a READ-ONLY derived index. DynamoDB remains the sole source
of truth. Graph unavailability does NOT affect tracker mutations.

Node labels: Task, Issue, Feature, Project
Edge types: CHILD_OF, RELATED_TO, BELONGS_TO, ADDRESSES, IMPLEMENTS
           + ENC-FTR-049 typed edges: BLOCKS, BLOCKED_BY, DUPLICATES, DUPLICATED_BY,
             RELATES_TO, PARENT_OF, CHILD_OF_TYPED, DEPENDS_ON, DEPENDED_ON_BY,
             CLONES, CLONED_BY, AFFECTS, AFFECTED_BY, TESTS, TESTED_BY,
             CONSUMES_FROM, PRODUCES_FOR

Environment variables:
  NEO4J_SECRET_NAME    Secrets Manager secret ID (default: enceladus/neo4j/auradb-credentials)
  SECRETS_REGION       AWS region for Secrets Manager (default: us-west-2)
  BEDROCK_REGION       AWS region for Bedrock runtime (default: us-west-2)
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ENC-TSK-B94: Incremental Titan V2 embedding helpers. build_embedding_text,
# hash_embedding_text, compute_embedding_for_record, and the model/property
# constants are the shared contract between this incremental path and the
# ENC-TSK-B91 backfill path. Keep imports colocated with lambda_function.py
# so the helper module is packaged automatically by deploy.sh.
from embedding import (
    EMBEDDABLE_RECORD_TYPES,
    EMBEDDING_HASH_PROPERTY,
    EMBEDDING_PROPERTY,
    compute_embedding_for_record,
)

# ENC-FTR-098 / ENC-TSK-G34: pure helpers for MENTIONS edge auto-extraction
# from prose fields. The same module powers the live reconciler path
# (ENC-TSK-G35), the one-shot corpus backfill (ENC-TSK-G42), and the daily
# drift audit (ENC-TSK-G43) so all three derive identical token sets.
from mentions_extraction import (
    MENTIONS_PROSE_FIELDS as _MENTIONS_PROSE_FIELDS,
    extract_id_tokens,
    stamp_provenance,
    strip_code_fences,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# ENC-TSK-S26-0A: stream-consumer write-audit line ([WRITE-AUDIT]) + governed_lag_ms.
# Duplicated per consumer (stdlib only). One line per processed governed record
# (image carries correlation_id or version_seq). governed_lag_ms = t_projection_done
# - t_ack, where t_ack is the image's t_ack attribute when present, else the item's
# updated_at (lag_basis says which). ONE EMF metric: governed_lag_ms (Milliseconds),
# namespace Enceladus/WritePath, single dimension tool.
# ---------------------------------------------------------------------------
import datetime as _wa_dt

import graph_repo as _graph_repo  # ENC-TSK-S47-0C: batched graph transaction seam
import time as _wa_time


def _wa_val(image: Dict[str, Any], key: str) -> Any:
    v = (image or {}).get(key)
    if isinstance(v, dict):
        return v.get("S") if "S" in v else v.get("N")
    return None


def _wa_iso_ms(value: Any) -> Optional[int]:
    try:
        return int(_wa_dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def _wa_consumer_emit(
    consumer: str, raw_record: Dict[str, Any], stream_record: Optional[Dict[str, Any]],
    t_received_ms: int, t_done_ms: int, outcome: str = "success", phase: str = "projected",
    stage: Optional[Dict[str, Any]] = None,
) -> None:
    """Never raises; silent for non-governed records (no correlation_id / version_seq on the image)."""
    try:
        image = ((stream_record or {}).get("dynamodb") or {}).get("NewImage") or {}
        cid, vseq = _wa_val(image, "correlation_id"), _wa_val(image, "version_seq")
        if not image or (not cid and vseq is None):
            return
        t_ack, basis = _wa_val(image, "t_ack"), "t_ack"
        if t_ack is None:
            t_ack, basis = _wa_iso_ms(_wa_val(image, "updated_at")), "updated_at"
        t_ack = int(t_ack) if t_ack is not None else None
        lag = max(0, t_done_ms - t_ack) if t_ack is not None and phase == "projected" else None
        tool = str(_wa_val(image, "write_tool") or "unknown")
        rid = _wa_val(image, "item_id") or _wa_val(image, "document_id") or str(_wa_val(image, "record_id") or "").split("#")[-1]
        attempt = int(((raw_record or {}).get("attributes") or {}).get("ApproximateReceiveCount") or 1)
        line = {
            "consumer": consumer, "surface": consumer, "correlation_id": cid or None, "record_id": rid or None,
            "version_seq": int(vseq) if vseq is not None else None, "tool": tool, "attempt": attempt,
            "event_name": (stream_record or {}).get("eventName"), "attempt_outcome": outcome,
            "success": outcome == "success", "projection_phase": phase, "t_stream_received": t_received_ms,
            "t_projection_done": t_done_ms, "t_ack": t_ack, "lag_basis": basis if t_ack is not None else None,
            **_edge_guard_audit_fields(),  # ENC-TSK-S46-0D: edges_skipped_missing_target, edges_placeholder_targets
            "governed_lag_ms": lag,
        }
        if stage is not None:  # ENC-TSK-S46-0A: BRD 7.1 per-record stage fields (derived lags live in the query pack)
            line.update(stage)
            line["t_record_done"] = t_done_ms
            line["stream_approx_creation_ms"] = _wa_stream_creation_ms(stream_record)
        print("[WRITE-AUDIT] " + json.dumps(line, sort_keys=True, default=str), flush=True)
        if lag is not None and outcome == "success" and phase == "projected":
            print(json.dumps({
                "_aws": {"Timestamp": t_done_ms, "CloudWatchMetrics": [{
                    "Namespace": "Enceladus/WritePath", "Dimensions": [["tool"]],
                    "Metrics": [{"Name": "governed_lag_ms", "Unit": "Milliseconds"}]}]},
                "tool": tool, "governed_lag_ms": lag,
            }, sort_keys=True), flush=True)
    except Exception:  # noqa: BLE001 - audit must never break projection
        pass


def _wa_now_ms() -> int:
    return int(_wa_time.time() * 1000)


# ---------------------------------------------------------------------------
# ENC-TSK-S46-0A (BRD DOC-735D82EA6E0E 7.1): per-record stage timing on the consumer audit line.
# Stamps only (perf_counter + one dict per record); derived lags (stream_delay_ms, queue_ms,
# graph_projection_lag_ms) are computed by the query pack, never here.
# ---------------------------------------------------------------------------
_WA_COLD = True  # flips False after the first handler invocation in this container
_WA_T0 = _wa_time.perf_counter()  # module import time; init_ms = import -> first invocation (same contract as the MCP server line)
_WA_EDGE_MERGE_RE = re.compile(r"MERGE\s*\([^)]*\)\s*(?:<-|-)\s*\[")
_WA_REC: Dict[str, Any] = {}


def _wa_reset_record_stats() -> None:
    _WA_REC.update({"store_ms": 0.0, "store_calls": 0, "store_statements": 0, "edges_written": 0, "mark_ms": 0.0})


_wa_reset_record_stats()


def _wa_stream_creation_ms(stream_record: Optional[Dict[str, Any]]) -> Optional[int]:
    try:
        v = ((stream_record or {}).get("dynamodb") or {}).get("ApproximateCreationDateTime")
        return int(float(v) * 1000) if v is not None else None
    except (TypeError, ValueError):
        return None


def _wa_shard_id(raw_record: Optional[Dict[str, Any]]) -> Optional[str]:
    """DynamoDB Streams events do not carry the shard id; the stream label from eventSourceARN is the closest stable key."""
    arn = str((raw_record or {}).get("eventSourceARN") or "")
    return arn.split("/stream/", 1)[1] if "/stream/" in arn else (arn or None)


class _WaTimedTx:
    """Counts graph statements (and edge MERGEs) for this record; forwards everything else."""

    def __init__(self, tx: Any) -> None:
        self._tx = tx

    def run(self, query: Any, *args: Any, **kwargs: Any) -> Any:
        _WA_REC["store_statements"] += 1
        if isinstance(query, str) and _WA_EDGE_MERGE_RE.search(query):
            _WA_REC["edges_written"] += 1
        return self._tx.run(query, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tx, name)


class _WaTimedSession:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._s: Any = None

    def __enter__(self) -> "_WaTimedSession":
        self._s = self._ctx.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return self._ctx.__exit__(*exc)

    def _timed(self, method: str, fn: Any, args: Any, kwargs: Any) -> Any:
        t0 = _wa_time.perf_counter()
        try:
            return getattr(self._s, method)(lambda tx, *a, **k: fn(_WaTimedTx(tx), *a, **k), *args, **kwargs)
        finally:
            _WA_REC["store_calls"] += 1
            _WA_REC["store_ms"] += (_wa_time.perf_counter() - t0) * 1000.0

    def execute_write(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        return self._timed("execute_write", fn, args, kwargs)

    def execute_read(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        return self._timed("execute_read", fn, args, kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._s, name)



# ---------------------------------------------------------------------------
# ENC-TSK-S28-0E (BRD DOC-E32D0ED08473 B3/W2.3): projection_status + loop guard +
# version_seq idempotence.
#  * LOOP GUARD: a consumer-originated update (projection_status / projected_version_seq /
#    t_projected / feed_published_version_seq only) must never re-trigger a consumer. An
#    EventBridge Pipe / ESM FilterCriteria cannot compare OldImage to NewImage, so the guard
#    is in code in every stream consumer (this function is duplicated per Lambda).
#  * IDEMPOTENCE: the node stores version_seq; an image whose version_seq <= stored is skipped,
#    so duplicate / out-of-order deliveries yield ONE projection at the highest version_seq.
#  * After a successful projection the SOURCE item is flipped to projection_status="projected"
#    with a minimal conditional UpdateItem (only if projected_version_seq < this version_seq).
# ---------------------------------------------------------------------------
PROJECTION_ONLY_ATTRS = frozenset({
    "projection_status", "projected_version_seq", "t_projected", "feed_published_version_seq",
    "write_kind",  # ENC-TSK-S47-0B: marker writers flip it to "marker"; governed writes set "governed"
})
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
_s28_ddb = None


def _projection_only_diff(old_image: Optional[Dict[str, Any]], new_image: Optional[Dict[str, Any]]) -> bool:
    """True when OldImage and NewImage differ ONLY in consumer-owned projection attributes."""
    if not old_image or not new_image:
        return False
    diff = {k for k in set(old_image) | set(new_image) if old_image.get(k) != new_image.get(k)}
    return bool(diff) and diff <= PROJECTION_ONLY_ATTRS


def _image_version_seq(image: Optional[Dict[str, Any]]) -> Optional[int]:
    try:
        raw = (image or {}).get("version_seq")
        return int(raw["N"]) if isinstance(raw, dict) and "N" in raw else None
    except (TypeError, ValueError):
        return None


def _get_s28_ddb():
    global _s28_ddb
    if _s28_ddb is None:
        import boto3
        from botocore.config import Config
        _s28_ddb = boto3.client(
            "dynamodb", region_name=os.environ.get("AWS_REGION", "us-west-2"),
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _s28_ddb


def _mark_source_projected(new_image: Dict[str, Any], vseq: int, ddb: Any = None) -> bool:
    """Conditionally flip the source item to projected. Never raises; returns True when written."""
    try:
        if "document_id" in new_image and "record_id" not in new_image:
            table, key, pk = DOCUMENTS_TABLE, {"document_id": new_image["document_id"]}, "document_id"
        elif "project_id" in new_image and "record_id" in new_image:
            table, key, pk = TRACKER_TABLE, {"project_id": new_image["project_id"], "record_id": new_image["record_id"]}, "record_id"
        else:
            return False
        (ddb or _get_s28_ddb()).update_item(
            TableName=table, Key=key,
            UpdateExpression="SET projection_status = :p, projected_version_seq = :v, t_projected = :t, write_kind = :wk",
            ConditionExpression=(
                f"attribute_exists({pk}) AND version_seq = :v AND "
                "(attribute_not_exists(projected_version_seq) OR projected_version_seq < :v)"
            ),
            ExpressionAttributeValues={
                ":p": {"S": "projected"}, ":v": {"N": str(int(vseq))}, ":t": {"N": str(_wa_now_ms())},
                ":wk": {"S": "marker"},  # ENC-TSK-S47-0B: stream filter drops marker-only MODIFYs
            },
        )
        return True
    except Exception as exc:  # noqa: BLE001 - ConditionalCheckFailed = stale/duplicate; others are non-fatal
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code != "ConditionalCheckFailedException":
            logger.warning("[WARN] projection_status update failed (non-fatal): %s", exc)
        return False


def _read_node_version_seq(tx, label: str, record_id: str) -> Optional[int]:
    rec = tx.run(f"MATCH (n:{label} {{record_id: $record_id}}) RETURN n.version_seq AS v", record_id=record_id).single()
    v = rec["v"] if rec else None
    return int(v) if v is not None else None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
# ENC-TSK-L06 / B63 Phase 2 AC-6 AC-2 ("...and verified on projection"): the same shared
# HMAC secret the ID Service signs item_id_provenance with. Empty by default (inert) so a
# gamma/prod environment that hasn't wired this env var yet degrades to "verification
# skipped, not attempted" rather than erroring — this is an observability/quarantine-flag
# feature, never a hard MERGE gate (existing pre-L06 records have no provenance at all).
ID_SERVICE_HMAC_SECRET_ARN = os.environ.get("ID_SERVICE_HMAC_SECRET_ARN", "")

# ---------------------------------------------------------------------------
# Lazy singletons (cold-start cached)
# ---------------------------------------------------------------------------

_neo4j_driver = None
_secretsmanager = None


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        import boto3
        from botocore.config import Config
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


def _get_neo4j_credentials() -> Dict[str, str]:
    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=NEO4J_SECRET_NAME)
    return json.loads(resp["SecretString"])


# ---------------------------------------------------------------------------
# ENC-TSK-L06 / B63 Phase 2 AC-6 AC-2 — provenance verification on projection.
# ---------------------------------------------------------------------------

_id_hmac_key_cache: Optional[bytes] = None


def _get_id_hmac_key() -> Optional[bytes]:
    """Fetch the ID Service's HMAC signing secret, cached for the life of the execution
    environment. Returns None (never raises) when ID_SERVICE_HMAC_SECRET_ARN is unset or
    the fetch fails — verification is a best-effort observability feature, not a hard
    dependency of the sync pipeline."""
    global _id_hmac_key_cache
    if _id_hmac_key_cache is not None:
        return _id_hmac_key_cache
    if not ID_SERVICE_HMAC_SECRET_ARN:
        return None
    try:
        sm = _get_secretsmanager()
        resp = sm.get_secret_value(SecretId=ID_SERVICE_HMAC_SECRET_ARN)
        secret_string = resp.get("SecretString", "")
        try:
            parsed = json.loads(secret_string)
            if isinstance(parsed, dict) and "hmac_key" in parsed:
                secret_string = parsed["hmac_key"]
        except (ValueError, TypeError):
            pass
        _id_hmac_key_cache = secret_string.encode("utf-8")
        return _id_hmac_key_cache
    except Exception:  # noqa: BLE001 — best-effort; never blocks the sync pipeline
        logger.warning("[ID-PROVENANCE] could not fetch ID Service HMAC secret; verification skipped")
        return None


def _verify_item_id_provenance(record: Dict[str, Any]) -> None:
    """Recompute + compare item_id_provenance for a record about to be MERGEd into the
    graph. Logs (never raises, never blocks the MERGE) on mismatch or absence — pre-L06
    records have no provenance at all (expected, not an error; see AC-5 backfill/
    quarantine), and this check must stay proportionate: a warning/metric signal, not a
    hard gate that would break ingestion for the entire pre-existing dataset."""
    provenance = record.get("item_id_provenance")
    if not provenance:
        return  # No provenance stamped (pre-L06 record, or flag was OFF at create time) — silent, expected.
    key = _get_id_hmac_key()
    if key is None:
        return  # Secret not wired in this environment — verification not attempted.
    record_id = str(record.get("item_id") or _bare_id(record.get("record_id", "")))
    created_at = str(record.get("created_at") or "")
    record_type = str(record.get("record_type") or "")
    if not (record_id and created_at and record_type):
        return
    try:
        import hashlib
        import hmac as _hmac
        message = f"{record_id}||{created_at}||{record_type}".encode("utf-8")
        expected = _hmac.new(key, message, hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, str(provenance)):
            logger.warning(
                "[ID-PROVENANCE] MISMATCH for %s (record_type=%s) — stamped provenance does not "
                "match recomputed signature. Flagging for quarantine review (AC-5), not blocking sync.",
                record_id, record_type,
            )
    except Exception as exc:  # noqa: BLE001 — best-effort; never blocks the sync pipeline
        logger.warning("[ID-PROVENANCE] verification error for %s: %s", record_id, exc)


def _get_neo4j_driver():
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
        except ImportError:
            logger.error("[ERROR] neo4j driver not installed")
            return None
        creds = _get_neo4j_credentials()
        uri = creds["NEO4J_URI"]
        user = creds.get("NEO4J_USERNAME", "neo4j")
        password = creds["NEO4J_PASSWORD"]
        _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
    return _neo4j_driver


# ---------------------------------------------------------------------------
# DynamoDB deserialization
# ---------------------------------------------------------------------------

def _deser_value(ddb_val: Dict) -> Any:
    """Deserialize a single DynamoDB-typed value."""
    if "S" in ddb_val:
        return ddb_val["S"]
    if "N" in ddb_val:
        return ddb_val["N"]
    if "BOOL" in ddb_val:
        return ddb_val["BOOL"]
    if "NULL" in ddb_val:
        return None
    if "L" in ddb_val:
        return [_deser_value(v) for v in ddb_val["L"]]
    if "M" in ddb_val:
        return {k: _deser_value(v) for k, v in ddb_val["M"].items()}
    if "SS" in ddb_val:
        return list(ddb_val["SS"])
    return str(ddb_val)


def _deser_image(image: Dict) -> Dict[str, Any]:
    """Deserialize a DynamoDB stream NewImage/OldImage dict."""
    return {k: _deser_value(v) for k, v in image.items()}


def _normalize_record_for_graph(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize cross-table record identity before graph projection.

    Tracker rows key on ``record_id`` while document rows key on
    ``document_id``. The graph projection code expects ``record_id``.
    """
    normalized = dict(record or {})
    if not normalized:
        return normalized

    record_type = str(normalized.get("record_type") or "").strip()
    if not record_type and normalized.get("document_id"):
        record_type = "document"
        normalized["record_type"] = record_type

    if record_type == "document" and not normalized.get("record_id"):
        normalized["record_id"] = normalized.get("document_id", "")

    # ENC-TSK-J04 / ENC-FTR-074 Ph3: agent-identity stores carry no record_type column and
    # key on their own id field. Synthesize record_type + record_id from the id field so
    # the graph dispatch can route them. Order matters: probe each type's OWN partition-key
    # field before any foreign-key field another type might also carry. ENC-TSK-J43 added an
    # optional credential_id FK onto agent-session rows, so session_id (a session's own PK)
    # MUST be probed before credential_id (a session row now has both) -- checking
    # credential_id first misclassified every credential-bound session as an agent_credential
    # record, corrupting the real credential's Neo4j node via SET n += $props on shared field
    # names (e.g. status). Credential rows have no session_id, so this ordering is safe for
    # them; agent-type rows have neither session_id nor credential_id, so they fall through
    # correctly regardless of position.
    if not record_type:
        for id_field, synthetic_type in (
            ("session_id", "agent_session"),
            ("credential_id", "agent_credential"),
            ("agent_type_id", "agent_identity"),
        ):
            id_val = str(normalized.get(id_field) or "").strip()
            if id_val:
                normalized["record_type"] = synthetic_type
                normalized["record_id"] = id_val
                break

    return normalized


def _extract_remove_record_id(keys: Dict[str, Any], old_record: Optional[Dict[str, Any]] = None) -> str:
    """Resolve the primary ID for REMOVE events across tracker + document tables."""
    id_fields = ("record_id", "document_id", "item_id",
                 "session_id", "agent_type_id", "credential_id")
    for key_name in id_fields:
        typed = keys.get(key_name) or {}
        value = str(typed.get("S") or "").strip()
        if value:
            return value

    if old_record:
        for key_name in id_fields:
            value = str(old_record.get(key_name) or "").strip()
            if value:
                return value

    return ""


# ---------------------------------------------------------------------------
# Graph schema constants
# ---------------------------------------------------------------------------

RECORD_TYPE_TO_LABEL = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
    "plan": "Plan",  # ENC-FTR-058
    "lesson": "Lesson",  # ENC-FTR-052 / ENC-TSK-983
    "document": "Document",  # ENC-FTR-065 / ENC-PLN-014
    "generation": "Generation",  # GMF DOC-63420302EF65
    "recipe": "Recipe",  # DVP-TSK-968 / DVP-FTR-106 (projected by _project_recipe_record, not the generic path)
    "recipe_run": "RecipeRun",  # DVP-TSK-968 / DVP-FTR-106
}

# ENC-TSK-J04 / ENC-FTR-074 Ph3: agent-identity graph projection. The three identity
# stores (agent-types / agent-sessions / agent-credentials) key on their own id field and
# carry NO record_type column, so _normalize_record_for_graph synthesizes a record_type
# from the presence of the id field (see below). These are kept in a SEPARATE map from
# RECORD_TYPE_TO_LABEL so the generic tracker/document dispatch (which assumes project_id,
# title, embeddings) never accidentally picks up an agent row.
AGENT_RECORD_TYPE_TO_LABEL = {
    "agent_identity": "AgentIdentity",   # <- agent-types stream (ENC-AGT-NNN)
    "agent_session": "AgentSession",     # <- agent-sessions stream (ENC-SES-NNN)
    "agent_credential": "AgentCredential",  # <- agent-credentials stream (CRED-<hex>)
}

# The partition-key field for each agent store (the graph node's record_id).
AGENT_ID_FIELD = {
    "agent_identity": "agent_type_id",
    "agent_session": "session_id",
    "agent_credential": "credential_id",
}

# Node property sets copied onto each :Agent* node. Value-identical to the persisted
# DynamoDB item shapes in coordination_api/agent_id_alloc.py (SESSION_NODE_PROPERTIES,
# AGENT_TYPE_NODE_PROPERTIES, CREDENTIAL_NODE_PROPERTIES) plus the optional session
# credential_id binding (ENC-TSK-J04 AC#4). record_id is set separately.
AGENT_NODE_PROPERTIES = {
    "agent_identity": (
        "agent_type_id", "surface", "model", "cost_tier", "status", "usage_count",
    ),
    "agent_session": (
        "session_id", "agent_type_id", "parent_session_id", "runtime",
        "created_at", "claimed_at", "status", "credential_id",
    ),
    "agent_credential": (
        "credential_id", "agent_identity_id", "issued_at", "status",
        "revoked_at", "revoked_reason", "rotated_from",
    ),
}

# A governed tracker write stamps write_source.provider = the acting session id
# (e.g. "ENC-SES-029"). This pattern gates the generic MUTATED edge hook.
_SESSION_PROVIDER_RE = re.compile(r"^ENC-SES-[0-9A-Z]+$")

# ENC-TSK-E01 / ENC-ISS-184: ID-prefix to Neo4j label mapping for placeholder
# node creation. When a plan emits a PLAN_CONTAINS edge to an objective task
# that has not yet been projected (race window after plan.add_objective is
# called before the target task's own DDB stream event reaches graph_sync),
# we MERGE a placeholder node with the inferred label so the edge always
# lands. The target's own stream event later MERGEs by the same label and
# record_id, augmenting the placeholder with full properties without
# creating a duplicate node.
ID_PREFIX_TO_LABEL = {
    "TSK": "Task",
    "ISS": "Issue",
    "FTR": "Feature",
    "PLN": "Plan",
    "LSN": "Lesson",
    "DOC": "Document",
    "GEN": "Generation",
    "REC": "Recipe",  # DVP-TSK-968: <PROJ>-REC-NNN
    "RUN": "RecipeRun",  # DVP-TSK-968: <PROJ>-RUN-NNN
    "DPL": "DeploymentDecision",
    # ENC-TSK-J04 / ENC-FTR-074 Ph3: agent-identity graph projection. ENC-SES / ENC-AGT are
    # 3-segment ids (ENC-SES-029) so the parts[1] type_code resolves them here; CRED-<hex>
    # is a 2-segment id handled by the dedicated branch in _infer_label_from_id below.
    "SES": "AgentSession",
    "AGT": "AgentIdentity",
}


def _bare_id(record_id: str) -> str:
    """Strip 'type#' prefix from composite DynamoDB record_id.

    DynamoDB record_id: 'task#ENC-TSK-890' -> 'ENC-TSK-890'
    Bare IDs pass through unchanged.
    """
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


def _infer_label_from_id(record_id: str) -> str:
    """Infer a Neo4j node label from a bare record_id like 'ENC-TSK-C59'.

    Returns '' when the prefix is not recognised so callers can skip
    placeholder creation rather than spawning unlabelled nodes.
    Document IDs may be 'DOC-XXXX' (no project prefix); both single- and
    triple-segment IDs are handled.
    """
    if not record_id:
        return ""
    parts = record_id.split("-")
    # Document IDs: 'DOC-XXXX' (2 segments) or PROJECT-DOC-XXXX (3+)
    if parts[0].upper() == "DOC":
        return "Document"
    # ENC-TSK-F45: Component IDs use 'comp-<name>' prefix (not the 3-segment ENC-TYPE-XXX form)
    if parts[0].lower() == "comp":
        return "Component"
    # ENC-TSK-J04: Credential IDs use 'CRED-<uuid4hex>' (2-segment, no project prefix).
    if parts[0].upper() == "CRED":
        return "AgentCredential"
    if len(parts) < 2:
        return ""
    type_code = parts[1].upper()
    return ID_PREFIX_TO_LABEL.get(type_code, "")


# Properties to copy from DynamoDB record to Neo4j node
NODE_PROPERTIES = [
    "record_id", "project_id", "title", "status", "priority",
    "category", "updated_at", "created_at",
    # ENC-TSK-I07 (Dedup P3): canonical pointer on a superseded node, so
    # retrieval/triage can exclude superseded records and surface the survivor.
    "superseded_by",
    # ENC-TSK-L06 / B63 Phase 2 AC-6: projected so the signature is queryable in the graph
    # (e.g. for an operator to spot-check or for a future dashboard read), even though
    # verification itself happens in _verify_item_id_provenance before the MERGE below.
    "item_id_provenance",
]

# ENC-TSK-S05 (N5a): free-text fields projected onto governed nodes so the keyword
# (fulltext) signal sees the same text the vector signal embeds. Value = max chars.
# These are projection-only: build_embedding_text / embedding_text_hash are unchanged.
TEXT_PROJECTION_CAPS = {"intent": 1000, "description": 2000}


def _text_projection_props(record: Dict[str, Any]) -> Dict[str, str]:
    """Return capped string ``intent`` / ``description`` props; omit empty or non-string values."""
    out: Dict[str, str] = {}
    for key, cap in TEXT_PROJECTION_CAPS.items():
        val = record.get(key)
        if not isinstance(val, str):
            continue
        val = val.strip()
        if val:
            out[key] = val[:cap]
    return out


# ENC-ISS-543: terminal lifecycle values that MUST project to Neo4j on close paths.
# Matches tracker/checkout terminal sets (task->closed, feature->production/deprecated,
# plan->complete, issue->closed, etc.).
TERMINAL_STATUSES = frozenset({
    "closed", "completed", "complete", "production", "deprecated", "archived",
    "superseded",
})


def _is_terminal_status(value: Any) -> bool:
    return str(value or "").strip().lower() in TERMINAL_STATUSES


def _typed_string_field(image: Dict[str, Any], field: str) -> str:
    """Read a DynamoDB stream String ('S') field directly from a typed image."""
    typed = (image or {}).get(field) or {}
    if isinstance(typed, dict) and "S" in typed:
        return str(typed["S"]).strip()
    return ""


def _coalesce_status_for_projection(
    record: Dict[str, Any],
    old_record: Dict[str, Any],
    new_image: Dict[str, Any],
    old_image: Dict[str, Any],
) -> Dict[str, Any]:
    """Ensure ``status`` is present for Neo4j MERGE on close / checkout-release paths.

    ENC-ISS-543: close transitions are often followed within seconds by a
    checkout-release MODIFY. Neo4j uses ``SET n += $props`` which never clears
    stale properties — if ``status`` is absent from the deserialized projection
    record, the node keeps the pre-close status (one write behind canonical).
    Recover ``status`` from the typed NewImage first, then OldImage.
    """
    merged = dict(record)
    status = str(merged.get("status") or "").strip()
    if not status:
        status = _typed_string_field(new_image, "status")
    old_status = str(old_record.get("status") or _typed_string_field(old_image, "status") or "").strip()
    if not status and _is_terminal_status(old_status):
        # ENC-ISS-543 mechanism 3: checkout-release MODIFY immediately after close —
        # OldImage already reflects the terminal status even when the deserialized
        # NewImage omits ``status``.
        status = old_status
    if not status:
        status = old_status
    if status:
        merged["status"] = status

    new_status = str(merged.get("status") or "").strip()
    if new_status and (_is_terminal_status(new_status) or new_status != old_status):
        logger.info(
            "[INFO] Status projection %s -> %s (record_id=%s)",
            old_status or "<none>", new_status,
            _bare_id(str(merged.get("record_id") or merged.get("item_id") or "")),
        )
    return merged


PlaceholderRef = Tuple[str, str]


def _add_placeholder_ref(refs: Set[PlaceholderRef], label: str, raw_id: Any) -> None:
    """Add a label-qualified placeholder candidate if the id is non-empty."""
    record_id = _bare_id(str(raw_id).strip()) if raw_id is not None else ""
    if label and record_id:
        refs.add((label, record_id))


def _collect_placeholder_target_refs(record: Dict[str, Any]) -> Set[PlaceholderRef]:
    """Collect label-qualified placeholder nodes that a record may create.

    Only graph_sync branches that use placeholder MERGE participate here.
    This lets MODIFY/REMOVE flows prune stale placeholders after edges are
    removed without touching real projected nodes.
    """
    refs: Set[PlaceholderRef] = set()
    record_type = str(record.get("record_type") or "").strip()

    # ENC-TSK-S46-0D: field-projection targets guarded by _merge_placeholder.
    if record_type == "task":
        _add_placeholder_ref(refs, "Task", record.get("parent", ""))
    for rid in record.get("related_task_ids", []) or []:
        _add_placeholder_ref(refs, "Task", rid)
    for rid in record.get("related_issue_ids", []) or []:
        _add_placeholder_ref(refs, "Issue", rid)
    for rid in record.get("related_feature_ids", []) or []:
        _add_placeholder_ref(refs, "Feature", rid)
    if record_type == "generation":
        _add_placeholder_ref(refs, "Generation", record.get("parent_generation_id", ""))
    if record_type in TARGET_GENERATION_EDGE_BY_RECORD_TYPE:
        _add_placeholder_ref(refs, "Generation", record.get("target_generation", ""))

    if record_type == "plan":
        for objective_id in record.get("objectives_set", []) or []:
            obj_id = _bare_id(str(objective_id).strip()) if objective_id else ""
            _add_placeholder_ref(refs, _infer_label_from_id(obj_id), obj_id)
        for document_id in record.get("attached_documents", []) or []:
            _add_placeholder_ref(refs, "Document", document_id)
        _add_placeholder_ref(refs, "Feature", record.get("related_feature_id", ""))

    elif record_type == "lesson":
        for evidence_id in record.get("evidence_chain", []) or []:
            ev_id = _bare_id(str(evidence_id).strip()) if evidence_id else ""
            _add_placeholder_ref(refs, _infer_label_from_id(ev_id), ev_id)
        for ext in record.get("extensions", []) or []:
            if not isinstance(ext, dict):
                continue
            for evidence_id in ext.get("evidence_ids", []) or []:
                ev_id = _bare_id(str(evidence_id).strip()) if evidence_id else ""
                _add_placeholder_ref(refs, _infer_label_from_id(ev_id), ev_id)

    elif record_type == "document":
        for related_id in record.get("related_items", []) or []:
            rid = _bare_id(str(related_id).strip()) if related_id else ""
            _add_placeholder_ref(refs, _infer_label_from_id(rid), rid)
        for source_id in record.get("informed_by", []) or []:
            _add_placeholder_ref(refs, "Document", source_id)
        # ENC-TSK-C08 / ENC-FTR-064: HCE provenance placeholder targets.
        for source_id in record.get("consolidated_from", []) or []:
            _add_placeholder_ref(refs, "Document", source_id)
        proposed_by = _bare_id(str(record.get("proposed_by") or "").strip())
        if proposed_by:
            _add_placeholder_ref(refs, _infer_label_from_id(proposed_by), proposed_by)

        doc_subtype = str(record.get("document_subtype") or "").strip()
        if doc_subtype == "coe":
            src = _bare_id(str(record.get("source_incident_id") or "").strip())
            _add_placeholder_ref(refs, _infer_label_from_id(src), src)
        elif doc_subtype == "wave":
            _add_placeholder_ref(refs, "Plan", record.get("plan_anchor_id", ""))
        elif doc_subtype == "handoff":
            src = _bare_id(str(record.get("source_record_id") or "").strip())
            _add_placeholder_ref(refs, _infer_label_from_id(src), src)

    elif record_type == "relationship":
        for endpoint in (record.get("source_id", ""), record.get("target_id", "")):
            endpoint_id = _bare_id(str(endpoint).strip()) if endpoint else ""
            _add_placeholder_ref(refs, _infer_label_from_id(endpoint_id), endpoint_id)

    return refs


def _relationship_placeholder_refs_from_sk(record_id_sk: str) -> Set[PlaceholderRef]:
    """Infer placeholder endpoints from a rel# sort key when OldImage is absent."""
    refs: Set[PlaceholderRef] = set()
    parts = str(record_id_sk or "").split("#")
    if len(parts) < 4 or parts[0] != "rel":
        return refs
    for endpoint in (parts[1], parts[3]):
        endpoint_id = _bare_id(endpoint)
        _add_placeholder_ref(refs, _infer_label_from_id(endpoint_id), endpoint_id)
    return refs


def _purge_orphan_placeholders(tx, refs: Set[PlaceholderRef]) -> None:
    """Delete placeholder nodes that no longer participate in any edge."""
    for label, record_id in refs:
        tx.run(
            f"MATCH (n:{label} {{record_id: $rid}}) "
            "WHERE coalesce(n.is_placeholder, false) = true "
            "AND NOT (n)--() "
            "DETACH DELETE n",
            rid=record_id,
        )


# ---------------------------------------------------------------------------
# Cypher operations
# ---------------------------------------------------------------------------

def _upsert_node(tx, record: Dict[str, Any]) -> None:
    """MERGE a node by record_id (bare format) and set properties."""
    record_type = record.get("record_type", "")
    label = RECORD_TYPE_TO_LABEL.get(record_type)
    if not label:
        return

    record_id = _bare_id(record.get("record_id", record.get("item_id", "")))
    if not record_id:
        return

    # ENC-TSK-L06 / B63 Phase 2 AC-6 AC-2: verify (never block on) item_id_provenance
    # before projecting. Logs a warning on mismatch/absence for AC-5 quarantine review;
    # the MERGE below always proceeds regardless of the verification outcome.
    _verify_item_id_provenance(record)

    props = {k: record.get(k) for k in NODE_PROPERTIES if record.get(k) is not None}
    props["record_id"] = record_id
    if record.get("version_seq") is not None:  # ENC-TSK-S28-0E: idempotence basis
        props["version_seq"] = int(record["version_seq"])
    props.update(_text_projection_props(record))

    # ENC-ISS-543: ``SET n += $props`` alone leaves stale ``status`` when a later
    # checkout-release MODIFY omits the field from the deserialized dict. Always
    # bind terminal / lifecycle status explicitly so close transitions MERGE.
    status_val = props.get("status")
    cypher = (
        f"MERGE (n:{label} {{record_id: $record_id}}) "
        "SET n += $props "
        "SET n.is_placeholder = false"
    )
    params: Dict[str, Any] = {"record_id": record_id, "props": props}
    if status_val is not None and str(status_val).strip() != "":
        cypher += " SET n.status = $status_val"
        params["status_val"] = str(status_val).strip()
    tx.run(cypher, **params)


def _upsert_project_node(tx, project_id: str) -> None:
    """Ensure a :Project node exists."""
    tx.run(
        "MERGE (p:Project {project_id: $pid})",
        pid=project_id,
    )


# ---------------------------------------------------------------------------
# Agent-identity node + edge projection (ENC-TSK-J04 / ENC-FTR-074 Ph3)
# ---------------------------------------------------------------------------

# ENC-TSK-S46-0D / ENC-ISS-180 defect A (io decision E2): per-record edge order-guard
# counters, reset by lambda_handler before each record and read by _wa_consumer_emit.
#   edges_placeholder_targets    : placeholder target nodes the guard materialized
#                                  (target not yet projected; edge still landed).
#   edges_skipped_missing_target : edges NOT created because the target could not be
#                                  placed (unrecognised id prefix and no such node).
# A transient-retry of execute_write may count twice; the counters are a diagnostic.
_EDGE_GUARD_STATS: Dict[str, int] = {"edges_skipped_missing_target": 0, "edges_placeholder_targets": 0}


def _edge_guard_reset() -> None:
    for key in _EDGE_GUARD_STATS:
        _EDGE_GUARD_STATS[key] = 0


def _edge_guard_audit_fields() -> Dict[str, int]:
    return dict(_EDGE_GUARD_STATS)


def _result_value(result: Any, key: str) -> Any:
    """Read one column of a single-row result; None for anything not a real row."""
    try:
        row = result.single() if result is not None else None
        return row[key] if row is not None else None
    except Exception:  # noqa: BLE001 - diagnostics must never break projection
        return None


def _on_result_value(result: Any, key: str, fn: Any) -> None:
    """ENC-TSK-S47-0C: apply fn to one column now, or after commit for a staged (batched) statement."""
    if isinstance(result, _graph_repo.DeferredResult):
        result.add_callback(lambda row: fn(row.get(key) if row else None))
    else:
        fn(_result_value(result, key))


def _count_edge_rows(result: Any) -> None:
    """Count a skipped edge when an unlabelled-endpoint MERGE reports zero rows."""
    def _apply(n: Any) -> None:
        if isinstance(n, int) and not isinstance(n, bool) and n == 0:
            _EDGE_GUARD_STATS["edges_skipped_missing_target"] += 1
    _on_result_value(result, "n", _apply)


def _merge_placeholder(tx, label: str, record_id: str, project_id: Optional[str] = None) -> None:
    """The ONE placeholder convention (ENC-TSK-E01/E06, extended by ENC-TSK-S46-0D).

    MERGE a node keyed by (label, record_id) so an edge lands even when the target's own
    stream event has not projected it yet. On create it is tagged is_placeholder = true
    (plus project_id and placeholder_created_at). The target's later real projection
    (_upsert_node / _upsert_agent_node) MERGEs the same (label, record_id) key, sets its
    properties and is_placeholder = false: the placeholder is completed in place, never
    duplicated. An existing node (real or placeholder) is left untouched.
    """
    if not label or not record_id:
        return
    result = tx.run(
        f"OPTIONAL MATCH (x:{label} {{record_id: $rid}}) "
        "WITH count(x) AS existed "
        f"MERGE (n:{label} {{record_id: $rid}}) ON CREATE SET n.is_placeholder = true, "
        "n.project_id = $project_id, n.placeholder_created_at = $now "
        "RETURN existed = 0 AS created",
        rid=record_id, project_id=(project_id or None),
        now=_wa_dt.datetime.now(_wa_dt.timezone.utc).isoformat(),
    )
    def _apply(created: Any) -> None:
        if created is True:
            _EDGE_GUARD_STATS["edges_placeholder_targets"] += 1
    _on_result_value(result, "created", _apply)


def _guard_field_target(tx, expected_label: str, target_id: str, project_id: Optional[str]) -> None:
    """ENC-TSK-S46-0D order guard for a field-projection edge whose field declares the
    target label (related_task_ids -> Task, parent -> Task, target_generation -> Generation...).

    Materializes the target as a placeholder via _merge_placeholder so the following
    MATCH-based edge MERGE lands even when the target is not yet projected. When the id
    prefix names a DIFFERENT label (e.g. an issue id stored in related_task_ids) no
    wrong-label placeholder is created (it would never be completed); the typed MATCH
    then finds nothing and the edge is counted as edges_skipped_missing_target.
    """
    inferred = _infer_label_from_id(target_id)
    if inferred and inferred != expected_label:
        _EDGE_GUARD_STATS["edges_skipped_missing_target"] += 1
        return
    _merge_placeholder(tx, expected_label, target_id, project_id)


def _upsert_agent_node(tx, record: Dict[str, Any]) -> None:
    """MERGE an :AgentIdentity / :AgentSession / :AgentCredential node by its id."""
    record_type = record.get("record_type", "")
    label = AGENT_RECORD_TYPE_TO_LABEL.get(record_type)
    if not label:
        return

    id_field = AGENT_ID_FIELD[record_type]
    raw_id = str(record.get("record_id") or record.get(id_field, "")).strip()
    if not raw_id or raw_id.startswith("counter#"):
        return  # reserved monotonic-counter sentinel row
    record_id = _bare_id(raw_id)
    if not record_id:
        return

    prop_keys = AGENT_NODE_PROPERTIES[record_type]
    props = {k: record.get(k) for k in prop_keys if record.get(k) is not None}
    props["record_id"] = record_id

    tx.run(
        f"MERGE (n:{label} {{record_id: $record_id}}) "
        "SET n += $props "
        "SET n.is_placeholder = false",
        record_id=record_id, props=props,
    )


def _reconcile_agent_edges(tx, record: Dict[str, Any]) -> None:
    """Project the typed lifecycle edges for an agent record (ENC-TSK-J04 AC#3).

    AgentSession -> AUTHENTICATED_AS -> AgentIdentity   (session.agent_type_id)
    AgentSession -> TRIGGERED_BY     -> parent session  (session.parent_session_id)
    AgentCredential -> OWNED_BY      -> AgentIdentity    (credential.agent_identity_id)
    AgentCredential -> DERIVED_FROM  -> parent credential (credential.rotated_from)

    The source-endpoint fields are immutable across a record's lifetime (only status /
    revoked_* / claimed_at change), so idempotent MERGE is sufficient — no delete-and-
    recreate reconcile is needed.
    """
    record_type = record.get("record_type", "")
    label = AGENT_RECORD_TYPE_TO_LABEL.get(record_type)
    raw_id = str(record.get("record_id") or "").strip()
    if not label or not raw_id or raw_id.startswith("counter#"):
        return
    record_id = _bare_id(raw_id)
    if not record_id:
        return

    if record_type == "agent_session":
        # AUTHENTICATED_AS -> AgentIdentity
        agent_type_id = _bare_id(str(record.get("agent_type_id") or "").strip())
        if agent_type_id:
            _merge_placeholder(tx, "AgentIdentity", agent_type_id)
            tx.run(
                "MATCH (s:AgentSession {record_id: $sid}), (i:AgentIdentity {record_id: $aid}) "
                "MERGE (s)-[:AUTHENTICATED_AS]->(i)",
                sid=record_id, aid=agent_type_id,
            )
        # TRIGGERED_BY -> the triggering session/routine (parent_session_id). "root" and
        # self-references are skipped. The parent is usually another AgentSession, but the
        # placeholder is created on the label inferred from the id so a non-session trigger
        # (e.g. a Routine id with a known prefix) still lands.
        parent = _bare_id(str(record.get("parent_session_id") or "").strip())
        if parent and parent.lower() != "root" and parent != record_id:
            parent_label = _infer_label_from_id(parent) or "AgentSession"
            _merge_placeholder(tx, parent_label, parent)
            tx.run(
                f"MATCH (s:AgentSession {{record_id: $sid}}), (p:{parent_label} {{record_id: $pid}}) "
                "MERGE (s)-[:TRIGGERED_BY]->(p)",
                sid=record_id, pid=parent,
            )

    elif record_type == "agent_credential":
        # OWNED_BY -> AgentIdentity
        owner = _bare_id(str(record.get("agent_identity_id") or "").strip())
        if owner:
            _merge_placeholder(tx, "AgentIdentity", owner)
            tx.run(
                "MATCH (c:AgentCredential {record_id: $cid}), (i:AgentIdentity {record_id: $oid}) "
                "MERGE (c)-[:OWNED_BY]->(i)",
                cid=record_id, oid=owner,
            )
        # DERIVED_FROM -> parent credential (rotation lineage)
        parent_cred = _bare_id(str(record.get("rotated_from") or "").strip())
        if parent_cred and parent_cred != record_id:
            _merge_placeholder(tx, "AgentCredential", parent_cred)
            tx.run(
                "MATCH (c:AgentCredential {record_id: $cid}), (p:AgentCredential {record_id: $pid}) "
                "MERGE (c)-[:DERIVED_FROM]->(p)",
                cid=record_id, pid=parent_cred,
            )


def _project_mutated_edge(session, record: Dict[str, Any]) -> None:
    """Generic MUTATED-edge hook (ENC-TSK-J04 AC#3, "the clever one").

    Every governed tracker write stamps ``write_source.provider`` = the acting session id
    (e.g. "ENC-SES-029") on the mutated record. When that provider matches the ENC-SES
    pattern AND differs from the record's own id, MERGE a MUTATED edge from that session
    node (placeholder if not yet projected) to this record's node. Runs for ALL record
    types (tracker, document, and agent rows alike)."""
    record_id = _bare_id(str(record.get("record_id") or "").strip())
    if not record_id:
        return
    write_source = record.get("write_source")
    provider = ""
    if isinstance(write_source, dict):
        provider = str(write_source.get("provider") or "").strip()
    if not provider or not _SESSION_PROVIDER_RE.match(provider):
        return
    if provider == record_id:  # a session mutating its own row is not an interesting edge
        return

    record_type = record.get("record_type", "")
    target_label = (
        _infer_label_from_id(record_id)
        or RECORD_TYPE_TO_LABEL.get(record_type)
        or AGENT_RECORD_TYPE_TO_LABEL.get(record_type)
    )
    if not target_label:
        return

    session.execute_write(
        lambda tx: _merge_mutated_edge(tx, provider, target_label, record_id)
    )


def _merge_mutated_edge(tx, provider: str, target_label: str, record_id: str) -> None:
    """MERGE (:AgentSession {provider})-[:MUTATED]->(:target_label {record_id})."""
    _merge_placeholder(tx, "AgentSession", provider)
    _merge_placeholder(tx, target_label, record_id)
    tx.run(
        f"MATCH (s:AgentSession {{record_id: $sid}}), (t:{target_label} {{record_id: $rid}}) "
        "MERGE (s)-[:MUTATED]->(t)",
        sid=provider, rid=record_id,
    )


def _read_existing_embedding_hash(tx, label: str, record_id: str) -> str:
    """Return the current `embedding_text_hash` on the node, or '' if absent.

    Used by the incremental embedding path to short-circuit no-op MODIFY
    events (e.g. status transitions) without invoking Bedrock when the
    embedding input text has not changed.
    """
    result = tx.run(
        f"MATCH (n:{label} {{record_id: $rid}}) "
        f"RETURN n.{EMBEDDING_HASH_PROPERTY} AS h",
        rid=record_id,
    )
    record = result.single()
    if record is None:
        return ""
    hash_val = record.get("h")
    return str(hash_val) if hash_val is not None else ""


def _write_embedding(tx, label: str, record_id: str, payload: Dict[str, Any]) -> None:
    """Set `embedding` and `embedding_text_hash` on the node.

    Payload is the dict returned by `compute_embedding_for_record`:
    `{embedding: [256 floats], embedding_text_hash: str}`. The node is
    assumed to already exist (upserted by `_upsert_node` earlier in the
    same session); SET on a non-existent match is a no-op and that is
    acceptable — the next stream event will retry.
    """
    tx.run(
        f"MATCH (n:{label} {{record_id: $rid}}) "
        f"SET n.{EMBEDDING_PROPERTY} = $embedding, "
        f"    n.{EMBEDDING_HASH_PROPERTY} = $hash",
        rid=record_id,
        embedding=payload[EMBEDDING_PROPERTY],
        hash=payload[EMBEDDING_HASH_PROPERTY],
    )


def _reconcile_edges(tx, record: Dict[str, Any]) -> None:
    """Delete existing edges for node then re-create from record fields."""
    record_id = _bare_id(record.get("record_id", record.get("item_id", "")))
    record_type = record.get("record_type", "")
    label = RECORD_TYPE_TO_LABEL.get(record_type)
    if not label or not record_id:
        return

    # ENC-TSK-S33 / ENC-ISS-890: owner-scoped reconcile (spec DOC-CC14B0A7C4BC section 2).
    # A record reconcile deletes only the edges it OWNS, then re-creates them from its
    # current fields:
    #   * start-owned outgoing edges (EDGE_OWNERSHIP["start"]) of this node, and
    #   * for Plan/Document, the inverse edges this record emits INTO itself
    #     (EDGE_OWNERSHIP["end"][label]).
    # Both deletes skip relationship-record edges (r.source_id IS NOT NULL), which only
    # _delete_relationship_edge may remove. The blanket outgoing delete and the incoming
    # RELATED_TO delete that this replaces erased edges other records own (ENC-ISS-890).
    # ENC-TSK-I07 (Dedup P3): the SUPERSEDED_BY tombstone is never deleted here; the
    # explicit exclusion stays as defense in depth (it is not start-owned either).
    tx.run(
        f"MATCH (n:{label} {{record_id: $rid}})-[r]->() "
        "WHERE type(r) IN $start_owned AND type(r) <> 'SUPERSEDED_BY' "
        "AND r.source_id IS NULL DELETE r",
        rid=record_id,
        start_owned=sorted(EDGE_OWNERSHIP["start"]),
    )
    end_owned = EDGE_OWNERSHIP["end"].get(label)
    if end_owned:
        tx.run(
            f"MATCH ()-[r]->(n:{label} {{record_id: $rid}}) "
            "WHERE type(r) IN $end_owned AND type(r) <> 'SUPERSEDED_BY' "
            "AND r.source_id IS NULL DELETE r",
            rid=record_id,
            end_owned=sorted(end_owned),
        )

    project_id = record.get("project_id", "")

    # BELONGS_TO -> Project
    if project_id:
        tx.run(
            f"MATCH (n:{label}), (p:Project) "
            "WHERE n.record_id = $rid AND p.project_id = $pid "
            "MERGE (n)-[:BELONGS_TO {source: 'field'}]->(p)",
            rid=record_id, pid=project_id,
        )

    # ENC-TSK-I07 (Dedup P3): a superseded record is retired from the active
    # graph — its field-derived edges are NOT re-projected. Only BELONGS_TO
    # (audit membership) and the preserved SUPERSEDED_BY tombstone remain.
    # Inbound field edges from other records are redirected onto the canonical
    # when those records reconcile (the coalesce redirect below). Reversible:
    # un-supersession clears status, and B's next reconcile re-creates its edges.
    if record.get("status") == "superseded":
        return

    # CHILD_OF -> parent Task
    parent = _bare_id(record.get("parent", ""))
    if parent and record_type == "task":
        # ENC-TSK-S46-0D / ENC-ISS-180 A: order guard, the parent may not be projected yet.
        _guard_field_target(tx, "Task", parent, project_id)
        tx.run(
            "MATCH (child:Task), (parent:Task) "
            "WHERE child.record_id = $child_id AND parent.record_id = $parent_id "
            "MERGE (child)-[:CHILD_OF {source: 'field'}]->(parent)",
            child_id=record_id, parent_id=parent,
        )

    # RELATED_TO from related_task_ids (single directed edge, not bidirectional).
    # ENC-TSK-I07 (Dedup P3): redirect onto the canonical when the target is
    # superseded (coalesce over the in-graph SUPERSEDED_BY tombstone), so inbound
    # field edges migrate to the survivor without mutating this record's stored
    # ids — idempotent and reversible (target un-supersede restores the direct
    # edge on next reconcile). The tgt<>a guard drops degenerate self-loops.
    for related_id in record.get("related_task_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        # ENC-TSK-S46-0D / ENC-ISS-180 A: order guard. A placeholder carries no
        # SUPERSEDED_BY edge unless one was projected onto it, so the redirect still holds.
        _guard_field_target(tx, "Task", related_id, project_id)
        tx.run(
            f"MATCH (a:{label}) WHERE a.record_id = $aid "
            "MATCH (b:Task) WHERE b.record_id = $bid "
            "OPTIONAL MATCH (b)-[:SUPERSEDED_BY]->(canon) "
            "WITH a, coalesce(canon, b) AS tgt WHERE tgt.record_id <> a.record_id "
            "MERGE (a)-[:RELATED_TO {source: 'field'}]->(tgt)",
            aid=record_id, bid=related_id,
        )

    # RELATED_TO from related_issue_ids + ADDRESSES (Task->Issue) — with the same
    # ENC-TSK-I07 canonical redirect on superseded targets.
    for related_id in record.get("related_issue_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        _guard_field_target(tx, "Issue", related_id, project_id)  # ENC-TSK-S46-0D order guard
        tx.run(
            f"MATCH (a:{label}) WHERE a.record_id = $aid "
            "MATCH (b:Issue) WHERE b.record_id = $bid "
            "OPTIONAL MATCH (b)-[:SUPERSEDED_BY]->(canon) "
            "WITH a, coalesce(canon, b) AS tgt WHERE tgt.record_id <> a.record_id "
            "MERGE (a)-[:RELATED_TO {source: 'field'}]->(tgt)",
            aid=record_id, bid=related_id,
        )
        if record_type == "task":
            tx.run(
                "MATCH (t:Task) WHERE t.record_id = $tid "
                "MATCH (i:Issue) WHERE i.record_id = $iid "
                "OPTIONAL MATCH (i)-[:SUPERSEDED_BY]->(canon) "
                "WITH t, coalesce(canon, i) AS tgt WHERE tgt.record_id <> t.record_id "
                "MERGE (t)-[:ADDRESSES {source: 'field'}]->(tgt)",
                tid=record_id, iid=related_id,
            )

    # RELATED_TO from related_feature_ids + IMPLEMENTS (Task->Feature)
    # (features are not supersedable, so no canonical redirect is needed here)
    for related_id in record.get("related_feature_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        _guard_field_target(tx, "Feature", related_id, project_id)  # ENC-TSK-S46-0D order guard
        tx.run(
            f"MATCH (a:{label}), (b:Feature) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO {source: 'field'}]->(b)",
            aid=record_id, bid=related_id,
        )
        if record_type == "task":
            tx.run(
                "MATCH (t:Task), (f:Feature) "
                "WHERE t.record_id = $tid AND f.record_id = $fid "
                "MERGE (t)-[:IMPLEMENTS {source: 'field'}]->(f)",
                tid=record_id, fid=related_id,
            )

    # ENC-ISS-150 / ENC-TSK-B14: Plan-specific edge projections
    # ENC-TSK-E01 / ENC-ISS-184: emit edges via labelled-target MERGE so the
    # PLAN_CONTAINS / PLAN_ATTACHED_DOC edges land even when the target node
    # is not yet projected. The previous Cartesian MATCH pattern silently
    # produced zero rows (and zero edges) when the objective task or
    # attached document had not been processed yet by graph_sync, leaving
    # plans like ENC-PLN-016 with zero PLAN_CONTAINS edges despite a
    # populated objectives_set. Placeholder MERGE attaches a label-correct
    # node by record_id; the target's own stream event later MERGEs by the
    # same (label, record_id) pair and augments the placeholder with full
    # properties without duplicating it.
    if record_type == "plan":
        objectives_set = record.get("objectives_set", []) or []
        attached_documents = record.get("attached_documents", []) or []
        logger.info(
            "[INFO] Plan reconcile %s: objectives_set=%d attached_documents=%d",
            record_id, len(objectives_set), len(attached_documents),
        )

        # PLAN_CONTAINS -> each objective (Task/Issue/Feature)
        for obj_id in objectives_set:
            obj_id = _bare_id(obj_id) if obj_id else ""
            if not obj_id:
                continue
            target_label = _infer_label_from_id(obj_id)
            if target_label:
                # Ensure a label-correct target node exists. Placeholder is
                # idempotent with the target's own _upsert_node MERGE.
                # ENC-TSK-E06: tag new placeholders so downstream embedding +
                # coverage pipelines can filter them out; _upsert_node clears
                # the flag to false when the real record materializes.
                _merge_placeholder(tx, target_label, obj_id, project_id)
                tx.run(
                    f"MATCH (p:Plan), (t:{target_label}) "
                    "WHERE p.record_id = $pid AND t.record_id = $tid "
                    "MERGE (p)-[:PLAN_CONTAINS {source: 'field'}]->(t)",
                    pid=record_id, tid=obj_id,
                )
            else:
                # Unknown ID prefix: fall back to the legacy unlabelled
                # MATCH so we do not silently lose the edge if the prefix
                # registry is incomplete.
                logger.warning(
                    "[WARNING] Plan %s objective %s has unrecognised ID prefix; "
                    "falling back to unlabelled MATCH (edge may not land if target absent)",
                    record_id, obj_id,
                )
                _count_edge_rows(tx.run(
                    "MATCH (p:Plan), (t {record_id: $tid}) "
                    "WHERE p.record_id = $pid "
                    "MERGE (p)-[:PLAN_CONTAINS {source: 'field'}]->(t) "
                    "RETURN count(*) AS n",
                    pid=record_id, tid=obj_id,
                ))

        # PLAN_ATTACHED_DOC -> each document
        for doc_id in attached_documents:
            doc_id = str(doc_id).strip() if doc_id else ""
            if not doc_id:
                continue
            # Documents always project to the :Document label.
            # ENC-TSK-E06: tag placeholder on create.
            _merge_placeholder(tx, "Document", doc_id, project_id)
            tx.run(
                "MATCH (p:Plan), (d:Document) "
                "WHERE p.record_id = $pid AND d.record_id = $did "
                "MERGE (p)-[:PLAN_ATTACHED_DOC {source: 'field'}]->(d)",
                pid=record_id, did=doc_id,
            )
            # ENC-PLN-014 / ENC-FTR-065: inverse DOC_ATTACHED_TO_PLAN
            tx.run(
                "MATCH (p:Plan), (d:Document) "
                "WHERE p.record_id = $pid AND d.record_id = $did "
                "MERGE (d)-[:DOC_ATTACHED_TO_PLAN {source: 'field'}]->(p)",
                pid=record_id, did=doc_id,
            )

        # PLAN_IMPLEMENTS -> related feature
        feat_id = _bare_id(record.get("related_feature_id", "") or "")
        if feat_id:
            # Placeholder MERGE so the edge lands even if the Feature node
            # has not been projected yet (ENC-TSK-E01).
            # ENC-TSK-E06: tag placeholder on create.
            _merge_placeholder(tx, "Feature", feat_id, project_id)
            tx.run(
                "MATCH (p:Plan), (f:Feature) "
                "WHERE p.record_id = $pid AND f.record_id = $fid "
                "MERGE (p)-[:PLAN_IMPLEMENTS {source: 'field'}]->(f)",
                pid=record_id, fid=feat_id,
            )

    # ENC-FTR-052 / ENC-TSK-B89: Lesson edge projections.
    # Lesson records carry evidence_chain (list of tracker/document record IDs)
    # as their canonical LEARNED_FROM source plus extensions[].evidence_ids for
    # append-only extensions. Prior to ENC-TSK-B89, _reconcile_edges() had no
    # lesson branch at all, so every lesson node landed with exactly one edge
    # (BELONGS_TO->Project) and zero relationship neighbors. LEARNED_FROM edges
    # existed only for the subset of lessons whose evidence_chain entries were
    # historically backfilled into rel# DynamoDB items by ENC-TSK-C38 Phase 2;
    # any lesson created or updated after that backfill had zero LEARNED_FROM
    # edges in the graph, breaking depth-1 traversal from lessons (see
    # ENC-ISS-189 for the canonical legacy-ID manifestation).
    #
    # Fix: iterate both evidence_chain and every extension's evidence_ids,
    # dedupe, then emit (Lesson)-[:LEARNED_FROM]->(target) via the E01
    # placeholder MERGE pattern so the edge lands even when the target node is
    # not yet projected. Unrecognised ID prefixes (e.g. legacy JAP-*, MJR-*
    # records or pre-ENC-FTR-056 flat IDs) fall back to the legacy unlabelled
    # MATCH with a WARNING log line so OGTM does not silently drop the edge.
    if record_type == "lesson":
        evidence_ids_ordered: List[str] = []
        seen_ev: set = set()

        def _collect_evidence(eid: Any) -> None:
            if eid is None:
                return
            if isinstance(eid, dict):
                return
            val = _bare_id(str(eid).strip())
            if val and val not in seen_ev:
                seen_ev.add(val)
                evidence_ids_ordered.append(val)

        for ev in record.get("evidence_chain", []) or []:
            _collect_evidence(ev)
        # Extensions are append-only lesson_version increments; each carries
        # its own evidence_ids bag. Project every extension's evidence IDs as
        # additional LEARNED_FROM edges so the corpus-wide lesson graph
        # reflects the full provenance, not just the bootstrap chain.
        for ext in record.get("extensions", []) or []:
            if isinstance(ext, dict):
                for ev in ext.get("evidence_ids", []) or []:
                    _collect_evidence(ev)

        logger.info(
            "[INFO] Lesson reconcile %s: evidence_ids=%d (deduped)",
            record_id, len(evidence_ids_ordered),
        )

        for ev_id in evidence_ids_ordered:
            target_label = _infer_label_from_id(ev_id)
            if target_label:
                # Placeholder MERGE on inferred label so the edge lands even
                # when the target node has not been projected yet
                # (ENC-TSK-E01 pattern).
                # ENC-TSK-E06: tag placeholder on create.
                _merge_placeholder(tx, target_label, ev_id, project_id)
                tx.run(
                    f"MATCH (l:Lesson), (t:{target_label}) "
                    "WHERE l.record_id = $lid AND t.record_id = $tid "
                    "MERGE (l)-[:LEARNED_FROM {source: 'field'}]->(t)",
                    lid=record_id, tid=ev_id,
                )
            else:
                # Unknown/legacy ID prefix: fall back to unlabelled MATCH so
                # pre-ENC-FTR-056 legacy IDs (JAP-*, MJR-*, bare non-canonical
                # strings) still produce an edge when the target happens to
                # be present. ENC-ISS-189 documents why the warning is
                # useful for future rationalization work.
                logger.warning(
                    "[WARNING] Lesson %s evidence_id %s has unrecognised ID prefix; "
                    "falling back to unlabelled MATCH (edge may not land if target absent)",
                    record_id, ev_id,
                )
                _count_edge_rows(tx.run(
                    "MATCH (l:Lesson), (t {record_id: $tid}) "
                    "WHERE l.record_id = $lid "
                    "MERGE (l)-[:LEARNED_FROM {source: 'field'}]->(t) "
                    "RETURN count(*) AS n",
                    lid=record_id, tid=ev_id,
                ))

    # ENC-FTR-065 / ENC-PLN-014: Document edge projections
    if record_type == "document":
        doc_id = record_id  # already _bare_id-stripped at the top of the function

        # Note: BELONGS_TO -> Project is emitted by the record_type-agnostic
        # block above at lines 198-205 and fires automatically for documents
        # once RECORD_TYPE_TO_LABEL contains the "document" entry. The
        # outgoing-edge delete prelude at lines 183-194 also strips the
        # Document node's outgoing relationships before the new MERGEs run,
        # so re-running graph_sync on a backfill is idempotent.

        # RELATED_TO -> each related_items target (any node label)
        # ENC-TSK-E01: placeholder MERGE on inferred label so the edge lands
        # even when the target has not been projected yet.
        for related_id in record.get("related_items", []) or []:
            related_id = _bare_id(related_id) if related_id else ""
            if not related_id:
                continue
            target_label = _infer_label_from_id(related_id)
            if target_label:
                # ENC-TSK-E06: tag placeholder on create.
                _merge_placeholder(tx, target_label, related_id, project_id)
                tx.run(
                    f"MATCH (d:Document), (t:{target_label}) "
                    "WHERE d.record_id = $did AND t.record_id = $tid "
                    "MERGE (d)-[:RELATED_TO {source: 'field'}]->(t)",
                    did=doc_id, tid=related_id,
                )
            else:
                logger.warning(
                    "[WARNING] Document %s related_item %s has unrecognised ID prefix; "
                    "falling back to unlabelled MATCH",
                    doc_id, related_id,
                )
                _count_edge_rows(tx.run(
                    "MATCH (d:Document), (t {record_id: $tid}) "
                    "WHERE d.record_id = $did "
                    "MERGE (d)-[:RELATED_TO {source: 'field'}]->(t) "
                    "RETURN count(*) AS n",
                    did=doc_id, tid=related_id,
                ))

        # INFORMED_BY -> source document; INFORMS inverse from source -> this doc
        # ENC-TSK-E01: placeholder MERGE so edges land even if the source
        # document has not been projected yet.
        for informed_id in record.get("informed_by", []) or []:
            informed_id = _bare_id(informed_id) if informed_id else ""
            if not informed_id:
                continue
            # ENC-TSK-E06: tag placeholder on create.
            _merge_placeholder(tx, "Document", informed_id, project_id)
            tx.run(
                "MATCH (d:Document), (s:Document) "
                "WHERE d.record_id = $did AND s.record_id = $sid "
                "MERGE (d)-[:INFORMED_BY {source: 'field'}]->(s) "
                "MERGE (s)-[:INFORMS {source: 'field'}]->(d)",
                did=doc_id, sid=informed_id,
            )

        # --- Subtype-specific document edges (ENC-FTR-077) ---
        doc_subtype = record.get("document_subtype", "")

        # COE: INVESTIGATES / INVESTIGATED_BY (source_incident_id -> Issue/Task)
        if doc_subtype == "coe":
            source_incident_id = record.get("source_incident_id", "")
            if source_incident_id:
                source_incident_id = _bare_id(source_incident_id)
                target_label = _infer_label_from_id(source_incident_id)
                if target_label:
                    _merge_placeholder(tx, target_label, source_incident_id, project_id)
                    tx.run(
                        f"MATCH (d:Document), (t:{target_label}) "
                        "WHERE d.record_id = $did AND t.record_id = $target_id "
                        "MERGE (d)-[:INVESTIGATES {source: 'field'}]->(t) "
                        "MERGE (t)-[:INVESTIGATED_BY {source: 'field'}]->(d)",
                        did=doc_id, target_id=source_incident_id,
                    )
                else:
                    logger.warning(
                        "[WARNING] COE document %s source_incident_id %s has unrecognised "
                        "ID prefix; skipping INVESTIGATES edge",
                        doc_id, source_incident_id,
                    )

        # Wave: TRACKS_WAVE_OF / HAS_WAVE_DOC (plan_anchor_id -> Plan)
        if doc_subtype == "wave":
            plan_anchor_id = record.get("plan_anchor_id", "")
            if plan_anchor_id:
                plan_anchor_id = _bare_id(plan_anchor_id)
                _merge_placeholder(tx, "Plan", plan_anchor_id, project_id)
                tx.run(
                    "MATCH (d:Document), (p:Plan) "
                    "WHERE d.record_id = $did AND p.record_id = $plan_id "
                    "MERGE (d)-[:TRACKS_WAVE_OF {source: 'field'}]->(p) "
                    "MERGE (p)-[:HAS_WAVE_DOC {source: 'field'}]->(d)",
                    did=doc_id, plan_id=plan_anchor_id,
                )

        # Handoff: HANDS_OFF / HANDED_OFF_BY (source_record_id -> Task/Issue/Feature)
        if doc_subtype == "handoff":
            source_record_id = record.get("source_record_id", "")
            if source_record_id:
                source_record_id = _bare_id(source_record_id)
                target_label = _infer_label_from_id(source_record_id)
                if target_label:
                    _merge_placeholder(tx, target_label, source_record_id, project_id)
                    tx.run(
                        f"MATCH (d:Document), (t:{target_label}) "
                        "WHERE d.record_id = $did AND t.record_id = $source_rec_id "
                        "MERGE (d)-[:HANDS_OFF {source: 'field'}]->(t) "
                        "MERGE (t)-[:HANDED_OFF_BY {source: 'field'}]->(d)",
                        did=doc_id, source_rec_id=source_record_id,
                    )
                else:
                    logger.warning(
                        "[WARNING] Handoff document %s source_record_id %s has unrecognised "
                        "ID prefix; skipping HANDS_OFF edge",
                        doc_id, source_record_id,
                    )

        # ENC-TSK-C08 / ENC-FTR-064 (OGTM): HCE provenance edges.
        # CONSOLIDATED_FROM -> each source Handoff document a Lesson candidate was
        # consolidated from; CONSOLIDATES is the inverse. Placeholder MERGE so the
        # edge lands even if a source document has not yet been projected.
        for source_id in record.get("consolidated_from", []) or []:
            source_id = _bare_id(source_id) if source_id else ""
            if not source_id:
                continue
            _merge_placeholder(tx, "Document", source_id, project_id)
            tx.run(
                "MATCH (d:Document), (s:Document) "
                "WHERE d.record_id = $did AND s.record_id = $sid "
                "MERGE (d)-[:CONSOLIDATED_FROM {source: 'field'}]->(s) "
                "MERGE (s)-[:CONSOLIDATES {source: 'field'}]->(d)",
                did=doc_id, sid=source_id,
            )

        # PROPOSED_BY -> the proposer record (HCE feature / agent); PROPOSES inverse.
        proposed_by = _bare_id(str(record.get("proposed_by") or "").strip())
        if proposed_by:
            target_label = _infer_label_from_id(proposed_by)
            if target_label:
                _merge_placeholder(tx, target_label, proposed_by, project_id)
                tx.run(
                    f"MATCH (d:Document), (t:{target_label}) "
                    "WHERE d.record_id = $did AND t.record_id = $pid "
                    "MERGE (d)-[:PROPOSED_BY {source: 'field'}]->(t) "
                    "MERGE (t)-[:PROPOSES {source: 'field'}]->(d)",
                    did=doc_id, pid=proposed_by,
                )
            else:
                logger.warning(
                    "[WARNING] Document %s proposed_by %s has unrecognised ID prefix; "
                    "skipping PROPOSED_BY edge",
                    doc_id, proposed_by,
                )

    # ENC-FTR-098 / ENC-TSK-G35: MENTIONS edge auto-extraction from prose.
    # For every governed record_type with prose fields, strip fenced code
    # blocks, regex-extract Enceladus ID tokens via the Unit 2 extractor,
    # MERGE label-correct placeholder targets (ENC-TSK-E01 pattern), and
    # MERGE the directed (source)-[:MENTIONS {source: 'auto_mention',
    # extracted_from_field}]->(target) edge. The top-level outgoing-edge
    # wipe at the head of _reconcile_edges() handles diff-and-delete:
    # MENTIONS edges no longer present in the freshly-extracted set are
    # naturally pruned because every reconcile starts from a blank
    # outgoing slate. Idempotent by construction. Source: DOC-59D2295AA7FD
    # §7.2.3.
    _reconcile_mentions_edges(tx, record_type, label, record_id, record)

    # GMF: Generation edge projections (DOC-63420302EF65 §8.2)
    if record_type == "generation":
        gen_id = record_id
        # SUCCEEDS -> parent generation (lineage chain)
        parent_gen = record.get("parent_generation_id", "")
        if parent_gen:
            parent_gen = _bare_id(parent_gen)
            _guard_field_target(tx, "Generation", parent_gen, project_id)  # ENC-TSK-S46-0D order guard
            tx.run(
                "MATCH (g:Generation), (p:Generation) "
                "WHERE g.record_id = $gid AND p.record_id = $pid "
                "MERGE (g)-[:SUCCEEDS {source: 'field'}]->(p)",
                gid=gen_id, pid=parent_gen,
            )

    # GMF: target_generation edges on existing types
    if record_type in ("task", "feature", "plan", "lesson"):
        target_gen = record.get("target_generation", "")
        if target_gen:
            target_gen = _bare_id(target_gen)
            edge_type = TARGET_GENERATION_EDGE_BY_RECORD_TYPE.get(record_type, "TARGETS_GENERATION")
            label = RECORD_TYPE_TO_LABEL.get(record_type, "Task")
            _guard_field_target(tx, "Generation", target_gen, project_id)  # ENC-TSK-S46-0D order guard
            tx.run(
                f"MATCH (n:{label}), (g:Generation) "
                "WHERE n.record_id = $nid AND g.record_id = $gid "
                f"MERGE (n)-[:{edge_type} {{source: 'field'}}]->(g)",
                nid=record_id, gid=target_gen,
            )


# ---------------------------------------------------------------------------
# ENC-FTR-098 / ENC-TSK-G35: MENTIONS edge auto-extraction (prose -> graph)
# ---------------------------------------------------------------------------

def _reconcile_mentions_edges(
    tx,
    record_type: str,
    label: Optional[str],
    record_id: str,
    record: Dict[str, Any],
) -> None:
    """Emit MENTIONS edges from prose-field ID tokens on this record.

    Pulled out of _reconcile_edges() so the prose-extraction logic stays
    independently testable and the corpus backfill Lambda (ENC-TSK-G42) can
    invoke it directly. ENC-FTR-098 / ENC-TSK-G35.
    """
    fields = _MENTIONS_PROSE_FIELDS.get(record_type)
    if not fields or not label or not record_id:
        return
    project_id = record.get("project_id")

    extracted: Dict[str, Set[str]] = {}
    for field_name in fields:
        value = record.get(field_name, "")
        if not isinstance(value, str) or not value:
            continue
        cleaned = strip_code_fences(value)
        tokens = extract_id_tokens(cleaned)
        if not tokens:
            continue
        # Drop self-mentions — they clutter neighbor queries and add no
        # information to the graph.
        tokens.discard(record_id)
        if tokens:
            extracted[field_name] = tokens

    if not extracted:
        return

    total = sum(len(v) for v in extracted.values())
    logger.info(
        "[INFO] MENTIONS reconcile %s (%s): %d field(s), %d token(s)",
        record_id, record_type, len(extracted), total,
    )

    for field_name, tokens in extracted.items():
        for target_id in tokens:
            target_label = _infer_label_from_id(target_id)
            if not target_label:
                logger.warning(
                    "[WARNING] MENTIONS source %s extracted token %s with "
                    "unrecognised prefix; skipping edge",
                    record_id, target_id,
                )
                continue
            # Placeholder MERGE on inferred label (ENC-TSK-E01 + E06 pattern)
            # so the edge lands even when the target node has not yet been
            # projected.
            _merge_placeholder(tx, target_label, target_id, project_id)
            edge_props = stamp_provenance({}, field_name)
            tx.run(
                f"MATCH (s:{label}), (t:{target_label}) "
                "WHERE s.record_id = $sid AND t.record_id = $tid "
                "MERGE (s)-[r:MENTIONS]->(t) "
                "SET r.source = $source, r.extracted_from_field = $field",
                sid=record_id, tid=target_id,
                source=edge_props["source"],
                field=edge_props["extracted_from_field"],
            )


# ---------------------------------------------------------------------------
# Typed Relationship Edge Projection (ENC-FTR-049)
# ---------------------------------------------------------------------------

RELATIONSHIP_TYPE_TO_EDGE_LABEL = {
    "blocks": "BLOCKS", "blocked-by": "BLOCKED_BY",
    "duplicates": "DUPLICATES", "duplicated-by": "DUPLICATED_BY",
    # ENC-ISS-178: typed 'relates-to' projects to RELATED_TO so it converges with the
    # legacy related_*_ids projection and is visible via tracker.graphsearch
    # edge_types=['RELATED_TO']. Previously emitted 'RELATES_TO' which silently
    # diverged from the legacy label and broke OGTM end-to-end traversability.
    "relates-to": "RELATED_TO",
    "parent-of": "PARENT_OF", "child-of": "CHILD_OF_TYPED",
    "depends-on": "DEPENDS_ON", "depended-on-by": "DEPENDED_ON_BY",
    "clones": "CLONES", "cloned-by": "CLONED_BY",
    "affects": "AFFECTS", "affected-by": "AFFECTED_BY",
    "tests": "TESTS", "tested-by": "TESTED_BY",
    "consumes-from": "CONSUMES_FROM", "produces-for": "PRODUCES_FOR",
    # ENC-ISS-150 / ENC-TSK-B14: Plan edge types
    "plan-contains": "PLAN_CONTAINS",
    "plan-attached-doc": "PLAN_ATTACHED_DOC",
    "plan-implements": "PLAN_IMPLEMENTS",
    # ENC-FTR-052 / ENC-TSK-983: Lesson edge types
    "learned-from": "LEARNED_FROM", "teaches": "TEACHES",
    "supersedes": "SUPERSEDES", "superseded-by": "SUPERSEDED_BY",
    # ENC-FTR-061: Handoff edge types
    "hands-off": "HANDS_OFF", "handed-off-by": "HANDED_OFF_BY",
    # ENC-TSK-960: Coordination dispatch edge types
    "dispatches": "DISPATCHES", "dispatched-by": "DISPATCHED_BY",
    # ENC-FTR-076 / ENC-TSK-E08: Component proposal provenance
    "component-proposed-by": "COMPONENT_PROPOSED_BY",
    "proposes-component": "PROPOSES_COMPONENT",
    # ENC-PLN-014 / ENC-FTR-065: Document edge types
    "doc-attached-to-plan": "DOC_ATTACHED_TO_PLAN",  # Document -> Plan (inverse of plan-attached-doc)
    "informed-by": "INFORMED_BY",                      # Document -> Document (GDMP provenance)
    "informs": "INFORMS",                              # Document -> Document (inverse provenance)
    # ENC-FTR-077: Docstore subtype edges
    "investigates": "INVESTIGATES",                    # Document (coe) -> Issue/Task
    "investigated-by": "INVESTIGATED_BY",              # Issue/Task -> Document (coe)
    "tracks-wave-of": "TRACKS_WAVE_OF",                # Document (wave) -> Plan
    "has-wave-doc": "HAS_WAVE_DOC",                    # Plan -> Document (wave)
    # GMF: Generational Metabolism Framework (DOC-63420302EF65 §8.2)
    "succeeds": "SUCCEEDS",                            # Generation -> Generation (lineage)
    "belongs-to-generation": "BELONGS_TO_GENERATION",  # Feature -> Generation
    "synthesized-in": "SYNTHESIZED_IN",                # Lesson -> Chapter document
    "seeds-thesis-of": "SEEDS_THESIS_OF",              # Chapter document -> Generation
    "advances-generation": "ADVANCES_GENERATION",      # DeploymentDecision -> Generation
    "targets-generation": "TARGETS_GENERATION",        # Task -> Generation
    "executes-within": "EXECUTES_WITHIN",              # Plan -> Generation
    # ENC-FTR-076 v2 / ENC-TSK-F45: Component-task lifecycle edges
    "designs": "DESIGNS",                              # Component -> Task
    "designed-by": "DESIGNED_BY",                     # Task -> Component
    "implements": "IMPLEMENTS",                        # Component -> Task (IMPLEMENTS label shared with Task->Feature generic edge)
    "implemented-by": "IMPLEMENTED_BY",               # Task -> Component
    "deploys": "DEPLOYS",                              # Component -> Task
    "deployed-by": "DEPLOYED_BY",                     # Task -> Component
    # ENC-FTR-082 Phase A / AC-6 (OGTM): Pathway-telemetry traversal edge. Labels
    # must stay byte-identical to graph_query_api _ALLOWED_EDGE_TYPES (ENC-ISS-178).
    "pathway-traversed": "PATHWAY_TRAVERSED",          # observed retrieval traversal
    "traversed-by": "TRAVERSED_BY",                    # inverse
    # ENC-TSK-J04 / ENC-FTR-074 Ph3: agent identity/session/credential lifecycle edges.
    # Registered here (and byte-identically in graph_query_api._ALLOWED_EDGE_TYPES per
    # ENC-ISS-178) for OGTM traversability. These edges are emitted directly by
    # _reconcile_agent_edges / _project_mutated_edge from the agent-store streams (NOT via
    # the ENC-FTR-049 relationship-record path), but the registry keeps them queryable via
    # tracker.graphsearch and enforces the two-lambda drift guard.
    "authenticated-as": "AUTHENTICATED_AS",            # AgentSession -> AgentIdentity
    "owned-by": "OWNED_BY",                            # AgentCredential -> AgentIdentity
    "derived-from": "DERIVED_FROM",                    # AgentCredential -> parent AgentCredential
    "triggered-by": "TRIGGERED_BY",                    # AgentSession -> triggering session/routine
    "mutated": "MUTATED",                              # AgentSession -> any mutated record
    # ENC-TSK-C08 / ENC-FTR-064 (OGTM): Handoff Consolidation Engine provenance.
    # The operational path is field-projection from the candidate Document's
    # consolidated_from / proposed_by fields (see _reconcile_edges document
    # branch); these mapping entries also register the typed relationship-record
    # path for parity. Labels stay byte-identical to graph_query_api.
    "consolidated-from": "CONSOLIDATED_FROM",          # candidate -> source handoff
    "consolidates": "CONSOLIDATES",                    # inverse
    "proposed-by": "PROPOSED_BY",                      # candidate -> proposer
    "proposes": "PROPOSES",                            # inverse
    # DVP-TSK-968 / DVP-FTR-106 (RP-0 s8): recipe + recipe-run edges; labels byte-identical to graph_query_api.
    "recipe-uses-tool": "RECIPE_USES_TOOL",
    "tool-used-by-recipe": "TOOL_USED_BY_RECIPE",
    "recipe-serves-project": "RECIPE_SERVES_PROJECT",
    "project-served-by-recipe": "PROJECT_SERVED_BY_RECIPE",
    "recipe-implements-feature": "RECIPE_IMPLEMENTS_FEATURE",
    "implemented-by-recipe": "IMPLEMENTED_BY_RECIPE",
    "run-instance-of-recipe": "RUN_INSTANCE_OF_RECIPE",
    "recipe-has-run": "RECIPE_HAS_RUN",
    "run-opened-escalation": "RUN_OPENED_ESCALATION",
    "escalation-opened-by-run": "ESCALATION_OPENED_BY_RUN",
}


# GMF: record_type -> edge label for target_generation projection.
TARGET_GENERATION_EDGE_BY_RECORD_TYPE = {
    "task": "TARGETS_GENERATION",
    "feature": "BELONGS_TO_GENERATION",
    "plan": "EXECUTES_WITHIN",
    "lesson": "TARGETS_GENERATION",
}

# ENC-TSK-S33 / ENC-ISS-890 (spec DOC-CC14B0A7C4BC section 2.1): which side owns each edge
# graph_sync creates. _reconcile_edges deletes only start-owned outgoing edges of the
# reconciling node and the end-owned inverse edges that point INTO it, and only edges
# without a relationship-record marker (r.source_id IS NULL).
#   start    : emitted while the START node's own record reconciles (field projection;
#              MENTIONS carries source 'auto_mention').
#   end      : inverse edges emitted while the END node's record reconciles, keyed by label.
#   external : never touched by _reconcile_edges (agent, MUTATED, recipe families; the
#              recipe projectors do their own owner-scoped deletes).
#   Relationship-record edges (_upsert_relationship_edge) carry {source_id, target_id} and
#   are removed only by _delete_relationship_edge. Field-projection MERGEs carry
#   {source: 'field'} so they never collapse onto a relationship-record edge.
# test_edge_ownership_s33.py scans every MERGE in this module against this table.
EDGE_OWNERSHIP = {
    "start": frozenset({
        "BELONGS_TO", "CHILD_OF", "RELATED_TO", "ADDRESSES", "IMPLEMENTS",
        "PLAN_CONTAINS", "PLAN_ATTACHED_DOC", "PLAN_IMPLEMENTS",
        "LEARNED_FROM",
        "INFORMED_BY", "INVESTIGATES", "TRACKS_WAVE_OF", "HANDS_OFF",
        "CONSOLIDATED_FROM", "PROPOSED_BY",
        "SUCCEEDS", "TARGETS_GENERATION", "BELONGS_TO_GENERATION", "EXECUTES_WITHIN",
        "MENTIONS",
    }),
    "end": {
        "Plan": frozenset({"DOC_ATTACHED_TO_PLAN"}),
        "Document": frozenset({
            "INFORMS", "INVESTIGATED_BY", "HAS_WAVE_DOC", "HANDED_OFF_BY",
            "CONSOLIDATES", "PROPOSES",
        }),
    },
    "external": frozenset({
        "AUTHENTICATED_AS", "TRIGGERED_BY", "OWNED_BY", "DERIVED_FROM", "MUTATED",
        "RECIPE_SERVES_PROJECT", "PROJECT_SERVED_BY_RECIPE",
        "RECIPE_IMPLEMENTS_FEATURE", "IMPLEMENTED_BY_RECIPE",
        "RECIPE_USES_TOOL", "TOOL_USED_BY_RECIPE",
        "RUN_INSTANCE_OF_RECIPE", "RECIPE_HAS_RUN",
        "RUN_OPENED_ESCALATION", "ESCALATION_OPENED_BY_RUN",
    }),
}


def _upsert_relationship_edge(tx, record: Dict[str, Any]) -> None:
    """MERGE a typed relationship edge with properties from a DynamoDB relationship record."""
    rel_type = record.get("relationship_type", "")
    edge_label = RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel_type)
    if not edge_label:
        return

    source_id = _bare_id(record.get("source_id", ""))
    target_id = _bare_id(record.get("target_id", ""))
    if not source_id or not target_id:
        return

    props = {}
    for key in ("weight", "confidence", "reason", "provenance", "is_inverse", "created_at"):
        val = record.get(key)
        if val is not None:
            props[key] = float(val) if key in ("weight", "confidence") else val

    # ENC-TSK-F45 / ENC-TSK-E01: Ensure labeled placeholder nodes exist for both
    # endpoints so edges land even when one side (e.g. comp-* Component nodes) has
    # not yet been projected to Neo4j. Mirrors the PLAN_CONTAINS/LEARNED_FROM
    # placeholder pattern in _reconcile_edges.
    for nid in (source_id, target_id):
        n_label = _infer_label_from_id(nid)
        if n_label:
            _merge_placeholder(tx, n_label, nid, record.get("project_id"))

    cypher = (
        f"MATCH (s {{record_id: $source_id}}), (t {{record_id: $target_id}}) "
        f"MERGE (s)-[r:{edge_label} {{source_id: $source_id, target_id: $target_id}}]->(t) "
        "SET r += $props "
        "RETURN count(*) AS n"
    )
    _count_edge_rows(tx.run(cypher, source_id=source_id, target_id=target_id, props=props))


def _delete_relationship_edge(tx, record_id_sk: str) -> None:
    """Delete a typed relationship edge from Neo4j using the DynamoDB SK."""
    parts = record_id_sk.split("#")
    if len(parts) < 4 or parts[0] != "rel":
        return
    source_id = parts[1]
    rel_type = parts[2]
    target_id = parts[3]

    edge_label = RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel_type)
    if not edge_label:
        return

    cypher = (
        # ENC-TSK-S33 (spec 2.4): match only the edge this relationship record owns, so the
        # field-projection edge of the same type between the same nodes survives.
        f"MATCH (s {{record_id: $source_id}})-[r:{edge_label} "
        "{source_id: $source_id, target_id: $target_id}]->"
        "(t {record_id: $target_id}) "
        "DELETE r"
    )
    tx.run(cypher, source_id=source_id, target_id=target_id)


def _delete_node(tx, record_id: str) -> None:
    """DETACH DELETE a node by record_id across all labels."""
    # ENC-TSK-J04: include the agent-identity labels so hard-deleted agent rows (rare —
    # the stores are append-only, retire/revoke are MODIFYs) also detach cleanly.
    all_labels = list(RECORD_TYPE_TO_LABEL.values()) + list(AGENT_RECORD_TYPE_TO_LABEL.values())
    for label in all_labels:
        tx.run(
            f"MATCH (n:{label} {{record_id: $rid}}) DETACH DELETE n",
            rid=record_id,
        )


# ---------------------------------------------------------------------------
# SQS event processing
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ENC-TSK-S28-0D: audit / idempotency-marker rows are write-path bookkeeping, not records.
# Their key (project_id on the tracker table, document_id on the documents table) begins
# `audit#` or `idem#`; every stream consumer drops them before any work. A skipped record is
# consumed (never reported in batchItemFailures).
# ---------------------------------------------------------------------------
_S28_META_PREFIXES = ("audit#", "idem#")


def _is_s28_meta_row(stream_record: Any) -> bool:
    try:
        ddb = stream_record.get("dynamodb") if isinstance(stream_record.get("dynamodb"), dict) else stream_record
        for image in (ddb.get("Keys"), ddb.get("NewImage"), ddb.get("OldImage")):
            for attr in ("project_id", "document_id"):
                value = ((image or {}).get(attr) or {}).get("S")
                if isinstance(value, str) and value.startswith(_S28_META_PREFIXES):
                    return True
    except AttributeError:
        return False
    return False


def _record_source_and_identifier(raw_record: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Classify a Records[] entry as 'sqs' or 'ddb_stream' and return its
    ReportBatchItemFailures identifier (messageId for SQS, SequenceNumber for
    a direct DynamoDB Streams ESM). See ENC-TSK-L85 / ENC-TSK-L84."""
    if "body" in raw_record or "messageId" in raw_record or "messageID" in raw_record:
        message_id = raw_record.get("messageId") or raw_record.get("messageID")
        return "sqs", message_id
    # Direct DynamoDB Streams ESM: the record itself has eventName/dynamodb.
    sequence_number = (raw_record.get("dynamodb") or {}).get("SequenceNumber")
    return "ddb_stream", sequence_number


# ---------------------------------------------------------------------------
# DVP-TSK-968 part D / DVP-FTR-106 AC4: Recipe + RecipeRun graph projection (RP-0 s8)
# ---------------------------------------------------------------------------
# Edges follow the plan precedent: label-correct placeholder targets are MERGEd before
# the edge so edges land regardless of stream event order. The run node is created at
# start and only its status/gate properties change; per-step results are NEVER projected.

RECIPE_RECORD_TYPES = ("recipe", "recipe_run")


def _recipe_json(value: Any) -> Any:
    """Recipe rows store list/dict fields as JSON strings; accept either shape."""
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in ("[", "{"):
            try:
                return json.loads(text)
            except ValueError:
                return value
    return value


def _recipe_list(value: Any) -> List[str]:
    parsed = _recipe_json(value)
    if isinstance(parsed, (list, tuple, set)):
        return [str(x).strip() for x in parsed if str(x).strip()]
    return []


def _recipe_key(record_id: Any) -> str:
    """'recipe#DVP-REC-001' / 'recipe#DVP-REC-001@1.0.0' / 'recipe_run#DVP-RUN-001' -> bare id."""
    return _bare_id(str(record_id or "").strip()).split("@", 1)[0]


def _recipe_tools(definition: Any) -> List[str]:
    """Tool names a definition uses: action steps plus compensate actions (mirrors recipe_service.derive_tools)."""
    parsed = _recipe_json(definition)
    tools: Set[str] = set()
    if isinstance(parsed, dict):
        for step in parsed.get("steps") or []:
            if not isinstance(step, dict):
                continue
            if isinstance(step.get("action"), str) and step.get("type", "action") == "action":
                tools.add(step["action"])
            comp = step.get("compensate")
            if isinstance(comp, dict) and isinstance(comp.get("action"), str):
                tools.add(comp["action"])
    return sorted(tools)


def _project_recipe_head(tx, record: Dict[str, Any]) -> None:
    rec = str(record.get("recipe_id") or _recipe_key(record.get("record_id"))).strip()
    if not rec:
        return
    name = str(record.get("name") or "").strip()
    props = {
        "record_id": rec, "record_type": "recipe", "title": name or rec, "name": name,
        "status": record.get("status"), "project_id": record.get("project_id"),
        "tags": _recipe_list(record.get("tags")), "latest_published": record.get("latest_published"),
        "owner": record.get("owner"), "created_at": record.get("created_at"), "updated_at": record.get("updated_at"),
    }
    props = {k: v for k, v in props.items() if v is not None and v != ""}
    tx.run("MERGE (n:Recipe {record_id: $rid}) SET n += $props SET n.is_placeholder = false", rid=rec, props=props)
    # Reconcile the head-sourced edges from current state; RECIPE_USES_TOOL belongs to version rows.
    tx.run("MATCH (n:Recipe {record_id: $rid})-[r:RECIPE_SERVES_PROJECT|RECIPE_IMPLEMENTS_FEATURE]->() DELETE r", rid=rec)
    tx.run("MATCH ()-[r:PROJECT_SERVED_BY_RECIPE|IMPLEMENTED_BY_RECIPE]->(n:Recipe {record_id: $rid}) DELETE r", rid=rec)
    for pid in _recipe_list(record.get("project_ids")):
        tx.run(
            "MATCH (n:Recipe {record_id: $rid}) MERGE (p:Project {project_id: $pid}) "
            "MERGE (n)-[:RECIPE_SERVES_PROJECT]->(p) MERGE (p)-[:PROJECT_SERVED_BY_RECIPE]->(n)",
            rid=rec, pid=pid,
        )
    for fid in _recipe_list(record.get("related_feature_ids")):
        tx.run(
            "MATCH (n:Recipe {record_id: $rid}) MERGE (f:Feature {record_id: $fid}) "
            "ON CREATE SET f.is_placeholder = true "
            "MERGE (n)-[:RECIPE_IMPLEMENTS_FEATURE]->(f) MERGE (f)-[:IMPLEMENTED_BY_RECIPE]->(n)",
            rid=rec, fid=_bare_id(fid),
        )


def _project_recipe_version(tx, record: Dict[str, Any]) -> None:
    rec = str(record.get("recipe_id") or _recipe_key(record.get("record_id"))).strip()
    version = str(record.get("version") or "").strip()
    if not rec or not version:
        return
    retired = str(record.get("status") or "").strip().lower() == "retired"
    tools = [] if retired else _recipe_tools(record.get("definition"))
    tx.run(
        "MERGE (n:Recipe {record_id: $rid}) ON CREATE SET n.is_placeholder = true, n.project_id = $pid",
        rid=rec, pid=record.get("project_id"),
    )
    # Drop this version from edges whose tool the version no longer uses (or any, when retired).
    for edge in ("RECIPE_USES_TOOL", "TOOL_USED_BY_RECIPE"):
        pattern = (
            "(n:Recipe {record_id: $rid})-[e:RECIPE_USES_TOOL]->(t:Tool)"
            if edge == "RECIPE_USES_TOOL"
            else "(n:Recipe {record_id: $rid})<-[e:TOOL_USED_BY_RECIPE]-(t:Tool)"
        )
        tx.run(
            f"MATCH {pattern} WHERE NOT t.record_id IN $tools AND $v IN coalesce(e.versions, []) "
            "SET e.versions = [x IN e.versions WHERE x <> $v] WITH e WHERE size(e.versions) = 0 DELETE e",
            rid=rec, tools=tools, v=version,
        )
    for tool in tools:
        tx.run(
            "MATCH (n:Recipe {record_id: $rid}) "
            "MERGE (t:Tool {record_id: $tool}) ON CREATE SET t.is_placeholder = true, t.title = $tool "
            "MERGE (n)-[e:RECIPE_USES_TOOL]->(t) "
            "SET e.versions = CASE WHEN $v IN coalesce(e.versions, []) THEN e.versions ELSE coalesce(e.versions, []) + [$v] END "
            "MERGE (t)-[i:TOOL_USED_BY_RECIPE]->(n) SET i.versions = e.versions",
            rid=rec, tool=tool, v=version,
        )


def _project_recipe_run(tx, record: Dict[str, Any]) -> None:
    run_id = str(record.get("run_id") or _recipe_key(record.get("record_id"))).strip()
    if not run_id:
        return
    ref = _recipe_json(record.get("recipe_ref"))
    ref = ref if isinstance(ref, dict) else {}
    gate = _recipe_json(record.get("gate"))
    gate = gate if isinstance(gate, dict) else {}
    rec = str(ref.get("recipe_id") or "").strip()
    project_id = record.get("project_id")
    props = {
        "record_id": run_id, "record_type": "recipe_run", "title": f"{rec or 'recipe'} run {run_id}",
        "status": record.get("status"), "project_id": project_id, "recipe_id": rec,
        "recipe_version": ref.get("version"), "content_hash": ref.get("content_hash"),
        "started_by": record.get("started_by"), "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
    }
    props = {k: v for k, v in props.items() if v is not None and v != ""}
    # Only run-level facts are projected; per-step results/inputs/outputs stay in DynamoDB.
    tx.run(
        "MERGE (n:RecipeRun {record_id: $rid}) SET n += $props "
        "SET n.is_placeholder = false, n.gate_escalation_id = $gesc, n.gate_step_id = $gstep",
        rid=run_id, props=props, gesc=gate.get("escalation_id"), gstep=gate.get("step_id"),
    )
    if rec:
        tx.run(
            "MATCH (n:RecipeRun {record_id: $rid}) "
            "MERGE (r:Recipe {record_id: $rec}) ON CREATE SET r.is_placeholder = true, r.project_id = $pid "
            "MERGE (n)-[e:RUN_INSTANCE_OF_RECIPE]->(r) SET e.version = $ver, e.content_hash = $ch "
            "MERGE (r)-[i:RECIPE_HAS_RUN]->(n) SET i.version = $ver, i.content_hash = $ch",
            rid=run_id, rec=rec, pid=project_id, ver=ref.get("version"), ch=ref.get("content_hash"),
        )
    opened: Dict[str, Any] = {}
    history = _recipe_json(record.get("gate_history"))
    for entry in list(history if isinstance(history, list) else []) + [gate]:
        if isinstance(entry, dict) and entry.get("escalation_id"):
            opened[str(entry["escalation_id"])] = entry.get("step_id")
    for esc_id, step_id in opened.items():
        tx.run(
            "MATCH (n:RecipeRun {record_id: $rid}) "
            "MERGE (x:Escalation {record_id: $eid}) ON CREATE SET x.is_placeholder = true, x.project_id = $pid "
            "MERGE (n)-[e:RUN_OPENED_ESCALATION]->(x) SET e.step_id = $sid "
            "MERGE (x)-[i:ESCALATION_OPENED_BY_RUN]->(n) SET i.step_id = $sid",
            rid=run_id, eid=_bare_id(esc_id), pid=project_id, sid=step_id,
        )


def _project_recipe_record(driver, record: Dict[str, Any]) -> bool:
    """Project one recipe-family stream record. Returns False for rows that are not projected (name index rows)."""
    kind = str(record.get("record_kind") or "").strip()
    if record.get("record_type") == "recipe_run" or kind == "run":
        projector = _project_recipe_run
    elif kind == "version":
        projector = _project_recipe_version
    elif kind == "head":
        projector = _project_recipe_head
    else:
        return False
    with driver.session() as session:
        session.execute_write(lambda tx: projector(tx, record))
    return True


def _extract_stream_record(sqs_body: Dict) -> Optional[Dict]:
    """Extract the DynamoDB stream record from an SQS message body."""
    # EventBridge Pipe wraps stream records in the SQS body
    if "dynamodb" in sqs_body:
        return sqs_body
    # Sometimes the body is double-wrapped
    if isinstance(sqs_body, str):
        try:
            return json.loads(sqs_body)
        except (json.JSONDecodeError, TypeError):
            return None
    return sqs_body


def _stage_entity_record(repo, record: Dict[str, Any], record_type: str, record_id: str,
                         new_image: Dict[str, Any], incoming_vseq: Optional[int],
                         stale_placeholder_refs: Set[PlaceholderRef], event_name: str) -> None:
    """ENC-TSK-S47-0C: the entity INSERT/MODIFY projection, staged into the batch transaction.

    Same statements, same order as the per-record path in _process_record (project node,
    node upsert, owner-scoped edge reconcile incl. order-guard placeholders, placeholder purge,
    embedding, MUTATED edge); the version_seq and embedding-hash reads come from the batch's
    node-state prefetch. The projection marker and the Synced log run per record after commit.
    """
    label = RECORD_TYPE_TO_LABEL[record_type]
    bare = _bare_id(record_id)
    state = repo.node_state(label, bare)
    if incoming_vseq is not None:  # ENC-TSK-S28-0E: duplicate / out-of-order delivery -> skip
        stored_vseq = state.get("v")
        if stored_vseq is not None and incoming_vseq <= stored_vseq:
            logger.info("[INFO] Skipped stale %s %s (version_seq %s <= stored %s)",
                        record_type, record_id, incoming_vseq, stored_vseq)
            return
    staged = repo.begin_record((label, bare))
    tx = staged.capture()
    project_id = record.get("project_id", "")
    if project_id:
        _upsert_project_node(tx, project_id)
    _upsert_node(tx, record)
    _reconcile_edges(tx, record)
    if stale_placeholder_refs:
        _purge_orphan_placeholders(tx, stale_placeholder_refs)
    new_hash = None
    if record_type in EMBEDDABLE_RECORD_TYPES:  # ENC-TSK-B94: never breaks the primary projection
        try:
            record["_existing_embedding_hash"] = state.get("h") or ""
            payload = compute_embedding_for_record(record)
            if payload is not None:
                _write_embedding(staged.capture(optional=True), label, bare, payload)
                new_hash = payload[EMBEDDING_HASH_PROPERTY]
                logger.info("[INFO] Embedded %s %s (dims=%d, hash=%s)", record_type, bare,
                            len(payload[EMBEDDING_PROPERTY]), new_hash)
            else:
                logger.info("[INFO] Skipped embedding for %s %s (no-op or empty text or bedrock failure)",
                            record_type, bare)
        except Exception:
            logger.exception("[ERROR] Incremental embedding failed for %s %s; primary projection preserved",
                             record_type, record_id)
    _project_mutated_edge(_graph_repo.CaptureSession(tx), record)
    staged.guard_stats = _edge_guard_audit_fields()

    def _after_commit() -> None:
        if incoming_vseq is not None:  # ENC-TSK-S28-0E: projected marker on the source item
            _wa_m0 = _wa_time.perf_counter()
            try:
                _mark_source_projected(new_image, incoming_vseq)
            finally:
                _WA_REC["mark_ms"] += (_wa_time.perf_counter() - _wa_m0) * 1000.0
        logger.info("[INFO] Synced %s %s (event=%s, project=%s)",
                    record_type, record_id, event_name, record.get("project_id", ""))

    staged.post_commit = _after_commit
    repo.stage(staged, version_seq=record.get("version_seq"), embedding_hash=new_hash)


def _process_record(driver, stream_record: Dict) -> None:
    """Process a single DynamoDB stream record."""
    event_name = stream_record.get("eventName", "")
    dynamodb = stream_record.get("dynamodb", {})

    if event_name in ("INSERT", "MODIFY"):
        new_image = dynamodb.get("NewImage", {})
        if not new_image:
            return

        old_image = dynamodb.get("OldImage", {})
        old_record = _normalize_record_for_graph(_deser_image(old_image)) if old_image else {}
        record = _normalize_record_for_graph(_deser_image(new_image))
        if event_name == "MODIFY":
            record = _coalesce_status_for_projection(record, old_record, new_image, old_image)
        record_type = record.get("record_type", "")
        stale_placeholder_refs = _collect_placeholder_target_refs(old_record) - _collect_placeholder_target_refs(record)

        # ENC-FTR-049: Handle typed relationship records
        if record_type == "relationship":
            rel_status = record.get("status", "")
            record_id_sk = record.get("record_id", "")
            relationship_refs = (
                _collect_placeholder_target_refs(record)
                if rel_status == "archived"
                else set()
            )
            with driver.session() as session:
                if rel_status == "archived":
                    # Soft-deleted: remove edge from Neo4j projection
                    session.execute_write(lambda tx: _delete_relationship_edge(tx, record_id_sk))
                    if relationship_refs:
                        session.execute_write(lambda tx: _purge_orphan_placeholders(tx, relationship_refs))
                    logger.info(
                        "[INFO] Archived relationship edge removed from graph: %s",
                        record_id_sk,
                    )
                else:
                    session.execute_write(lambda tx: _upsert_relationship_edge(tx, record))
                    logger.info(
                        "[INFO] Synced relationship %s -> %s (%s, event=%s)",
                        record.get("source_id", ""), record.get("target_id", ""),
                        record.get("relationship_type", ""), event_name,
                    )
            return

        # ENC-TSK-J04 / ENC-FTR-074 Ph3: agent-identity node + edge projection.
        # Agent rows ride the same async pipe; they carry no project_id / title / embedding
        # so they take a dedicated branch ahead of the generic tracker/document path.
        # DVP-TSK-968 part D: recipe + recipe-run primitive projection (rows written before the
        # record_type stamp are recognised by their recipe_run# key).
        if record_type in RECIPE_RECORD_TYPES or str(record.get("record_id") or "").startswith("recipe_run#"):
            record["record_type"] = record_type or "recipe_run"
            projected = _project_recipe_record(driver, record)
            logger.info("[INFO] %s recipe-family record %s (kind=%s, event=%s)",
                        "Synced" if projected else "Skipped", record.get("record_id"), record.get("record_kind"), event_name)
            return

        if record_type in AGENT_RECORD_TYPE_TO_LABEL:
            agent_raw_id = str(record.get("record_id") or "").strip()
            if not agent_raw_id or agent_raw_id.startswith("counter#"):
                return  # skip the reserved monotonic-counter sentinel rows
            agent_record_id = _bare_id(agent_raw_id)
            with driver.session() as session:
                session.execute_write(lambda tx: _upsert_agent_node(tx, record))
                session.execute_write(lambda tx: _reconcile_agent_edges(tx, record))
                # Generic MUTATED hook applies to agent rows too (a session may mutate
                # another agent record and stamp write_source.provider).
                _project_mutated_edge(session, record)
            logger.info(
                "[INFO] Synced agent %s %s (event=%s)",
                record_type, agent_record_id, event_name,
            )
            return

        # Skip non-entity records
        if record_type not in RECORD_TYPE_TO_LABEL:
            return

        # Skip COUNTER records
        record_id = record.get("record_id", record.get("item_id", ""))
        if record_id and record_id.startswith("COUNTER-"):
            return

        incoming_vseq = _image_version_seq(new_image)
        if isinstance(driver, _graph_repo.GraphRepository) and driver.batching:  # ENC-TSK-S47-0C
            _stage_entity_record(driver, record, record_type, record_id, new_image, incoming_vseq,
                                 stale_placeholder_refs, event_name)
            return
        with driver.session() as session:
            if incoming_vseq is not None:  # ENC-TSK-S28-0E: duplicate / out-of-order delivery -> skip
                stored_vseq = session.execute_read(
                    lambda tx: _read_node_version_seq(tx, RECORD_TYPE_TO_LABEL[record_type], _bare_id(record_id))
                )
                if stored_vseq is not None and incoming_vseq <= stored_vseq:
                    logger.info("[INFO] Skipped stale %s %s (version_seq %s <= stored %s)",
                                record_type, record_id, incoming_vseq, stored_vseq)
                    return
            # Ensure project node exists
            project_id = record.get("project_id", "")
            if project_id:
                session.execute_write(lambda tx: _upsert_project_node(tx, project_id))

            session.execute_write(lambda tx: _upsert_node(tx, record))
            session.execute_write(lambda tx: _reconcile_edges(tx, record))
            if stale_placeholder_refs:
                session.execute_write(lambda tx: _purge_orphan_placeholders(tx, stale_placeholder_refs))

            # ENC-TSK-B94: Incremental Titan V2 embedding. Runs inline on the
            # already-async SQS consumer so the user-visible mutation path is
            # unaffected. Wrapped in try/except so Bedrock, IAM, or vector
            # model failures NEVER break the primary node + edge projection.
            # Skip non-embeddable record types (e.g. "generation") fast.
            if record_type in EMBEDDABLE_RECORD_TYPES:
                try:
                    bare = _bare_id(record_id)
                    label = RECORD_TYPE_TO_LABEL.get(record_type)
                    existing_hash = session.execute_read(
                        lambda tx: _read_existing_embedding_hash(tx, label, bare)
                    )
                    # Thread the existing hash into the record so the helper
                    # can short-circuit no-op MODIFY events (e.g. status
                    # transitions that do not change title/intent/description).
                    record["_existing_embedding_hash"] = existing_hash
                    payload = compute_embedding_for_record(record)
                    if payload is not None:
                        session.execute_write(
                            lambda tx: _write_embedding(tx, label, bare, payload)
                        )
                        logger.info(
                            "[INFO] Embedded %s %s (dims=%d, hash=%s)",
                            record_type, bare, len(payload[EMBEDDING_PROPERTY]),
                            payload[EMBEDDING_HASH_PROPERTY],
                        )
                    else:
                        logger.info(
                            "[INFO] Skipped embedding for %s %s (no-op or empty text or bedrock failure)",
                            record_type, bare,
                        )
                except Exception:
                    logger.exception(
                        "[ERROR] Incremental embedding failed for %s %s; "
                        "primary projection preserved",
                        record_type, record_id,
                    )

            # ENC-TSK-J04 / ENC-FTR-074 Ph3: generic MUTATED-edge hook. If this record was
            # written by an agent session (write_source.provider = ENC-SES-NNN), MERGE a
            # MUTATED edge from that session to this node. Runs after node upsert so the
            # target node already exists.
            _project_mutated_edge(session, record)

        if incoming_vseq is not None:  # ENC-TSK-S28-0E: projected marker on the source item
            _wa_m0 = _wa_time.perf_counter()
            try:
                _mark_source_projected(new_image, incoming_vseq)
            finally:
                _WA_REC["mark_ms"] += (_wa_time.perf_counter() - _wa_m0) * 1000.0
        logger.info(
            "[INFO] Synced %s %s (event=%s, project=%s)",
            record_type, record_id, event_name, record.get("project_id", ""),
        )

    elif event_name == "REMOVE":
        old_image = dynamodb.get("OldImage", {})
        old_record = _normalize_record_for_graph(_deser_image(old_image)) if old_image else {}
        keys = dynamodb.get("Keys", {})
        record_id_val = _extract_remove_record_id(keys, old_record)
        if not record_id_val:
            return

        # ENC-FTR-049: Handle relationship record removal
        if record_id_val.startswith("rel#"):
            relationship_refs = _collect_placeholder_target_refs(old_record)
            if not relationship_refs:
                relationship_refs = _relationship_placeholder_refs_from_sk(record_id_val)
            with driver.session() as session:
                session.execute_write(lambda tx: _delete_relationship_edge(tx, record_id_val))
                if relationship_refs:
                    session.execute_write(lambda tx: _purge_orphan_placeholders(tx, relationship_refs))
            logger.info("[INFO] Deleted relationship edge %s (event=REMOVE)", record_id_val)
            return

        # Extract the actual item_id from the record_id key
        # DynamoDB record_id format: "task#ENC-TSK-123" or bare "ENC-TSK-123"
        item_id = record_id_val.split("#", 1)[-1] if "#" in record_id_val else record_id_val
        stale_placeholder_refs = _collect_placeholder_target_refs(old_record)

        with driver.session() as session:
            session.execute_write(lambda tx: _delete_node(tx, item_id))
            if stale_placeholder_refs:
                session.execute_write(lambda tx: _purge_orphan_placeholders(tx, stale_placeholder_refs))

        logger.info("[INFO] Deleted node %s (event=REMOVE)", item_id)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

# ENC-TSK-S47-0C: kill switch for the batched graph transaction (default on).
_GRAPH_BATCH_TX = os.environ.get("GRAPH_SYNC_BATCH_TX", "1").strip().lower() not in ("0", "false", "off")


def _wa_prefetch_keys(records: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """(label, record_id) of the batch's entity INSERT/MODIFY records, for one node-state read.
    Best effort: a key missed here is read singly by the repository."""
    keys: List[Tuple[str, str]] = []
    for raw in records:
        try:
            src, _ident = _record_source_and_identifier(raw)
            body = raw.get("body", "{}") if src == "sqs" else raw
            if isinstance(body, str):
                body = json.loads(body)
            srec = body if isinstance(body, dict) else None  # same shape _extract_stream_record yields
            if not srec or srec.get("eventName") not in ("INSERT", "MODIFY"):
                continue
            new_image = (srec.get("dynamodb") or {}).get("NewImage") or {}
            rec = _normalize_record_for_graph(_deser_image(new_image)) if new_image else {}
            label = RECORD_TYPE_TO_LABEL.get(rec.get("record_type", ""))
            rid = _bare_id(str(rec.get("record_id", rec.get("item_id", "")) or ""))
            if label and rid and not rid.startswith("COUNTER-"):
                keys.append((label, rid))
        except Exception:  # noqa: BLE001
            continue
    return keys


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Processes DynamoDB stream records, from either the legacy SQS-fed path
    (GraphSyncSqsTrigger, prod/v3) or the direct DynamoDB Streams
    EventSourceMapping (GraphSyncTrackerStreamTrigger /
    GraphSyncDocumentsStreamTrigger, gamma -- ENC-TSK-L85). See
    _record_source_and_identifier for the shape-classification contract.

    ENC-TSK-L74: reports the Lambda partial-batch-failure contract
    (batchItemFailures) so the source retries only the records that actually
    failed. Without this, a batch response of plain HTTP 200 -- which is what
    a bare `except Exception: continue` produces regardless of per-record
    errors -- tells the source the WHOLE batch succeeded, so it deletes every
    message/record in it, including the ones that raised. Those records'
    MENTIONS edges (and any other graph writes from _process_record) are then
    silently and permanently lost, with no retry and no DLQ delivery, despite
    this function's prior comments claiming otherwise. Requires
    FunctionResponseTypes: [ReportBatchItemFailures] on the event source
    mapping (infrastructure/cloudformation/02-compute.yaml
    GraphSyncSqsTrigger / GraphSyncTrackerStreamTrigger /
    GraphSyncDocumentsStreamTrigger) for batchItemFailures to actually take
    effect."""
    global _WA_COLD
    _wa_t_batch = _wa_now_ms()  # ENC-TSK-S46-0A
    _wa_cold, _WA_COLD = _WA_COLD, False
    records = event.get("Records", [])
    if not records:
        return {"statusCode": 200, "body": "no records"}

    _wa_init_ms = round((_wa_time.perf_counter() - _WA_T0) * 1000.0, 3) if _wa_cold else 0.0
    driver = _get_neo4j_driver()
    _wa_mem = getattr(context, "memory_limit_in_mb", None)
    try:
        _wa_mem = int(_wa_mem) if _wa_mem is not None else None
    except (TypeError, ValueError):
        _wa_mem = None
    if driver is None:
        logger.error("[ERROR] Neo4j driver unavailable; failing whole batch for retry")
        # Report every record as failed so the source retries the whole batch
        # once Neo4j is reachable again, instead of deleting it and losing
        # every record's graph write. Identifier depends on event shape
        # (ENC-TSK-L85): SQS messageId, or direct-ESM SequenceNumber.
        failures = []
        for r in records:
            _source, identifier = _record_source_and_identifier(r)
            if identifier:
                failures.append({"itemIdentifier": identifier})
        return {"batchItemFailures": failures}

    processed = 0
    errors = 0
    failed_identifiers: List[str] = []

    def _wa_stage(position: int, raw: Dict[str, Any], t_rec_start: int, marker_only: bool = False,
                  basis: str = "record", fallback: bool = False) -> Dict[str, Any]:
        return {
            "store_ms_basis": basis, "batch_tx_fallback": fallback,  # ENC-TSK-S47-0C
            "t_batch_start": _wa_t_batch, "batch_size": len(records), "batch_position": position,
            "t_record_start": t_rec_start, "cold_start": _wa_cold, "init_ms": _wa_init_ms,
            "store_ms": round(_WA_REC["store_ms"], 3), "store_calls": _WA_REC["store_calls"],
            "store_statements": _WA_REC["store_statements"], "edges_written": _WA_REC["edges_written"],
            "mark_ms": round(_WA_REC["mark_ms"], 3), "marker_only_skipped": marker_only,
            "shard_id": _wa_shard_id(raw), "memory_mb": _wa_mem,
        }

    def _on_batch_commit(staged_records: List[Any]) -> None:
        """ENC-TSK-S47-0C: per-record post-commit work + audit line for each batched record."""
        nonlocal processed, errors
        saved_rec, saved_guard = dict(_WA_REC), _edge_guard_audit_fields()
        try:
            for st in staged_records:
                pos, raw, srec, t_recv, src, ident = st.meta
                _WA_REC.update({"store_ms": st.store_ms, "store_calls": st.store_calls,
                                "store_statements": st.store_statements, "mark_ms": 0.0,
                                "edges_written": sum(1 for x in st.statements if _WA_EDGE_MERGE_RE.search(x.query))})
                _EDGE_GUARD_STATS.update(st.guard_stats)
                st.resolve_results()
                if st.error is None:
                    try:
                        if st.post_commit is not None:
                            st.post_commit()
                    except Exception as exc:  # noqa: BLE001
                        st.error = exc
                stage = _wa_stage(pos, raw, t_recv, basis="record" if st.batch_tx_fallback else "batch_share",
                                  fallback=st.batch_tx_fallback)
                if st.error is None:
                    _wa_consumer_emit("graph_sync", raw, srec, t_recv, _wa_now_ms(), stage=stage)
                    continue
                processed -= 1
                errors += 1
                _wa_consumer_emit("graph_sync", raw, srec, t_recv, _wa_now_ms(), outcome="error", stage=stage)
                logger.error("[ERROR] Failed to process %s record identifier=%s: %r", src, ident, st.error)
                if not ident:
                    raise st.error  # ENC-ISS-543: fail closed
                failed_identifiers.append(ident)
        finally:
            _WA_REC.update(saved_rec)
            _EDGE_GUARD_STATS.update(saved_guard)

    # ENC-TSK-S47-0C: one repository per invocation over the module-level driver (built once per
    # container); entity upserts of the batch commit in one UNWIND transaction.
    repo = _graph_repo.Neo4jRepository(driver, session_wrapper=_WaTimedSession, on_commit=_on_batch_commit,
                                       batching=_GRAPH_BATCH_TX, state_property_hash=EMBEDDING_HASH_PROPERTY)
    if repo.batching:
        repo.prefetch_node_state(_wa_prefetch_keys(records))

    for _wa_pos, raw_record in enumerate(records):
        source, identifier = _record_source_and_identifier(raw_record)
        _wa_t_recv = _wa_now_ms()  # ENC-TSK-S26-0A
        _wa_reset_record_stats()  # ENC-TSK-S46-0A: per-record stage timing counters
        _edge_guard_reset()  # ENC-TSK-S46-0D: per-record edge order-guard counters
        stream_record = None
        try:
            if source == "sqs":
                body = raw_record.get("body", "{}")
                if isinstance(body, str):
                    body = json.loads(body)
                stream_record = _extract_stream_record(body)
            else:
                stream_record = raw_record

            if stream_record and _is_s28_meta_row(stream_record):
                continue  # ENC-TSK-S28-0D: audit/marker row, nothing to project
            if stream_record and _projection_only_diff(
                (stream_record.get("dynamodb") or {}).get("OldImage"),
                (stream_record.get("dynamodb") or {}).get("NewImage"),
            ):
                _wa_consumer_emit("graph_sync", raw_record, stream_record, _wa_t_recv, _wa_now_ms(),
                                  phase="marker_skipped", stage=_wa_stage(_wa_pos, raw_record, _wa_t_recv, True))
                continue  # ENC-TSK-S28-0E loop guard: consumer-originated projection marker write
            if stream_record and "dynamodb" in stream_record:
                _process_record(repo, stream_record)
                processed += 1
                staged = repo.take_last_staged()
                if staged is not None:  # ENC-TSK-S47-0C: audit line after the batch commit
                    staged.meta = (_wa_pos, raw_record, stream_record, _wa_t_recv, source, identifier)
                    continue
                _wa_consumer_emit("graph_sync", raw_record, stream_record, _wa_t_recv, _wa_now_ms(),
                                  stage=_wa_stage(_wa_pos, raw_record, _wa_t_recv))
        except Exception:
            errors += 1
            _wa_consumer_emit("graph_sync", raw_record, stream_record, _wa_t_recv, _wa_now_ms(), outcome="error",
                              stage=_wa_stage(_wa_pos, raw_record, _wa_t_recv))
            logger.exception("[ERROR] Failed to process %s record identifier=%s", source, identifier)
            if identifier:
                failed_identifiers.append(identifier)
            else:
                # ENC-ISS-543: a missing failure identifier silently drops the
                # record (Lambda returns 200, source deletes it). Fail closed.
                logger.error(
                    "[ERROR] %s record failed but has no batchItemFailures identifier; "
                    "raising to avoid silent graph drift",
                    source,
                )
                raise

    repo.flush()  # ENC-TSK-S47-0C: commit the batch transaction; emits the deferred audit lines
    logger.info("[INFO] Batch complete: processed=%d, errors=%d, total=%d", processed, errors, len(records))

    if failed_identifiers:
        return {"batchItemFailures": [{"itemIdentifier": fid} for fid in failed_identifiers]}

    return {"statusCode": 200, "body": json.dumps({"processed": processed, "errors": errors})}
