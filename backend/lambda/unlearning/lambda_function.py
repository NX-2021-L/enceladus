"""FTR-106 / ENC-TSK-K03 — nightly unlearning Lambda handler."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3

from unlearning_core import (
    UNLEARNING_MUTATION_ENABLED,
    build_candidate_report_body,
    build_tombstone,
    fetch_high_spurious_waves,
    identify_candidates_from_traces,
    is_dry_run,
    list_expired_tombstone_keys,
    mutation_allowed,
    stable_report_doc_id,
    tombstone_s3_key,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_ddb = None
_s3 = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb")
    return _ddb


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


DRIFT_TELEMETRY_TABLE = os.environ.get("DRIFT_TELEMETRY_TABLE", "")
STIGMERGIC_TRACE_TABLE = os.environ.get("STIGMERGIC_TRACE_TABLE", "")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "")
UNLEARNING_BUCKET = os.environ.get("UNLEARNING_BUCKET", "")
UNLEARNING_PREFIX = os.environ.get("UNLEARNING_PREFIX", "unlearning-tombstones")
STATE_PREFIX = os.environ.get("UNLEARNING_STATE_PREFIX", "unlearning-state")
DEFAULT_PROJECT_ID = os.environ.get("DEFAULT_PROJECT_ID", "enceladus")


def _iso_cutoff(hours: int) -> str:
    when = datetime.now(timezone.utc) - timedelta(hours=hours)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _load_run_counter() -> int:
    if not UNLEARNING_BUCKET:
        return 0
    key = f"{STATE_PREFIX.strip().strip('/')}/run_counter.json"
    try:
        resp = _get_s3().get_object(Bucket=UNLEARNING_BUCKET, Key=key)
        payload = json.loads(resp["Body"].read().decode("utf-8"))
        return int(payload.get("run_count") or 0)
    except Exception:
        return 0


def _save_run_counter(run_count: int) -> None:
    if not UNLEARNING_BUCKET:
        return
    key = f"{STATE_PREFIX.strip().strip('/')}/run_counter.json"
    _get_s3().put_object(
        Bucket=UNLEARNING_BUCKET,
        Key=key,
        Body=json.dumps({"run_count": run_count}).encode("utf-8"),
        ContentType="application/json",
    )


def _scan_recent_traces(project_id: str, cutoff_iso: str) -> List[Dict[str, Any]]:
    if not STIGMERGIC_TRACE_TABLE:
        return []
    traces: List[Dict[str, Any]] = []
    params: Dict[str, Any] = {
        "TableName": STIGMERGIC_TRACE_TABLE,
        "IndexName": "project-timestamp-index",
        "KeyConditionExpression": "project_id = :pid AND #ts >= :cut",
        "ExpressionAttributeNames": {"#ts": "timestamp"},
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":cut": {"S": cutoff_iso},
        },
    }
    while True:
        resp = _get_ddb().query(**params)
        for item in resp.get("Items") or []:
            traces.append(
                {
                    "record_id_path": item.get("record_id_path", {}).get("S"),
                    "outcome_signal": item.get("outcome_signal", {}).get("S"),
                    "timestamp": item.get("timestamp", {}).get("S"),
                }
            )
        if not resp.get("LastEvaluatedKey"):
            break
        params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return traces


def _get_tracker_snapshot(record_id: str) -> Dict[str, Any]:
    if not TRACKER_TABLE:
        return {}
    resp = _get_ddb().get_item(
        TableName=TRACKER_TABLE,
        Key={"record_id": {"S": record_id}},
    )
    item = resp.get("Item") or {}
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if "S" in v:
            out[k] = v["S"]
        elif "N" in v:
            out[k] = v["N"]
        elif "BOOL" in v:
            out[k] = v["BOOL"]
    return out


def _archive_reference_record(record_id: str) -> bool:
    """Archive eligible reference records — graph_sync removes Neo4j projection."""
    snap = _get_tracker_snapshot(record_id)
    if not snap:
        return False
    if str(snap.get("record_type") or "") != "reference":
        logger.info("skip archive %s: record_type=%s", record_id, snap.get("record_type"))
        return False
    if str(snap.get("status") or "") == "archived":
        return False
    _get_ddb().update_item(
        TableName=TRACKER_TABLE,
        Key={"record_id": {"S": record_id}},
        UpdateExpression="SET #st = :archived, unlearning_archived_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":archived": {"S": "archived"},
            ":ts": {"S": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
        },
    )
    return True


def _write_tombstone(record_id: str, snapshot: Dict[str, Any]) -> str:
    tomb = build_tombstone(record_id, snapshot)
    key = tombstone_s3_key(UNLEARNING_PREFIX, record_id, tomb["created_at"])
    _get_s3().put_object(
        Bucket=UNLEARNING_BUCKET,
        Key=key,
        Body=json.dumps(tomb, default=str).encode("utf-8"),
        ContentType="application/json",
    )
    return key


def _put_candidate_report(
    project_id: str,
    body: str,
    *,
    run_id: str,
) -> str:
    doc_id = stable_report_doc_id(project_id, run_id)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if not DOCUMENTS_TABLE:
        logger.info("UNLEARNING_REPORT %s", body[:500])
        return doc_id
    _get_ddb().put_item(
        TableName=DOCUMENTS_TABLE,
        Item={
            "document_id": {"S": doc_id},
            "project_id": {"S": project_id},
            "document_subtype": {"S": "report"},
            "subtypepattern": {"S": "unlearning-candidate"},
            "title": {"S": f"Unlearning candidates {run_id}"},
            "status": {"S": "draft"},
            "created_at": {"S": now},
            "updated_at": {"S": now},
            "full_description": {"S": body},
        },
    )
    return doc_id


def _hard_delete_expired_tombstones(dry_run: bool) -> List[str]:
    if not UNLEARNING_BUCKET:
        return []

    def _list(prefix: str):
        token = None
        while True:
            kwargs: Dict[str, Any] = {"Bucket": UNLEARNING_BUCKET, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = _get_s3().list_objects_v2(**kwargs)
            for obj in resp.get("Contents") or []:
                yield obj["Key"]
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")

    def _get(key: str) -> str:
        return _get_s3().get_object(Bucket=UNLEARNING_BUCKET, Key=key)["Body"].read().decode(
            "utf-8"
        )

    expired = list_expired_tombstone_keys(_list, UNLEARNING_PREFIX, get_object=_get)
    if dry_run:
        return expired
    for key in expired:
        _get_s3().delete_object(Bucket=UNLEARNING_BUCKET, Key=key)
    return expired


def lambda_handler(event: Optional[Dict[str, Any]], context: Any) -> Dict[str, Any]:
    event = event or {}
    project_id = str(event.get("project_id") or DEFAULT_PROJECT_ID)
    dry_run = is_dry_run(event)
    run_count = _load_run_counter()
    run_id = str(event.get("run_id") or uuid.uuid4().hex[:12])

    from unlearning_core import LOOKBACK_HOURS

    cutoff = _iso_cutoff(LOOKBACK_HOURS)
    hot_waves = fetch_high_spurious_waves(
        _get_ddb(),
        table_name=DRIFT_TELEMETRY_TABLE,
        project_id=project_id,
        cutoff_iso=cutoff,
    )
    traces = _scan_recent_traces(project_id, cutoff)
    candidates = identify_candidates_from_traces(traces, hot_waves=hot_waves)

    allow_mutate = mutation_allowed(
        run_count=run_count,
        dry_run=dry_run,
        mutation_enabled=UNLEARNING_MUTATION_ENABLED,
    )

    report_body = build_candidate_report_body(
        project_id,
        candidates,
        run_count=run_count,
        dry_run=dry_run,
        mutation_enabled=UNLEARNING_MUTATION_ENABLED,
    )
    report_doc_id = _put_candidate_report(project_id, report_body, run_id=run_id)

    archived: List[str] = []
    tombstones: List[str] = []
    if allow_mutate:
        for cand in candidates:
            rid = str(cand.get("record_id") or "")
            if not rid:
                continue
            snap = _get_tracker_snapshot(rid)
            tombstones.append(_write_tombstone(rid, snap))
            if _archive_reference_record(rid):
                archived.append(rid)

    expired_deleted = _hard_delete_expired_tombstones(dry_run=dry_run)

    if not dry_run:
        _save_run_counter(run_count + 1)

    result = {
        "status": "ok",
        "project_id": project_id,
        "run_id": run_id,
        "run_count": run_count,
        "dry_run": dry_run,
        "mutation_allowed": allow_mutate,
        "hot_wave_count": len(hot_waves),
        "candidate_count": len(candidates),
        "report_doc_id": report_doc_id,
        "archived_record_ids": archived,
        "tombstone_keys": tombstones,
        "expired_tombstones_deleted": expired_deleted,
    }
    logger.info("UNLEARNING_RUN %s", json.dumps(result, default=str))
    return result
