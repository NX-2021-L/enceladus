"""Lambda entrypoint for devops-json-to-parquet-transformer.

This function is invoked by the `on-project-json-sync` EventBridge rule for
DVP-FTR-006. It expects an EventBridge event whose `detail` (or nested
SNS `Message`) contains:

    {
        "project": "devops",
        "log_type": "issues",
        "stage_prefix": "s3://devops-agentcli-compute/projects/sync-stage/issues/project=devops/ingest_ts=202511120930/",
        "sync_run_id": "2025-11-12T14:30:00Z-devops-json-sync"
    }

The function:
  1. Lists JSON files under `stage_prefix`.
  2. Loads each file, converts it to Parquet via pyarrow.
  3. Writes the Parquet output to `projects/sync/<log_type>/project=<project>/ingest_ts=<YYYYMMDDHHMM>/`.
  4. Publishes a completion SNS message (consumed by the Glue crawler fan-out rule).
"""

from __future__ import annotations

import io
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import boto3
import pyarrow as pa
import pyarrow.parquet as pq

S3 = boto3.client("s3")
SNS = boto3.client("sns")
EVENTS = boto3.client("events")
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME", "default")
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "devops.parquet-ready")
EVENT_DETAIL_TYPE = os.environ.get("EVENT_DETAIL_TYPE", "parquet-ready")


SUPPORTED_LOG_TYPES: Sequence[str] = ("features", "tasks", "issues")
STAGE_PATH_TOKEN = "/sync-stage/"
PROJECT_PARTITION_PREFIX = "project="
INGEST_PARTITION_PREFIX = "ingest_ts="


class StagePrefixError(ValueError):
    """Raised when the stage_prefix cannot be parsed."""


def parse_s3_uri(uri: str) -> Tuple[str, str]:
    if not uri.startswith("s3://"):
        raise StagePrefixError(f"Invalid S3 URI: {uri}")
    without_scheme = uri[5:]
    if "/" not in without_scheme:
        raise StagePrefixError(f"S3 URI missing key component: {uri}")
    bucket, key = without_scheme.split("/", 1)
    return bucket, key


def ensure_trailing_slash(path: str) -> str:
    return path if path.endswith("/") else f"{path}/"


def extract_partitions(path_segments: Sequence[str]) -> Tuple[str, str]:
    project_part = next(
        (segment for segment in path_segments if segment.startswith(PROJECT_PARTITION_PREFIX)),
        None,
    )
    ingest_part = next(
        (segment for segment in path_segments if segment.startswith(INGEST_PARTITION_PREFIX)),
        None,
    )
    if not project_part or not ingest_part:
        raise StagePrefixError(
            f"stage_prefix must include {PROJECT_PARTITION_PREFIX} and {INGEST_PARTITION_PREFIX}"
        )
    return project_part, ingest_part


def convert_stage_to_dest(
    key: str,
    log_type: str,
    suffix: Optional[str],
    dest_base_prefix: str,
) -> str:
    """Convert sync-stage/... path into <dest_base_prefix>/<log_type>/project=.../ingest_ts=.../"""
    norm = ensure_trailing_slash(key)
    if STAGE_PATH_TOKEN not in norm:
        raise StagePrefixError(f"stage_prefix must contain {STAGE_PATH_TOKEN}: {key}")
    segments = [segment for segment in norm.strip("/").split("/") if segment]
    project_part, ingest_part = extract_partitions(segments)
    dest_segments = [
        dest_base_prefix.strip("/"),
        log_type,
        project_part,
        ingest_part,
    ]
    return "/".join(dest_segments) + "/"


def list_stage_objects(bucket: str, prefix: str) -> Iterable[str]:
    continuation_token = None
    while True:
        params = {"Bucket": bucket, "Prefix": prefix}
        if continuation_token:
            params["ContinuationToken"] = continuation_token
        response = S3.list_objects_v2(**params)
        for obj in response.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json"):
                yield key
        if not response.get("IsTruncated"):
            break
        continuation_token = response.get("NextContinuationToken")


def load_json_records(bucket: str, key: str) -> List[Dict[str, Any]]:
    body = S3.get_object(Bucket=bucket, Key=key)["Body"].read()
    payload = json.loads(body.decode("utf-8"))
    if isinstance(payload, list):
        return [sanitize_record(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [sanitize_record(payload)]
    raise ValueError(f"Unsupported JSON payload type in {key}: {type(payload)}")


def sanitize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Convert nested structures to JSON strings to keep Arrow schema consistent."""
    sanitized: Dict[str, Any] = {}
    for key, value in record.items():
        if isinstance(value, (dict, list)):
            sanitized[key] = json.dumps(value, sort_keys=True)
        else:
            sanitized[key] = value
    return sanitized


def write_parquet_to_buffer(records: List[Dict[str, Any]]) -> bytes:
    if not records:
        raise ValueError("No records to write to Parquet")
    # Ensure schema includes the union of keys across all rows.
    # Arrow infers schema from observed keys and may drop late-appearing fields
    # (for example `history`) if early rows do not contain them.
    all_keys = sorted({key for record in records for key in record.keys()})
    normalized_records = [{key: record.get(key) for key in all_keys} for record in records]
    table = pa.Table.from_pylist(normalized_records)
    sink = io.BytesIO()
    pq.write_table(
        table,
        sink,
        compression=os.environ.get("PARQUET_COMPRESSION", "snappy"),
        flavor="spark",
    )
    return sink.getvalue()


def upload_parquet(bucket: str, key: str, payload: bytes) -> None:
    S3.put_object(
        Bucket=bucket,
        Key=key,
        Body=payload,
        ContentType="application/octet-stream",
        ServerSideEncryption="AES256",
    )


def publish_parquet_ready(payload: Dict[str, Any]) -> None:
    topic_arn = os.environ["PARQUET_READY_TOPIC_ARN"]
    SNS.publish(
        TopicArn=topic_arn,
        Message=json.dumps(payload),
        Subject=f"Parquet ready: {payload['project']}/{payload['log_type']}",
    )


def publish_eventbridge_event(payload: Dict[str, Any]) -> None:
    EVENTS.put_events(
        Entries=[
            {
                "Source": EVENT_SOURCE,
                "DetailType": EVENT_DETAIL_TYPE,
                "Detail": json.dumps(payload),
                "EventBusName": EVENT_BUS_NAME,
            }
        ]
    )


@dataclass
class LambdaConfig:
    dest_bucket: str
    dest_base_prefix: str

    @classmethod
    def from_env(cls) -> "LambdaConfig":
        return cls(
            dest_bucket=os.environ.get("DEST_BUCKET", "devops-agentcli-compute"),
            dest_base_prefix=os.environ.get("DEST_BASE_PREFIX", "projects/sync"),
        )


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    results = []
    for message in extract_messages(event):
        results.append(process_log_type(message))
    return {"status": "OK", "results": results}


def extract_messages(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize EventBridge and SNS payloads into per-log-type work items."""
    if "Records" in event:
        normalized: List[Dict[str, Any]] = []
        for record in event["Records"]:
            sns_env = record.get("Sns") or record.get("sns")
            payload = sns_env.get("Message") if sns_env else record
            normalized.extend(expand_message(payload))
        return normalized
    detail = event.get("detail") or event
    payload = detail.get("Message", detail)
    return expand_message(payload)


def expand_message(payload: Any) -> List[Dict[str, Any]]:
    """Return a list of messages, one per log type."""
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise TypeError(f"Unsupported payload type: {type(payload)}")
    if "log_type" in payload and "stage_prefix" in payload:
        return [payload]

    stage_prefixes = payload.get("stage_prefixes") or {}
    project = payload.get("project")
    if not project:
        raise KeyError("Payload missing project field")
    sync_run_id = payload.get("sync_run_id", "unknown-sync-run")
    artifacts = payload.get("artifacts") or stage_prefixes.keys()

    messages: List[Dict[str, Any]] = []
    for log_type in artifacts:
        if log_type not in SUPPORTED_LOG_TYPES:
            continue
        prefix = stage_prefixes.get(log_type)
        if not prefix:
            continue
        messages.append(
            {
                "project": project,
                "log_type": log_type,
                "stage_prefix": prefix,
                "sync_run_id": sync_run_id,
                "sync_target_suffix": payload.get("sync_target_suffix"),
            }
        )

    if not messages:
        raise KeyError("Unable to derive log_type/stage_prefix pairs from payload")
    return messages


def process_log_type(message: Dict[str, Any]) -> Dict[str, Any]:
    project = message["project"]
    log_type = message["log_type"]
    stage_prefix_uri = message["stage_prefix"]
    sync_run_id = message.get("sync_run_id", "unknown-sync-run")
    target_suffix = message.get("sync_target_suffix")

    stage_bucket, stage_prefix = parse_s3_uri(stage_prefix_uri)
    stage_prefix = ensure_trailing_slash(stage_prefix)
    cfg = LambdaConfig.from_env()
    dest_key_prefix = convert_stage_to_dest(
        stage_prefix, log_type, target_suffix, cfg.dest_base_prefix
    )
    dest_bucket = cfg.dest_bucket

    written_files = []
    total_rows = 0
    for key in list_stage_objects(stage_bucket, stage_prefix):
        records = load_json_records(stage_bucket, key)
        if not records:
            continue
        parquet_bytes = write_parquet_to_buffer(records)
        relative = key[len(stage_prefix) :]
        filename = relative or f"{log_type}.json"
        dest_key = dest_key_prefix + filename.replace(".json", ".parquet")
        upload_parquet(dest_bucket, dest_key, parquet_bytes)
        total_rows += len(records)
        written_files.append(dest_key)

    if not written_files:
        raise FileNotFoundError(f"No JSON artifacts found under {stage_prefix_uri}")

    parquet_prefix_uri = f"s3://{dest_bucket}/{dest_key_prefix}"
    parquet_payload = {
        "project": project,
        "log_type": log_type,
        "sync_run_id": sync_run_id,
        "sync_target_suffix": target_suffix,
        "stage_prefix": stage_prefix_uri,
        "parquet_prefix": parquet_prefix_uri,
        "records_written": total_rows,
        "artifacts": written_files,
    }
    publish_parquet_ready(parquet_payload)
    publish_eventbridge_event(parquet_payload)

    return {
        "status": "OK",
        "project": project,
        "log_type": log_type,
        "records_written": total_rows,
        "parquet_prefix": parquet_prefix_uri,
        "artifacts": written_files,
    }
