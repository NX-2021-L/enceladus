#!/usr/bin/env python3
"""Submit Enceladus UI deployments to the backend deployment manager.

Designed for GitHub Actions in NX-2021-L/enceladus. It uploads the `frontend/ui/`
source tree to the configured source S3 prefix, writes a deployment request to
the backend deployment table, triggers the FIFO queue, and can wait for the
resulting deployment spec to reach a terminal state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import secrets
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

DEFAULT_PROJECT_ID = "devops"
DEFAULT_REGION = "us-west-2"
DEFAULT_DEPLOY_TABLE = "devops-deployment-manager"
DEFAULT_CONFIG_BUCKET = "jreese-net"
DEFAULT_CONFIG_PREFIX = "deploy-config"
DEFAULT_QUEUE_NAME = "devops-deploy-queue.fifo"
DEFAULT_DEPLOYMENT_TYPE = "github_public_static"
DEFAULT_SUBMITTED_BY = "github-actions"
TERMINAL_SPEC_STATUSES = {"deployed", "failed", "cancelled"}
ACTIVE_REQUEST_STATUSES = {"pending", "included"}

_DESER = TypeDeserializer()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now_compact() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _log(tag: str, message: str) -> None:
    print(f"[{tag}] {message}")


def _parse_csv(value: str) -> List[str]:
    if not value:
        return []
    return [token.strip() for token in value.split(",") if token.strip()]


def _ddb_deser(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _DESER.deserialize(v) for k, v in item.items()}


def _clients(region: str) -> Tuple[Any, Any, Any]:
    cfg = Config(retries={"max_attempts": 5, "mode": "standard"})
    ddb = boto3.client("dynamodb", region_name=region, config=cfg)
    s3 = boto3.client("s3", region_name=region, config=cfg)
    sqs = boto3.client("sqs", region_name=region, config=cfg)
    return ddb, s3, sqs


def _load_deploy_config(
    s3: Any,
    *,
    bucket: str,
    prefix: str,
    project_id: str,
) -> Dict[str, Any]:
    key = f"{prefix}/{project_id}/deploy.json"
    response = s3.get_object(Bucket=bucket, Key=key)
    return json.loads(response["Body"].read().decode("utf-8"))


def _read_project_state(
    s3: Any,
    *,
    bucket: str,
    prefix: str,
    project_id: str,
) -> str:
    key = f"{prefix}/{project_id}/state.json"
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        payload = json.loads(response["Body"].read().decode("utf-8"))
        return str(payload.get("state") or "ACTIVE").upper()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchKey":
            return "ACTIVE"
        raise


def _iter_source_files(ui_dir: Path) -> Iterable[Path]:
    skip_dirs = {".git", "node_modules", "dist", ".cache", ".vite", "coverage"}
    skip_files = {".DS_Store"}
    for path in sorted(ui_dir.rglob("*")):
        if path.is_dir():
            continue
        rel_parts = path.relative_to(ui_dir).parts
        if any(part in skip_dirs for part in rel_parts):
            continue
        if path.name in skip_files:
            continue
        yield path


def _create_source_zip(ui_dir: Path) -> Path:
    temp_dir = Path(tempfile.mkdtemp(prefix="enceladus-ui-src-"))
    zip_path = temp_dir / "ui-source.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file_path in _iter_source_files(ui_dir):
            archive.write(file_path, file_path.relative_to(ui_dir))
    return zip_path


def _upload_source_archive(
    s3: Any,
    *,
    zip_path: Path,
    bucket: str,
    prefix: str,
    run_id: str,
    sha: str,
) -> str:
    sha_short = (sha or "manual")[:12]
    run_token = run_id or "local"
    key = f"{prefix.rstrip('/')}/{_utc_now_compact()}-{run_token}-{sha_short}.zip"
    s3.upload_file(str(zip_path), bucket, key)
    return key


def _write_request(
    ddb: Any,
    *,
    table: str,
    project_id: str,
    request_id: str,
    submitted_by: str,
    change_type: str,
    deployment_type: str,
    summary: str,
    changes: List[str],
    related_record_ids: List[str],
    files_changed: List[str],
) -> None:
    now = _utc_now()
    item: Dict[str, Any] = {
        "project_id": {"S": project_id},
        "record_id": {"S": f"request#{request_id}"},
        "request_id": {"S": request_id},
        "record_type": {"S": "request"},
        "status": {"S": "pending"},
        "submitted_at": {"S": now},
        "submitted_by": {"S": submitted_by},
        "change_type": {"S": change_type},
        "deployment_type": {"S": deployment_type},
        "summary": {"S": summary[:500]},
        "changes": {"L": [{"S": value[:200]} for value in changes[:50]]},
        "related_record_ids": {"L": [{"S": rid} for rid in related_record_ids]},
    }
    if files_changed:
        item["files_changed"] = {"L": [{"S": value} for value in files_changed]}
    ddb.put_item(TableName=table, Item=item)


def _trigger_queue(sqs: Any, *, queue_name: str, project_id: str) -> str:
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    response = sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({"project_id": project_id, "trigger": "github_actions"}),
        MessageGroupId=project_id,
    )
    return str(response.get("MessageId") or "")


def _get_request(ddb: Any, *, table: str, project_id: str, request_id: str) -> Optional[Dict[str, Any]]:
    response = ddb.get_item(
        TableName=table,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"request#{request_id}"}},
    )
    item = response.get("Item")
    return _ddb_deser(item) if item else None


def _get_spec(ddb: Any, *, table: str, project_id: str, spec_id: str) -> Optional[Dict[str, Any]]:
    response = ddb.get_item(
        TableName=table,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
    )
    item = response.get("Item")
    return _ddb_deser(item) if item else None


def _wait_for_spec_id(
    ddb: Any,
    *,
    table: str,
    project_id: str,
    request_id: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> str:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        request_item = _get_request(ddb, table=table, project_id=project_id, request_id=request_id)
        if request_item:
            status = str(request_item.get("status") or "")
            spec_id = str(request_item.get("spec_id") or "")
            if spec_id:
                _log("INFO", f"Request {request_id} included in spec {spec_id} (status={status})")
                return spec_id
            if status and status not in ACTIVE_REQUEST_STATUSES:
                raise RuntimeError(f"Request {request_id} entered unexpected status: {status}")
        time.sleep(poll_seconds)
    raise TimeoutError(f"Timed out waiting for spec_id for request {request_id}")


def _wait_for_spec_terminal(
    ddb: Any,
    *,
    table: str,
    project_id: str,
    spec_id: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        spec_item = _get_spec(ddb, table=table, project_id=project_id, spec_id=spec_id)
        if spec_item:
            status = str(spec_item.get("status") or "")
            if status in TERMINAL_SPEC_STATUSES:
                _log("INFO", f"Spec {spec_id} reached terminal status: {status}")
                return spec_item
        time.sleep(poll_seconds)
    raise TimeoutError(f"Timed out waiting for terminal status on spec {spec_id}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Submit UI deploy requests from GitHub Actions to backend deployment manager.",
    )
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--deploy-table", default=DEFAULT_DEPLOY_TABLE)
    parser.add_argument("--config-bucket", default=DEFAULT_CONFIG_BUCKET)
    parser.add_argument("--config-prefix", default=DEFAULT_CONFIG_PREFIX)
    parser.add_argument("--queue-name", default=DEFAULT_QUEUE_NAME)
    parser.add_argument("--ui-dir", default="frontend/ui")
    parser.add_argument("--deployment-type", default=DEFAULT_DEPLOYMENT_TYPE)
    parser.add_argument("--change-type", choices=("patch", "minor", "major"), default="patch")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--changes", default="")
    parser.add_argument("--related-ids", default="")
    parser.add_argument("--files-changed", default="")
    parser.add_argument("--submitted-by", default=DEFAULT_SUBMITTED_BY)
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument(
        "--wait",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Wait for request->spec resolution and terminal spec status.",
    )
    parser.add_argument("--wait-timeout", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=int, default=15)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    ui_dir = Path(args.ui_dir).expanduser().resolve()
    if not ui_dir.is_dir():
        _log("ERROR", f"UI directory not found: {ui_dir}")
        return 1

    changes = _parse_csv(args.changes)
    if not changes:
        sha_short = (args.sha or "manual")[:12]
        changes = [f"GitHub Actions deployment for commit {sha_short}"]

    related_ids = _parse_csv(args.related_ids)
    files_changed = _parse_csv(args.files_changed)
    request_id = f"REQ-{_utc_now_compact()}-{secrets.token_hex(3)}"

    ddb, s3, sqs = _clients(args.region)
    try:
        deploy_config = _load_deploy_config(
            s3,
            bucket=args.config_bucket,
            prefix=args.config_prefix,
            project_id=args.project_id,
        )
    except Exception as exc:
        _log("ERROR", f"Failed to load deploy config: {exc}")
        return 1

    source_cfg = deploy_config.get("source", {})
    source_bucket = str(source_cfg.get("source_s3_bucket") or args.config_bucket)
    source_prefix = str(source_cfg.get("source_s3_prefix") or f"deploy-sources/{args.project_id}")
    project_state = _read_project_state(
        s3,
        bucket=args.config_bucket,
        prefix=args.config_prefix,
        project_id=args.project_id,
    )

    zip_path = _create_source_zip(ui_dir)
    source_key = f"{source_prefix.rstrip('/')}/DRYRUN-{zip_path.name}"
    if not args.dry_run:
        source_key = _upload_source_archive(
            s3,
            zip_path=zip_path,
            bucket=source_bucket,
            prefix=source_prefix,
            run_id=args.run_id,
            sha=args.sha,
        )

    _log("INFO", f"Prepared source archive from {ui_dir}")
    _log("INFO", f"Source key: s3://{source_bucket}/{source_key}")
    _log("INFO", f"Project state: {project_state}")

    if args.dry_run:
        payload = {
            "request_id": request_id,
            "project_id": args.project_id,
            "state": project_state,
            "deployment_type": args.deployment_type,
            "change_type": args.change_type,
            "summary": args.summary,
            "source_archive": f"s3://{source_bucket}/{source_key}",
            "changes": changes,
            "related_ids": related_ids,
            "files_changed": files_changed,
        }
        _log("DRY-RUN", json.dumps(payload, indent=2))
        return 0

    try:
        _write_request(
            ddb,
            table=args.deploy_table,
            project_id=args.project_id,
            request_id=request_id,
            submitted_by=args.submitted_by,
            change_type=args.change_type,
            deployment_type=args.deployment_type,
            summary=args.summary,
            changes=changes,
            related_record_ids=related_ids,
            files_changed=files_changed,
        )
        _log("SUCCESS", f"Wrote deployment request: {request_id}")
    except (ClientError, BotoCoreError) as exc:
        _log("ERROR", f"Failed writing deployment request: {exc}")
        return 1

    if project_state == "ACTIVE":
        try:
            message_id = _trigger_queue(sqs, queue_name=args.queue_name, project_id=args.project_id)
            _log("SUCCESS", f"Triggered deploy queue message: {message_id}")
        except (ClientError, BotoCoreError) as exc:
            _log("ERROR", f"Failed to trigger deploy queue: {exc}")
            return 1
    else:
        _log("WARNING", "Project state is PAUSED. Request is queued but not triggered.")
        return 0

    if not args.wait:
        return 0

    try:
        spec_id = _wait_for_spec_id(
            ddb,
            table=args.deploy_table,
            project_id=args.project_id,
            request_id=request_id,
            timeout_seconds=args.wait_timeout,
            poll_seconds=args.poll_seconds,
        )
        spec_item = _wait_for_spec_terminal(
            ddb,
            table=args.deploy_table,
            project_id=args.project_id,
            spec_id=spec_id,
            timeout_seconds=args.wait_timeout,
            poll_seconds=args.poll_seconds,
        )
    except Exception as exc:
        _log("ERROR", str(exc))
        return 1

    status = str(spec_item.get("status") or "")
    _log("INFO", f"Final spec status: {status}")
    _log(
        "INFO",
        json.dumps(
            {
                "request_id": request_id,
                "spec_id": spec_item.get("spec_id"),
                "resolved_version": spec_item.get("resolved_version"),
                "deployment_type": spec_item.get("deployment_type"),
                "status": status,
                "error_message": spec_item.get("error_message"),
            },
            indent=2,
        ),
    )

    if status != "deployed":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
