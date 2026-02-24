"""deploy_finalize/lambda_function.py

EventBridge-triggered Lambda that finalizes deployments after CodeBuild completes.

Triggered by EventBridge rule on CodeBuild Build State Change events
(SUCCEEDED or FAILED) for the devops-ui-deploy-builder project.

On SUCCESS:
  - Update deployment spec status to "deployed"
  - Create deploy audit record in devops-deployment-manager
  - Write [DEPLOYMENT] worklog entries to all related records in devops-project-tracker
  - Mark included requests as "included" (confirmed)

On FAILURE:
  - Update deployment spec status to "failed" with error message
  - Reset included requests back to "pending" for retry

Environment variables:
    DEPLOY_TABLE           default: devops-deployment-manager
    TRACKER_TABLE          default: devops-project-tracker
    DEPLOY_REGION          default: us-west-2
    PROJECTS_TABLE         default: projects
    WORKLOG_PREFIX         default: [DEPLOYMENT]
    CONFIG_BUCKET          default: jreese-net
    CONFIG_PREFIX          default: deploy-config

Related: DVP-FTR-028, DVP-TSK-323
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Set

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from boto3.dynamodb.types import TypeDeserializer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DEPLOY_REGION = os.environ.get("DEPLOY_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
WORKLOG_PREFIX = os.environ.get("WORKLOG_PREFIX", "[DEPLOYMENT]")
CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "jreese-net")
CONFIG_PREFIX = os.environ.get("CONFIG_PREFIX", "deploy-config")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_deser = TypeDeserializer()

# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

_ddb = None
_s3 = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DEPLOY_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3", region_name=DEPLOY_REGION)
    return _s3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ddb_deser(item: Dict) -> Dict[str, Any]:
    return {k: _deser.deserialize(v) for k, v in item.items()}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now_compact() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# Prefix-to-project cache
_prefix_to_project: Dict[str, str] = {}


def _load_prefix_map() -> None:
    """Load prefix -> project_id mapping from projects table."""
    if _prefix_to_project:
        return
    try:
        ddb = _get_ddb()
        resp = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id, prefix",
        )
        for item in resp.get("Items", []):
            pid = item.get("project_id", {}).get("S", "")
            pfx = item.get("prefix", {}).get("S", "")
            if pid and pfx:
                _prefix_to_project[pfx] = pid
    except Exception:
        logger.warning("Failed to load prefix map", exc_info=True)


def _infer_record_type(record_id: str) -> Optional[str]:
    """Infer DynamoDB record_type from item ID like DVP-TSK-074."""
    m = re.match(r"^[A-Z]{3}-(TSK|FTR|ISS)-\d{3}", record_id)
    if not m:
        return None
    return {"TSK": "task", "FTR": "feature", "ISS": "issue"}.get(m.group(1))


def _infer_project_id(record_id: str) -> Optional[str]:
    """Infer project_id from record prefix like DVP -> devops."""
    m = re.match(r"^([A-Z]{3})-", record_id)
    if not m:
        return None
    _load_prefix_map()
    return _prefix_to_project.get(m.group(1))


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _handle_success(project_id: str, spec_id: str, build_id: str, build_duration: int) -> None:
    """Handle a successful CodeBuild completion."""
    logger.info(f"[START] Finalizing successful deployment: {spec_id}")
    ddb = _get_ddb()

    # Read the spec
    resp = ddb.get_item(
        TableName=DEPLOY_TABLE,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
    )
    if "Item" not in resp:
        logger.error(f"Spec {spec_id} not found in DDB")
        return

    spec = _ddb_deser(resp["Item"])
    now = _utc_now()

    # Update spec status to deployed
    ddb.update_item(
        TableName=DEPLOY_TABLE,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
        UpdateExpression="SET #st = :deployed, completed_at = :now",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":deployed": {"S": "deployed"},
            ":now": {"S": now},
        },
    )
    logger.info(f"[INFO] Spec {spec_id} status updated to 'deployed'")

    # Create deploy audit record
    deploy_id = f"DEP-{_utc_now_compact()}"
    version = spec.get("resolved_version", "?")
    previous_version = spec.get("previous_version", "?")
    change_type = spec.get("resolved_change_type", "patch")
    release_summary = spec.get("aggregated_release_summary", "")
    changes = spec.get("aggregated_changes", [])
    request_ids = spec.get("included_request_ids", [])
    related_ids = spec.get("all_related_record_ids", [])

    deploy_item = {
        "project_id": {"S": project_id},
        "record_id": {"S": f"deploy#{deploy_id}"},
        "deploy_id": {"S": deploy_id},
        "record_type": {"S": "deploy"},
        "spec_id": {"S": spec_id},
        "version": {"S": version},
        "previous_version": {"S": previous_version},
        "change_type": {"S": change_type},
        "release_summary": {"S": release_summary},
        "changes": {"L": [{"S": c} for c in (changes if isinstance(changes, list) else [])]},
        "included_request_ids": {"L": [{"S": r} for r in (request_ids if isinstance(request_ids, list) else [])]},
        "related_record_ids": {"L": [{"S": r} for r in (related_ids if isinstance(related_ids, list) else [])]},
        "codebuild_build_id": {"S": build_id},
        "duration_seconds": {"N": str(build_duration)},
        "deployed_at": {"S": now},
    }
    ddb.put_item(TableName=DEPLOY_TABLE, Item=deploy_item)
    logger.info(f"[INFO] Deploy audit record created: {deploy_id}")

    # Write current-version.json to S3 so the orchestrator reads the correct
    # version on the next deployment (DVP-TSK-323)
    try:
        s3 = _get_s3()
        version_key = f"{CONFIG_PREFIX}/{project_id}/current-version.json"
        version_data = json.dumps({
            "version": version,
            "deployed_at": now,
            "spec_id": spec_id,
        }, indent=2).encode("utf-8")
        s3.put_object(
            Bucket=CONFIG_BUCKET,
            Key=version_key,
            Body=version_data,
            ContentType="application/json",
        )
        logger.info(f"[SUCCESS] current-version.json updated to v{version}")
    except Exception as e:
        logger.error(f"[ERROR] Failed to write current-version.json: {e}")
        # Non-fatal — deployment itself succeeded

    # Write [DEPLOYMENT] worklog entries to all related tracker records
    if related_ids and isinstance(related_ids, list):
        description = f"{WORKLOG_PREFIX} v{version} deployed — {release_summary} (spec: {spec_id})"
        if len(description) > 500:
            description = description[:497] + "..."

        updated_count = 0
        for record_id in related_ids:
            record_type = _infer_record_type(record_id)
            rec_project_id = _infer_project_id(record_id)
            if not record_type or not rec_project_id:
                logger.warning(f"Could not infer type/project for {record_id}, skipping worklog")
                continue

            history_entry = {
                "M": {
                    "timestamp": {"S": now},
                    "status": {"S": "worklog"},
                    "description": {"S": description},
                }
            }

            try:
                ddb.update_item(
                    TableName=TRACKER_TABLE,
                    Key={
                        "project_id": {"S": rec_project_id},
                        "record_id": {"S": f"{record_type}#{record_id}"},
                    },
                    UpdateExpression=(
                        "SET updated_at = :ts, last_update_note = :note, "
                        "sync_version = sync_version + :one, "
                        "#history = list_append(if_not_exists(#history, :empty_list), :entry)"
                    ),
                    ExpressionAttributeNames={"#history": "history"},
                    ExpressionAttributeValues={
                        ":ts": {"S": now},
                        ":note": {"S": description[:200]},
                        ":one": {"N": "1"},
                        ":entry": {"L": [history_entry]},
                        ":empty_list": {"L": []},
                    },
                )
                updated_count += 1
                logger.info(f"[INFO] Worklog written to {record_id}")
            except ClientError as e:
                logger.warning(f"Failed to write worklog to {record_id}: {e}")

        logger.info(f"[SUCCESS] Wrote {WORKLOG_PREFIX} worklogs to {updated_count}/{len(related_ids)} records")

    logger.info(f"[END] Deployment finalized: v{version} ({deploy_id})")


def _handle_failure(project_id: str, spec_id: str, error_message: str) -> None:
    """Handle a failed CodeBuild completion."""
    logger.error(f"[ERROR] CodeBuild failed for spec {spec_id}: {error_message}")
    ddb = _get_ddb()
    now = _utc_now()

    # Read the spec to get included request IDs
    resp = ddb.get_item(
        TableName=DEPLOY_TABLE,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
    )
    if "Item" not in resp:
        logger.error(f"Spec {spec_id} not found in DDB")
        return

    spec = _ddb_deser(resp["Item"])
    request_ids = spec.get("included_request_ids", [])

    # Update spec status to failed
    ddb.update_item(
        TableName=DEPLOY_TABLE,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
        UpdateExpression="SET #st = :failed, error_message = :err, completed_at = :now",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":failed": {"S": "failed"},
            ":err": {"S": error_message[:500]},
            ":now": {"S": now},
        },
    )

    # Reset requests back to pending
    if request_ids and isinstance(request_ids, list):
        for rid in request_ids:
            try:
                ddb.update_item(
                    TableName=DEPLOY_TABLE,
                    Key={"project_id": {"S": project_id}, "record_id": {"S": f"request#{rid}"}},
                    UpdateExpression="SET #st = :pending, spec_id = :null_val",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":pending": {"S": "pending"},
                        ":null_val": {"NULL": True},
                    },
                )
            except ClientError:
                logger.warning(f"Failed to reset request {rid}")

        logger.info(f"[INFO] Reset {len(request_ids)} request(s) to pending")


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------


def handler(event: Dict[str, Any], context: Any) -> None:
    """EventBridge Lambda handler for CodeBuild state changes."""
    logger.info(f"deploy_finalize: received event")
    logger.info(json.dumps(event, default=str)[:2000])

    # Extract CodeBuild details from EventBridge event
    detail = event.get("detail", {})
    build_status = detail.get("build-status", "")
    project_name = detail.get("project-name", "")

    # Only process our CodeBuild project
    if project_name != os.environ.get("CODEBUILD_PROJECT", "devops-ui-deploy-builder"):
        logger.info(f"[SKIP] Not our project: {project_name}")
        return

    # Extract environment variables from the build
    env_vars = {}
    for env_item in detail.get("additional-information", {}).get("environment", {}).get("environment-variables", []):
        env_vars[env_item.get("name", "")] = env_item.get("value", "")

    spec_id = env_vars.get("DEPLOY_SPEC_ID", "")
    project_id = env_vars.get("DEPLOY_PROJECT_ID", "")
    build_id = detail.get("build-id", "")

    if not spec_id or not project_id:
        logger.error(f"Missing DEPLOY_SPEC_ID or DEPLOY_PROJECT_ID in build env vars")
        return

    logger.info(f"[INFO] Build {build_id} for project {project_id}, spec {spec_id}: {build_status}")

    # Calculate build duration
    start_time = detail.get("additional-information", {}).get("build-start-time", "")
    build_duration = 0
    if start_time:
        try:
            start_dt = dt.datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            build_duration = int((dt.datetime.now(dt.timezone.utc) - start_dt).total_seconds())
        except Exception:
            pass

    if build_status == "SUCCEEDED":
        _handle_success(project_id, spec_id, build_id, build_duration)
    elif build_status in ("FAILED", "FAULT", "TIMED_OUT", "STOPPED"):
        error_msg = f"CodeBuild {build_status}"
        phases = detail.get("additional-information", {}).get("phases", [])
        for phase in phases:
            if phase.get("phase-status") in ("FAILED", "FAULT", "TIMED_OUT"):
                ctx = phase.get("phase-context", [])
                if ctx:
                    error_msg += f" in {phase.get('phase-type', '?')}: {ctx[0][:200]}"
                break
        _handle_failure(project_id, spec_id, error_msg)
    else:
        logger.info(f"[SKIP] Build status {build_status} — not a terminal state")
