"""deploy_intake/lambda_function.py

Lambda API handler for the UI Deployment Manager.
Handles API Gateway requests for deployment submission, state management,
status checks, and deployment history.

Routes (via API Gateway proxy):
    POST   /api/v1/deploy/submit              — Submit deployment request
    GET    /api/v1/deploy/state/{projectId}    — Read deployment state
    PATCH  /api/v1/deploy/state/{projectId}    — Set PAUSED/ACTIVE
    GET    /api/v1/deploy/status/{specId}      — Check spec status
    GET    /api/v1/deploy/history/{projectId}  — List recent deployments
    OPTIONS /api/v1/deploy/*                   — CORS preflight

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header.
    Validates the JWT using Cognito JWKS (RS256, cached module-level).
    Optional service-to-service auth via X-Coordination-Internal-Key when
    COORDINATION_INTERNAL_API_KEY is set.

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    DEPLOY_TABLE           default: devops-deployment-manager
    DEPLOY_REGION          default: us-west-2
    CONFIG_BUCKET          default: jreese-net
    CONFIG_PREFIX          default: deploy-config
    SQS_QUEUE_URL          SQS FIFO queue URL for deploy triggers
    PROJECTS_TABLE         default: projects

Related: DVP-FTR-028
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from boto3.dynamodb.types import TypeDeserializer

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
DEPLOY_REGION = os.environ.get("DEPLOY_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "jreese-net")
CONFIG_PREFIX = os.environ.get("CONFIG_PREFIX", "deploy-config")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL", "")
DOC_PREP_LAMBDA_NAME = os.environ.get("DOC_PREP_LAMBDA_NAME", "doc_prep")
CORS_ORIGIN = "https://jreese.net"

VALID_CHANGE_TYPES = {"patch", "minor", "major"}
VALID_DEPLOYMENT_TYPES = {
    "github_public_static",
    "github_private_sst",
    "github_public_workers",
    "github_private_workers",
    "lambda_update",
    "lambda_layer",
    "container_template",
    "glue_crawler_update",
    "glue_job_update",
    "eventbridge_rule",
    "s3_asset_sync",
    "cloudfront_config",
    "step_function_update",
}
NON_UI_SERVICE_GROUP_BY_TYPE = {
    "lambda_update": "lambda",
    "lambda_layer": "lambda",
    "container_template": "container",
    "glue_crawler_update": "glue",
    "glue_job_update": "glue",
    "eventbridge_rule": "eventbridge",
    "s3_asset_sync": "s3",
    "cloudfront_config": "cloudfront",
    "step_function_update": "step_function",
}
MAX_SUMMARY_LENGTH = 500
MAX_CHANGE_LENGTH = 200
MAX_CHANGES_COUNT = 50
SUPPORTED_PRE_DEPLOY_HOOKS = {"doc_prep"}
SERVICE_GROUP_TARGET_ARN_PREFIXES = {
    "lambda": ("arn:aws:lambda:",),
    "container": ("arn:aws:ecs:", "arn:aws:ecr:", "arn:aws:codebuild:"),
    "glue": ("arn:aws:glue:",),
    "eventbridge": ("arn:aws:events:",),
    "s3": ("arn:aws:s3:::",),
    "cloudfront": ("arn:aws:cloudfront::",),
    "step_function": ("arn:aws:states:",),
}
SERVICE_GROUP_REQUIRED_CHECKS = {
    "lambda": {"cold_start_regression_check", "runtime_compatibility_check"},
    "container": {"image_architecture_check", "resource_limits_check"},
    "glue": {"timeout_config_check", "worker_type_check"},
    "eventbridge": {"schedule_safety_check"},
    "s3": {"bucket_policy_check"},
    "cloudfront": {"cache_behavior_check"},
    "step_function": {"state_machine_validation_check"},
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_deser = TypeDeserializer()

# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_ddb = None
_s3 = None
_sqs = None
_lambda_client = None

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

_project_cache: Dict[str, bool] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0


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


def _get_sqs():
    global _sqs
    if _sqs is None:
        _sqs = boto3.client("sqs", region_name=DEPLOY_REGION)
    return _sqs


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client(
            "lambda",
            region_name=DEPLOY_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _lambda_client


# ---------------------------------------------------------------------------
# CORS + Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Coordination-Internal-Key",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str, **extra: Any) -> Dict:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code == 401:
            code = "PERMISSION_DENIED"
        elif status_code == 404:
            code = "NOT_FOUND"
        elif status_code == 409:
            code = "CONFLICT"
        elif status_code == 429:
            code = "RATE_LIMITED"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500))
    details = dict(extra)
    payload: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details,
        },
    }
    payload.update(details)
    return _response(status_code, payload)


def _ok(body: Any) -> Dict:
    if isinstance(body, dict) and "success" not in body:
        body["success"] = True
    return _response(200, body)


# ---------------------------------------------------------------------------
# JWT Auth (same pattern as tracker_mutation)
# ---------------------------------------------------------------------------


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache

    if not COGNITO_USER_POOL_ID:
        raise ValueError("COGNITO_USER_POOL_ID not set")

    region = COGNITO_USER_POOL_ID.split("_")[0]
    url = (
        f"https://cognito-idp.{region}.amazonaws.com/"
        f"{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    )
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())

    new_cache: Dict[str, Any] = {}
    for key_data in data.get("keys", []):
        kid = key_data["kid"]
        if _JWT_AVAILABLE:
            new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))
        else:
            new_cache[kid] = key_data

    _jwks_cache = new_cache
    _jwks_fetched_at = now
    return _jwks_cache


def _verify_token(token: str) -> Dict[str, Any]:
    if not _JWT_AVAILABLE:
        raise ValueError("JWT library not available in Lambda package")

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    if alg != "RS256":
        raise ValueError(f"Unexpected token algorithm: {alg}")

    keys = _get_jwks()
    pub_key = keys.get(kid)
    if pub_key is None:
        raise ValueError("Token key ID not found in JWKS")

    try:
        return jwt.decode(
            token, pub_key, algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID, options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Token audience mismatch.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc


def _extract_token(event: Dict) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_parts = []

    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        cookie_parts.extend(p.strip() for p in cookie_header.split(";") if p.strip())

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(p.strip() for p in event_cookies if isinstance(p, str) and p.strip())

    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return unquote(part[len("enceladus_id_token="):])
    return None


def _authenticate(event: Dict) -> Tuple[Optional[Dict[str, Any]], Optional[Dict]]:
    """Authenticate request. Returns (claims, None) or (None, error_response)."""
    headers = event.get("headers") or {}
    if COORDINATION_INTERNAL_API_KEY:
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key == COORDINATION_INTERNAL_API_KEY:
            return {"auth_mode": "internal-key", "sub": "internal-key"}, None

    token = _extract_token(event)
    if not token:
        logger.warning("No enceladus_id_token cookie found")
        return None, _error(401, "Authentication required")

    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("Auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# Project validation
# ---------------------------------------------------------------------------


def _validate_project(project_id: str) -> Optional[str]:
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now

    if project_id in _project_cache:
        return None if _project_cache[project_id] else f"Project '{project_id}' not found"

    try:
        ddb = _get_ddb()
        resp = boto3.client("dynamodb", region_name=DEPLOY_REGION).get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="project_id",
        )
        exists = "Item" in resp
        _project_cache[project_id] = exists
        return None if exists else f"Project '{project_id}' not registered"
    except Exception:
        logger.warning("Project validation failed (fail-open)", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# DDB helper
# ---------------------------------------------------------------------------


def _ddb_deser(item: Dict) -> Dict[str, Any]:
    return {k: _deser.deserialize(v) for k, v in item.items()}


def _utc_now() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now_compact() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _validate_service_group_rules(
    *,
    service_group: str,
    target_arn: str,
    validation_checks: List[str],
) -> Optional[str]:
    expected_prefixes = SERVICE_GROUP_TARGET_ARN_PREFIXES.get(service_group, ())
    if expected_prefixes and not any(target_arn.startswith(prefix) for prefix in expected_prefixes):
        return (
            f"non_ui_config.target_arn must match service_group '{service_group}' "
            f"prefixes: {', '.join(expected_prefixes)}"
        )

    required_checks = SERVICE_GROUP_REQUIRED_CHECKS.get(service_group, set())
    provided_checks = {str(check).strip() for check in validation_checks if str(check).strip()}
    missing = sorted(required_checks - provided_checks)
    if missing:
        return (
            f"non_ui_config.validation_checks missing required checks for '{service_group}': "
            f"{', '.join(missing)}"
        )
    return None


def _invoke_doc_prep_hook(project_id: str) -> Dict[str, Any]:
    event = {
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": f"/api/v1/doc-prep/{project_id}",
        "pathParameters": {"projectName": project_id},
        "body": json.dumps({"dry_run": True}),
    }
    response = _get_lambda_client().invoke(
        FunctionName=DOC_PREP_LAMBDA_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode("utf-8"),
    )
    payload_raw = response.get("Payload").read()
    decoded = payload_raw.decode("utf-8") if isinstance(payload_raw, (bytes, bytearray)) else str(payload_raw)
    payload = json.loads(decoded or "{}")
    status_code = int(payload.get("statusCode") or 500)
    body_raw = payload.get("body") or "{}"
    body = json.loads(body_raw) if isinstance(body_raw, str) else (body_raw or {})
    success = status_code < 400 and bool(body.get("success"))
    return {
        "hook": "doc_prep",
        "success": success,
        "status_code": status_code,
        "result": body,
    }


def _run_pre_deploy_hooks(project_id: str, hooks: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for hook in hooks:
        if hook != "doc_prep":
            continue
        try:
            results.append(_invoke_doc_prep_hook(project_id))
        except Exception as exc:
            results.append(
                {
                    "hook": "doc_prep",
                    "success": False,
                    "status_code": 500,
                    "result": {"success": False, "error": str(exc)},
                }
            )
    return results


# ---------------------------------------------------------------------------
# Route: POST /api/v1/deploy/submit
# ---------------------------------------------------------------------------


def _handle_submit(event: Dict, body: Dict) -> Dict:
    project_id = body.get("project_id", "").strip()
    change_type = body.get("change_type", "").strip().lower()
    deployment_type = body.get("deployment_type", "github_public_static").strip()
    summary = body.get("summary", "").strip()
    changes = body.get("changes", [])
    related_record_ids = body.get("related_record_ids", [])
    files_changed = body.get("files_changed", [])
    submitted_by = body.get("submitted_by", "api-user")
    non_ui_config = body.get("non_ui_config", {})
    pre_deploy_hooks = body.get("pre_deploy_hooks", [])

    # Validation
    if not project_id:
        return _error(400, "project_id is required")
    if change_type not in VALID_CHANGE_TYPES:
        return _error(400, f"change_type must be one of: {', '.join(sorted(VALID_CHANGE_TYPES))}")
    if deployment_type not in VALID_DEPLOYMENT_TYPES:
        return _error(400, f"deployment_type must be one of: {', '.join(sorted(VALID_DEPLOYMENT_TYPES))}")
    if not summary:
        return _error(400, "summary is required")
    if len(summary) > MAX_SUMMARY_LENGTH:
        return _error(400, f"summary exceeds {MAX_SUMMARY_LENGTH} characters")
    if not isinstance(changes, list):
        return _error(400, "changes must be an array of strings")
    if len(changes) > MAX_CHANGES_COUNT:
        return _error(400, f"changes exceeds {MAX_CHANGES_COUNT} items")
    if pre_deploy_hooks is None:
        pre_deploy_hooks = []
    if not isinstance(pre_deploy_hooks, list):
        return _error(400, "pre_deploy_hooks must be an array of strings")
    pre_deploy_hooks = [str(h).strip() for h in pre_deploy_hooks if str(h).strip()]
    unknown_hooks = sorted(set(pre_deploy_hooks) - SUPPORTED_PRE_DEPLOY_HOOKS)
    if unknown_hooks:
        return _error(400, f"Unsupported pre_deploy_hooks: {', '.join(unknown_hooks)}")

    if deployment_type in NON_UI_SERVICE_GROUP_BY_TYPE:
        if not isinstance(non_ui_config, dict):
            return _error(400, "non_ui_config must be an object for non-UI deployment types")

        expected_group = NON_UI_SERVICE_GROUP_BY_TYPE[deployment_type]
        service_group = str(non_ui_config.get("service_group", "")).strip()
        if not service_group:
            return _error(400, "non_ui_config.service_group is required for non-UI deployment types")
        if service_group != expected_group:
            return _error(
                400,
                f"non_ui_config.service_group must be '{expected_group}' for deployment_type '{deployment_type}'",
            )

        target_arn = str(non_ui_config.get("target_arn", "")).strip()
        if not target_arn:
            return _error(400, "non_ui_config.target_arn is required for non-UI deployment types")
        validation_checks = non_ui_config.get("validation_checks")
        if validation_checks is None:
            validation_checks = sorted(SERVICE_GROUP_REQUIRED_CHECKS.get(expected_group, set()))
            non_ui_config["validation_checks"] = validation_checks
        if not isinstance(validation_checks, list):
            return _error(400, "non_ui_config.validation_checks must be an array of strings")
        validation_checks_norm = [str(check).strip() for check in validation_checks if str(check).strip()]
        non_ui_config["validation_checks"] = validation_checks_norm
        rules_error = _validate_service_group_rules(
            service_group=expected_group,
            target_arn=target_arn,
            validation_checks=validation_checks_norm,
        )
        if rules_error:
            return _error(400, rules_error)

    # Validate project exists
    proj_err = _validate_project(project_id)
    if proj_err:
        return _error(404, proj_err)

    pre_deploy_results: List[Dict[str, Any]] = []
    if pre_deploy_hooks:
        pre_deploy_results = _run_pre_deploy_hooks(project_id, pre_deploy_hooks)
        failed_hooks = [result for result in pre_deploy_results if not result.get("success")]
        if failed_hooks:
            return _error(
                409,
                "Pre-deploy hook execution failed",
                pre_deploy_results=pre_deploy_results,
            )

    # Read deploy state
    try:
        s3 = _get_s3()
        key = f"{CONFIG_PREFIX}/{project_id}/state.json"
        resp = s3.get_object(Bucket=CONFIG_BUCKET, Key=key)
        state_data = json.loads(resp["Body"].read().decode("utf-8"))
        deploy_state = state_data.get("state", "ACTIVE")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            deploy_state = "ACTIVE"
        else:
            return _error(500, "Failed to read deployment state")

    # Generate request ID
    request_id = f"REQ-{_utc_now_compact()}-{secrets.token_hex(3)}"
    now = _utc_now()

    # Write to DynamoDB
    item = {
        "project_id": {"S": project_id},
        "record_id": {"S": f"request#{request_id}"},
        "request_id": {"S": request_id},
        "record_type": {"S": "request"},
        "status": {"S": "pending"},
        "submitted_at": {"S": now},
        "submitted_by": {"S": submitted_by},
        "change_type": {"S": change_type},
        "deployment_type": {"S": deployment_type},
        "summary": {"S": summary[:MAX_SUMMARY_LENGTH]},
        "changes": {"L": [{"S": c[:MAX_CHANGE_LENGTH]} for c in changes[:MAX_CHANGES_COUNT]]},
        "related_record_ids": {"L": [{"S": r} for r in related_record_ids]},
    }
    if files_changed:
        item["files_changed"] = {"L": [{"S": f} for f in files_changed]}
    if deployment_type in NON_UI_SERVICE_GROUP_BY_TYPE:
        item["non_ui_config"] = {"S": json.dumps(non_ui_config)}
    if pre_deploy_hooks:
        item["pre_deploy_hooks"] = {"L": [{"S": hook} for hook in pre_deploy_hooks]}
    if pre_deploy_results:
        item["pre_deploy_results"] = {"S": json.dumps(pre_deploy_results)}

    ddb = _get_ddb()
    ddb.put_item(TableName=DEPLOY_TABLE, Item=item)
    logger.info(f"Wrote deployment request {request_id} for project {project_id}")

    # Send SQS trigger if ACTIVE
    message = "Deployment request queued."
    queued_paused = False
    if deploy_state == "PAUSED":
        message = "Deployment request stored. Deployments are currently PAUSED."
        queued_paused = True
    elif SQS_QUEUE_URL:
        try:
            sqs = _get_sqs()
            sqs.send_message(
                QueueUrl=SQS_QUEUE_URL,
                MessageBody=json.dumps({"project_id": project_id, "trigger": "deploy_request"}),
                MessageGroupId=project_id,
            )
            message = "Deployment request queued. 60-second debounce window started."
        except Exception:
            logger.warning("SQS trigger failed", exc_info=True)
            message = "Deployment request stored. SQS trigger failed — will be picked up on next trigger."

    return _ok({
        "request_id": request_id,
        "deployment_type": deployment_type,
        "project_state": deploy_state,
        "queued_paused": queued_paused,
        "message": message,
        "pre_deploy_results": pre_deploy_results,
    })


# ---------------------------------------------------------------------------
# Route: GET /api/v1/deploy/state/{projectId}
# ---------------------------------------------------------------------------


def _handle_get_state(project_id: str) -> Dict:
    try:
        s3 = _get_s3()
        key = f"{CONFIG_PREFIX}/{project_id}/state.json"
        resp = s3.get_object(Bucket=CONFIG_BUCKET, Key=key)
        data = json.loads(resp["Body"].read().decode("utf-8"))
        return _ok({"project_id": project_id, **data})
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return _ok({
                "project_id": project_id,
                "state": "ACTIVE",
                "updated_at": None,
                "updated_by": "default",
                "reason": None,
            })
        return _error(500, "Failed to read deployment state")


# ---------------------------------------------------------------------------
# Route: PATCH /api/v1/deploy/state/{projectId}
# ---------------------------------------------------------------------------


def _handle_set_state(project_id: str, body: Dict) -> Dict:
    new_state = body.get("state", "").strip().upper()
    reason = body.get("reason")

    if new_state not in ("ACTIVE", "PAUSED"):
        return _error(400, "state must be ACTIVE or PAUSED")

    now = _utc_now()
    data = {
        "state": new_state,
        "updated_at": now,
        "updated_by": "api-user",
        "reason": reason,
        "paused_since": now if new_state == "PAUSED" else None,
    }

    s3 = _get_s3()
    key = f"{CONFIG_PREFIX}/{project_id}/state.json"
    s3.put_object(
        Bucket=CONFIG_BUCKET, Key=key,
        Body=json.dumps(data, indent=2).encode("utf-8"),
        ContentType="application/json",
    )

    result = {"project_id": project_id, **data, "message": f"State set to {new_state}"}

    # If setting to ACTIVE, check for pending requests and trigger
    if new_state == "ACTIVE" and SQS_QUEUE_URL:
        ddb = _get_ddb()
        resp = ddb.query(
            TableName=DEPLOY_TABLE,
            KeyConditionExpression="project_id = :pid AND begins_with(record_id, :prefix)",
            FilterExpression="#st = :pending",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":pid": {"S": project_id},
                ":prefix": {"S": "request#"},
                ":pending": {"S": "pending"},
            },
            Select="COUNT",
        )
        pending_count = resp.get("Count", 0)
        if pending_count > 0:
            try:
                sqs = _get_sqs()
                sqs.send_message(
                    QueueUrl=SQS_QUEUE_URL,
                    MessageBody=json.dumps({"project_id": project_id, "trigger": "state_activated"}),
                    MessageGroupId=project_id,
                )
                result["pending_requests_triggered"] = pending_count
            except Exception:
                logger.warning("SQS trigger on ACTIVE failed", exc_info=True)

    return _ok(result)


# ---------------------------------------------------------------------------
# Route: GET /api/v1/deploy/status/{specId}
# ---------------------------------------------------------------------------


def _handle_get_status(spec_id: str, project_id: str) -> Dict:
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=DEPLOY_TABLE,
        Key={"project_id": {"S": project_id}, "record_id": {"S": f"spec#{spec_id}"}},
    )
    item = resp.get("Item")
    if not item:
        return _error(404, f"Spec {spec_id} not found")

    data = _ddb_deser(item)
    # Parse integration_analysis if it's a JSON string
    if isinstance(data.get("integration_analysis"), str):
        try:
            data["integration_analysis"] = json.loads(data["integration_analysis"])
        except (json.JSONDecodeError, TypeError):
            pass

    return _ok(data)


# ---------------------------------------------------------------------------
# Route: GET /api/v1/deploy/history/{projectId}
# ---------------------------------------------------------------------------


def _handle_get_history(project_id: str, limit: int = 10) -> Dict:
    ddb = _get_ddb()
    results = []
    kwargs = {
        "TableName": DEPLOY_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":prefix": {"S": "deploy#"},
        },
        "ScanIndexForward": False,
    }
    while True:
        resp = ddb.query(**kwargs)
        results.extend([_ddb_deser(item) for item in resp.get("Items", [])])
        if len(results) >= limit or "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    results.sort(key=lambda r: r.get("deployed_at", ""), reverse=True)
    return _ok({"project_id": project_id, "deployments": results[:limit]})


# ---------------------------------------------------------------------------
# Path routing
# ---------------------------------------------------------------------------

# Patterns for path parsing (supports both direct and CloudFront-forwarded paths)
_SUBMIT_PATTERN = re.compile(r"(?:/api/v1/deploy)?/submit$")
_STATE_PATTERN = re.compile(r"(?:/api/v1/deploy)?/state/(?P<projectId>[a-z0-9_-]+)$")
_STATUS_PATTERN = re.compile(r"(?:/api/v1/deploy)?/status/(?P<specId>[A-Z0-9_-]+)$")
_HISTORY_PATTERN = re.compile(r"(?:/api/v1/deploy)?/history/(?P<projectId>[a-z0-9_-]+)$")
_OPTIONS_PATTERN = re.compile(r"(?:/api/v1/deploy)?/")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Main Lambda entry point."""
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod", "")).upper()
    path = event.get("rawPath") or event.get("path") or ""

    logger.info(f"deploy_intake: {method} {path}")

    # CORS preflight
    if method == "OPTIONS":
        return _response(204, "")

    # Auth (Cognito cookie or internal service key)
    _claims, auth_error = _authenticate(event)
    if auth_error:
        return auth_error

    # Parse body
    body = {}
    raw_body = event.get("body")
    if raw_body:
        try:
            body = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
        except (json.JSONDecodeError, TypeError):
            return _error(400, "Invalid JSON body")

    # Route dispatch
    try:
        # POST /submit
        if method == "POST":
            m = _SUBMIT_PATTERN.search(path)
            if m:
                return _handle_submit(event, body)

        # GET or PATCH /state/{projectId}
        m = _STATE_PATTERN.search(path)
        if m:
            project_id = m.group("projectId")
            if method == "GET":
                return _handle_get_state(project_id)
            elif method == "PATCH":
                return _handle_set_state(project_id, body)

        # GET /status/{specId}
        if method == "GET":
            m = _STATUS_PATTERN.search(path)
            if m:
                spec_id = m.group("specId")
                # Need project_id from query string
                qs = event.get("queryStringParameters") or {}
                project_id = qs.get("project") or body.get("project_id", "")
                if not project_id:
                    return _error(400, "project query parameter required for status lookup")
                return _handle_get_status(spec_id, project_id)

        # GET /history/{projectId}
        if method == "GET":
            m = _HISTORY_PATTERN.search(path)
            if m:
                project_id = m.group("projectId")
                qs = event.get("queryStringParameters") or {}
                limit = min(int(qs.get("limit", "10")), 50)
                return _handle_get_history(project_id, limit)

        return _error(404, f"Route not found: {method} {path}")

    except (ClientError, BotoCoreError) as e:
        logger.error(f"AWS error: {e}", exc_info=True)
        return _error(500, "Internal service error")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return _error(500, "Internal service error")
