"""bedrock_agent_actions/lambda_function.py

Bedrock Agent Action Group Lambda — exposes Enceladus system operations as
actions that ephemeral Bedrock Agents can invoke during coordination dispatches.

This Lambda is registered as an action group executor when a Bedrock Agent is
created by the dispatch_orchestrator. The agent calls these actions via its
tool-use interface to interact with the Enceladus tracker, projects, documents,
and deployment systems.

Supported actions (mapped via apiPath + httpMethod):
    GET  /tracker/{recordId}          - Fetch a tracker record by ID
    GET  /tracker/list/{projectId}    - List tracker records for a project
    POST /tracker/{recordId}/log      - Log a worklog entry on a record
    PUT  /tracker/{recordId}/status   - Update record status
    POST /tracker/create              - Create a new tracker record
    GET  /projects/{projectId}        - Get project metadata
    GET  /projects                    - List all projects
    GET  /documents/search            - Search documents by keyword
    GET  /documents/{documentId}      - Fetch document content
    FUNCTION check_document_policy    - Validate proposed document writes
    GET  /deployment/{projectId}      - Get deployment state

Environment variables:
    TRACKER_TABLE       default: devops-project-tracker
    PROJECTS_TABLE      default: projects
    DOCUMENTS_TABLE     default: documents
    DEPLOY_TABLE        default: devops-deployment-manager
    DYNAMODB_REGION     default: us-west-2
    S3_BUCKET           default: jreese-net

Related: DVP-TSK-345, DVP-FTR-023
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger("bedrock_agent_actions")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
GOVERNANCE_POLICIES_TABLE = os.environ.get("GOVERNANCE_POLICIES_TABLE", "governance-policies")
AGENT_COMPLIANCE_TABLE = os.environ.get("AGENT_COMPLIANCE_TABLE", "agent-compliance-violations")
DOCUMENT_STORAGE_POLICY_ID = os.environ.get(
    "DOCUMENT_STORAGE_POLICY_ID",
    "document_storage_cloud_only",
)
COMPLIANCE_ENFORCEMENT_DEFAULT = os.environ.get("COMPLIANCE_ENFORCEMENT_DEFAULT", "enforce")
S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")

# ---------------------------------------------------------------------------
# AWS Clients (lazy-init)
# ---------------------------------------------------------------------------

_ddb_client = None
_s3_client = None


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client(
            "dynamodb", region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "adaptive"}),
        )
    return _ddb_client


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=DYNAMODB_REGION)
    return _s3_client


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


def _ser_value(val: Any) -> Dict:
    if isinstance(val, dict):
        return {"M": {str(k): _ser_value(v) for k, v in val.items()}}
    if isinstance(val, list):
        return {"L": [_ser_value(v) for v in val]}
    if isinstance(val, bool):
        return {"BOOL": val}
    if isinstance(val, (int, float)):
        return {"N": str(val)}
    if val is None:
        return {"NULL": True}
    return _ser_s(str(val))


def _deser_val(v: Dict) -> Any:
    if "S" in v:
        return v["S"]
    if "N" in v:
        n = v["N"]
        return int(n) if "." not in n else float(n)
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "L" in v:
        return [_deser_val(i) for i in v["L"]]
    if "M" in v:
        return {k: _deser_val(val) for k, val in v["M"].items()}
    if "SS" in v:
        return list(v["SS"])
    return str(v)


def _deser_item(item: Dict) -> Dict[str, Any]:
    return {k: _deser_val(v) for k, v in item.items()}


def _normalize_string_list(value: Any) -> Optional[List[str]]:
    if value is None:
        return []
    if isinstance(value, str):
        source = [value]
    elif isinstance(value, list):
        source = value
    else:
        return None

    out: List[str] = []
    for entry in source:
        if not isinstance(entry, str):
            return None
        stripped = entry.strip()
        if stripped:
            out.append(stripped)
    return out


def _default_document_storage_policy() -> Dict[str, Any]:
    return {
        "policy_id": DOCUMENT_STORAGE_POLICY_ID,
        "status": "active",
        "enforcement_mode": COMPLIANCE_ENFORCEMENT_DEFAULT,
        "allowed_targets": ["docstore_api", "governance_s3", "mcp_validator", "bedrock_action"],
    }


def _load_document_storage_policy(policy_id: str = DOCUMENT_STORAGE_POLICY_ID) -> Dict[str, Any]:
    fallback = _default_document_storage_policy()
    fallback["policy_source"] = "default"
    fallback["policy_id"] = policy_id or DOCUMENT_STORAGE_POLICY_ID
    try:
        resp = _get_ddb().get_item(
            TableName=GOVERNANCE_POLICIES_TABLE,
            Key={"policy_id": _ser_s(fallback["policy_id"])},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return fallback
        loaded = _deser_item(item)
        if not isinstance(loaded, dict):
            return fallback
        loaded.setdefault("policy_id", fallback["policy_id"])
        loaded.setdefault("status", "active")
        loaded.setdefault("enforcement_mode", COMPLIANCE_ENFORCEMENT_DEFAULT)
        loaded.setdefault("allowed_targets", fallback["allowed_targets"])
        loaded["policy_source"] = "dynamodb"
        return loaded
    except Exception as exc:
        logger.warning(
            "[POLICY] Failed to load policy '%s' from %s: %s",
            fallback["policy_id"],
            GOVERNANCE_POLICIES_TABLE,
            exc,
        )
        return fallback


def _looks_like_local_path(path_value: str) -> bool:
    text = str(path_value or "").strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered.startswith(("/", "~/", "../", "./", "\\\\")):
        return True
    return bool(re.match(r"^[a-z]:[\\/]", lowered))


def _evaluate_document_policy(
    *,
    operation: str,
    storage_target: str,
    file_name: str = "",
    provider: str = "",
    project_id: str = "",
    request_id: str = "",
    dispatch_id: str = "",
) -> Dict[str, Any]:
    policy = _load_document_storage_policy()
    allowed_targets_raw = policy.get("allowed_targets")
    if isinstance(allowed_targets_raw, list):
        allowed_targets = {
            str(entry).strip().lower()
            for entry in allowed_targets_raw
            if str(entry).strip()
        }
    else:
        allowed_targets = set()
    if not allowed_targets:
        allowed_targets = {"docstore_api", "governance_s3", "mcp_validator", "bedrock_action"}

    op_name = str(operation or "").strip().lower()
    target_name = str(storage_target or "").strip().lower()
    policy_status = str(policy.get("status") or "active").strip().lower()
    enforcement_mode = str(policy.get("enforcement_mode") or COMPLIANCE_ENFORCEMENT_DEFAULT).strip().lower()

    reasons: List[str] = []
    if target_name not in allowed_targets:
        reasons.append(f"storage_target '{target_name}' is not allowlisted")
    if file_name and _looks_like_local_path(file_name):
        reasons.append(f"file_name '{file_name}' resolves to local filesystem path")
    if op_name.startswith("documents_") and file_name and ("/" in file_name or "\\" in file_name):
        reasons.append("documents_* file_name must be basename only (no path segments)")

    should_enforce = policy_status == "active" and enforcement_mode == "enforce"
    denied = should_enforce and bool(reasons)
    decision = "denied" if denied else "allowed"

    evaluation = {
        "success": True,
        "policy_id": str(policy.get("policy_id") or DOCUMENT_STORAGE_POLICY_ID),
        "policy_source": str(policy.get("policy_source") or "unknown"),
        "policy_status": policy_status,
        "enforcement_mode": enforcement_mode,
        "operation": op_name,
        "storage_target": target_name,
        "allowed_targets": sorted(allowed_targets),
        "decision": decision,
        "allowed": not denied,
        "reasons": reasons,
        "checked_at": _now_z(),
    }

    details = {
        "operation": op_name,
        "storage_target": target_name,
        "file_name": file_name,
        "provider": provider,
        "project_id": project_id,
        "coordination_request_id": request_id,
        "dispatch_id": dispatch_id,
        "decision": decision,
        "reasons": reasons,
        "policy_source": evaluation["policy_source"],
        "policy_status": policy_status,
        "enforcement_mode": enforcement_mode,
    }
    event_id = f"CMP-{uuid.uuid4().hex[:20].upper()}"
    now = _now_z()
    epoch = int(time.time())
    item = {
        "violation_id": _ser_s(event_id),
        "policy_id": _ser_s(evaluation["policy_id"]),
        "event_epoch": {"N": str(epoch)},
        "event_time": _ser_s(now),
        "result": _ser_s(decision),
        "provider": _ser_s(provider or "bedrock"),
        "project_id": _ser_s(project_id or ""),
        "coordination_request_id": _ser_s(request_id or ""),
        "dispatch_id": _ser_s(dispatch_id or ""),
        "details": _ser_value(details),
        "created_at": _ser_s(now),
    }
    try:
        _get_ddb().put_item(TableName=AGENT_COMPLIANCE_TABLE, Item=item)
    except Exception as exc:
        logger.warning("[POLICY] Failed to persist compliance event %s: %s", event_id, exc)

    return evaluation


# ---------------------------------------------------------------------------
# Action Group Response Helpers
# ---------------------------------------------------------------------------


def _success_response(
    action_group: str,
    api_path: str,
    http_method: str,
    body: Any,
) -> Dict[str, Any]:
    """Build a Bedrock Agent action group success response."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": http_method,
            "httpStatusCode": 200,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(body, default=str),
                },
            },
        },
    }


def _error_response(
    action_group: str,
    api_path: str,
    http_method: str,
    status_code: int,
    error_message: str,
) -> Dict[str, Any]:
    """Build a Bedrock Agent action group error response."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": http_method,
            "httpStatusCode": status_code,
            "responseBody": {
                "application/json": {
                    "body": json.dumps({"error": error_message}),
                },
            },
        },
    }


def _success_function_response(
    action_group: str,
    function_name: str,
    body: Any,
    session_attributes: Optional[Dict[str, Any]] = None,
    prompt_session_attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a Bedrock function-details action group success response."""
    response: Dict[str, Any] = {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": function_name,
            "functionResponse": {
                "responseBody": {
                    "TEXT": {
                        "body": json.dumps(body, default=str),
                    }
                }
            },
        },
    }
    if session_attributes is not None:
        response["sessionAttributes"] = session_attributes
    if prompt_session_attributes is not None:
        response["promptSessionAttributes"] = prompt_session_attributes
    return response


def _error_function_response(
    action_group: str,
    function_name: str,
    error_message: str,
    session_attributes: Optional[Dict[str, Any]] = None,
    prompt_session_attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a Bedrock function-details action group error response."""
    response: Dict[str, Any] = {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": function_name,
            "functionResponse": {
                "responseState": "FAILURE",
                "responseBody": {
                    "TEXT": {
                        "body": json.dumps({"error": error_message}),
                    }
                },
            },
        },
    }
    if session_attributes is not None:
        response["sessionAttributes"] = session_attributes
    if prompt_session_attributes is not None:
        response["promptSessionAttributes"] = prompt_session_attributes
    return response


# ---------------------------------------------------------------------------
# Action Handlers
# ---------------------------------------------------------------------------


def _get_param(parameters: List[Dict], name: str) -> Optional[str]:
    """Extract a named parameter from Bedrock action group parameters list."""
    for p in parameters:
        if p.get("name") == name:
            return p.get("value")
    return None


def _handle_tracker_get(parameters: List[Dict]) -> Dict[str, Any]:
    """GET /tracker/{recordId} — Fetch a tracker record."""
    record_id = _get_param(parameters, "recordId")
    if not record_id:
        return {"error": "recordId parameter required"}

    ddb = _get_ddb()
    # Determine project_id and record_type from item_id format (e.g. DVP-TSK-123)
    # Try all known prefixes
    parts = record_id.split("-")
    if len(parts) < 3:
        return {"error": f"Invalid record ID format: {record_id}"}

    prefix = parts[0]
    record_type = parts[1].lower()
    type_map = {"tsk": "task", "ftr": "feature", "iss": "issue"}
    record_type_full = type_map.get(record_type, record_type)

    # Query using GSI to find project_id, or scan with filter
    # For simplicity, scan with filter on item_id
    resp = ddb.scan(
        TableName=TRACKER_TABLE,
        FilterExpression="item_id = :iid",
        ExpressionAttributeValues={":iid": _ser_s(record_id)},
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return {"error": f"Record {record_id} not found"}

    return _deser_item(items[0])


def _handle_tracker_list(parameters: List[Dict]) -> Dict[str, Any]:
    """GET /tracker/list/{projectId} — List tracker records for a project."""
    project_id = _get_param(parameters, "projectId")
    record_type = _get_param(parameters, "recordType") or "task"
    limit = int(_get_param(parameters, "limit") or "20")

    if not project_id:
        return {"error": "projectId parameter required"}

    ddb = _get_ddb()
    sk_prefix = f"{record_type}#"

    resp = ddb.query(
        TableName=TRACKER_TABLE,
        KeyConditionExpression="project_id = :pid AND begins_with(record_id, :prefix)",
        ExpressionAttributeValues={
            ":pid": _ser_s(project_id),
            ":prefix": _ser_s(sk_prefix),
        },
        Limit=min(limit, 50),
        ScanIndexForward=False,
    )

    items = [_deser_item(item) for item in resp.get("Items", [])]
    return {"items": items, "count": len(items), "project_id": project_id}


def _handle_tracker_log(parameters: List[Dict], body: Dict) -> Dict[str, Any]:
    """POST /tracker/{recordId}/log — Log a worklog entry."""
    record_id = _get_param(parameters, "recordId")
    description = body.get("description") or body.get("message", "")

    if not record_id or not description:
        return {"error": "recordId and description required"}

    # Find the record first
    record = _handle_tracker_get(parameters)
    if "error" in record:
        return record

    project_id = record.get("project_id", "")
    sk = record.get("record_id", "")

    ddb = _get_ddb()
    now = _now_z()
    history_entry = {
        "M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(description[:500]),
        }
    }

    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key={
            "project_id": _ser_s(project_id),
            "record_id": _ser_s(sk),
        },
        UpdateExpression=(
            "SET updated_at = :now, "
            "history = list_append(if_not_exists(history, :empty), :entry)"
        ),
        ExpressionAttributeValues={
            ":now": _ser_s(now),
            ":entry": {"L": [history_entry]},
            ":empty": {"L": []},
        },
    )

    return {"success": True, "record_id": record_id, "logged_at": now}


def _handle_tracker_status(parameters: List[Dict], body: Dict) -> Dict[str, Any]:
    """PUT /tracker/{recordId}/status — Update record status."""
    record_id = _get_param(parameters, "recordId")
    new_status = body.get("status", "")

    if not record_id or not new_status:
        return {"error": "recordId and status required"}

    record = _handle_tracker_get(parameters)
    if "error" in record:
        return record

    project_id = record.get("project_id", "")
    sk = record.get("record_id", "")

    ddb = _get_ddb()
    now = _now_z()
    history_entry = {
        "M": {
            "timestamp": _ser_s(now),
            "status": _ser_s(new_status),
            "description": _ser_s(f"Status changed to {new_status} by bedrock agent"),
        }
    }

    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key={
            "project_id": _ser_s(project_id),
            "record_id": _ser_s(sk),
        },
        UpdateExpression=(
            "SET #st = :status, updated_at = :now, "
            "history = list_append(if_not_exists(history, :empty), :entry)"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":status": _ser_s(new_status),
            ":now": _ser_s(now),
            ":entry": {"L": [history_entry]},
            ":empty": {"L": []},
        },
    )

    return {"success": True, "record_id": record_id, "status": new_status}


def _handle_tracker_create(body: Dict) -> Dict[str, Any]:
    """POST /tracker/create — Create a new tracker record."""
    project_id = body.get("project_id", "")
    record_type = body.get("record_type", "task")
    title = body.get("title", "")
    priority = body.get("priority", "P2")
    acceptance_criteria = _normalize_string_list(body.get("acceptance_criteria"))

    if not project_id or not title:
        return {"error": "project_id and title required"}
    if acceptance_criteria is None:
        return {"error": "acceptance_criteria must be a string or list of strings"}
    if record_type == "task" and not acceptance_criteria:
        return {
            "error": (
                "Task creation requires acceptance_criteria with at least one "
                "non-empty criterion"
            )
        }

    # Generate next item_id — query for highest existing
    ddb = _get_ddb()
    type_code = {"task": "TSK", "feature": "FTR", "issue": "ISS"}.get(record_type, "TSK")

    # Get project prefix
    proj_resp = ddb.get_item(
        TableName=PROJECTS_TABLE,
        Key={"project_id": _ser_s(project_id)},
    )
    proj = _deser_item(proj_resp.get("Item", {}))
    prefix = proj.get("prefix", project_id[:3].upper())

    # For simplicity, use a UUID-based approach for the sequence
    # (full auto-sequencing is handled by tracker.py in production)
    item_id = f"{prefix}-{type_code}-{str(uuid.uuid4().int)[:3].zfill(3)}"

    now = _now_z()
    sk = f"{record_type}#{item_id}"

    item = {
        "project_id": _ser_s(project_id),
        "record_id": _ser_s(sk),
        "record_type": _ser_s(record_type),
        "item_id": _ser_s(item_id),
        "title": _ser_s(title),
        "status": _ser_s("open"),
        "priority": _ser_s(priority),
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "sync_version": {"N": "1"},
        "history": {
            "L": [{
                "M": {
                    "timestamp": _ser_s(now),
                    "status": _ser_s("created"),
                    "description": _ser_s(f"Created by bedrock agent: {title}"),
                }
            }]
        },
    }
    if record_type == "task" and acceptance_criteria:
        item["acceptance_criteria"] = {"L": [_ser_s(v) for v in acceptance_criteria]}

    ddb.put_item(TableName=TRACKER_TABLE, Item=item)

    return {"success": True, "item_id": item_id, "record_type": record_type}


def _handle_project_get(parameters: List[Dict]) -> Dict[str, Any]:
    """GET /projects/{projectId} — Get project metadata."""
    project_id = _get_param(parameters, "projectId")
    if not project_id:
        return {"error": "projectId parameter required"}

    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=PROJECTS_TABLE,
        Key={"project_id": _ser_s(project_id)},
    )
    item = resp.get("Item")
    if not item:
        return {"error": f"Project {project_id} not found"}

    return _deser_item(item)


def _handle_projects_list() -> Dict[str, Any]:
    """GET /projects — List all projects."""
    ddb = _get_ddb()
    resp = ddb.scan(TableName=PROJECTS_TABLE, Limit=50)
    items = [_deser_item(item) for item in resp.get("Items", [])]
    return {"projects": items, "count": len(items)}


def _handle_documents_search(parameters: List[Dict]) -> Dict[str, Any]:
    """GET /documents/search — Search documents by keyword."""
    keyword = _get_param(parameters, "keyword")
    project_id = _get_param(parameters, "projectId")

    if not keyword:
        return {"error": "keyword parameter required"}

    ddb = _get_ddb()
    filter_expr = "contains(keywords, :kw)"
    expr_vals: Dict[str, Any] = {":kw": _ser_s(keyword.lower())}

    if project_id:
        filter_expr += " AND project_id = :pid"
        expr_vals[":pid"] = _ser_s(project_id)

    resp = ddb.scan(
        TableName=DOCUMENTS_TABLE,
        FilterExpression=filter_expr,
        ExpressionAttributeValues=expr_vals,
        Limit=20,
    )

    items = [_deser_item(item) for item in resp.get("Items", [])]
    return {"documents": items, "count": len(items)}


def _handle_document_get(parameters: List[Dict]) -> Dict[str, Any]:
    """GET /documents/{documentId} — Fetch document content from S3."""
    document_id = _get_param(parameters, "documentId")
    if not document_id:
        return {"error": "documentId parameter required"}

    # First get metadata from DynamoDB
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=DOCUMENTS_TABLE,
        Key={"document_id": _ser_s(document_id)},
    )
    item = resp.get("Item")
    if not item:
        return {"error": f"Document {document_id} not found"}

    meta = _deser_item(item)

    # Fetch content from S3
    s3_key = meta.get("s3_key", "")
    if s3_key:
        try:
            s3 = _get_s3()
            obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
            content = obj["Body"].read().decode("utf-8")
            meta["content"] = content[:5000]  # Cap content for agent context
        except Exception as exc:
            meta["content_error"] = str(exc)

    return meta


def _handle_check_document_policy(parameters: List[Dict]) -> Dict[str, Any]:
    """Validate document storage operation against governance policy."""
    operation = _get_param(parameters, "operation")
    storage_target = _get_param(parameters, "storageTarget")
    file_name = _get_param(parameters, "fileName") or ""
    provider = _get_param(parameters, "provider") or "bedrock"
    project_id = _get_param(parameters, "projectId") or ""
    request_id = _get_param(parameters, "coordinationRequestId") or ""
    dispatch_id = _get_param(parameters, "dispatchId") or ""

    if not operation:
        return {"error": "operation parameter required"}
    if not storage_target:
        return {"error": "storageTarget parameter required"}

    return _evaluate_document_policy(
        operation=operation,
        storage_target=storage_target,
        file_name=file_name,
        provider=provider,
        project_id=project_id,
        request_id=request_id,
        dispatch_id=dispatch_id,
    )


def _handle_deployment_state(parameters: List[Dict]) -> Dict[str, Any]:
    """GET /deployment/{projectId} — Get deployment state."""
    project_id = _get_param(parameters, "projectId")
    if not project_id:
        return {"error": "projectId parameter required"}

    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=DEPLOY_TABLE,
        Key={
            "project_id": _ser_s(project_id),
            "record_id": _ser_s("STATE"),
        },
    )
    item = resp.get("Item")
    if not item:
        return {"state": "ACTIVE", "project_id": project_id}

    return _deser_item(item)


def _dispatch_function_call(function_name: str, parameters: List[Dict]) -> Dict[str, Any]:
    """Dispatch function-details invocation to the corresponding internal handler."""
    if function_name == "tracker_get":
        return _handle_tracker_get(parameters)
    if function_name == "tracker_list":
        return _handle_tracker_list(parameters)
    if function_name == "tracker_log":
        return _handle_tracker_log(
            parameters,
            {
                "description": _get_param(parameters, "description") or _get_param(parameters, "message") or "",
            },
        )
    if function_name == "tracker_status":
        return _handle_tracker_status(
            parameters,
            {
                "status": _get_param(parameters, "status") or "",
            },
        )
    if function_name == "tracker_create":
        return _handle_tracker_create(
            {
                "project_id": _get_param(parameters, "project_id") or "",
                "record_type": _get_param(parameters, "record_type") or "",
                "title": _get_param(parameters, "title") or "",
                "description": _get_param(parameters, "description") or "",
                "priority": _get_param(parameters, "priority") or "P2",
            }
        )
    if function_name == "project_get":
        return _handle_project_get(parameters)
    if function_name == "projects_list":
        return _handle_projects_list()
    if function_name == "documents_search":
        return _handle_documents_search(parameters)
    if function_name == "document_get":
        return _handle_document_get(parameters)
    if function_name == "check_document_policy":
        return _handle_check_document_policy(parameters)
    if function_name == "deployment_state_get":
        return _handle_deployment_state(parameters)
    return {"error": f"Unknown function: {function_name}"}


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Bedrock Agent action group Lambda handler.

    Receives action group invocations from Bedrock Agent and routes to
    the appropriate handler based on apiPath and httpMethod.
    """
    logger.info("[START] Bedrock agent action invoked")
    logger.info("[INFO] Event: %s", json.dumps(event, default=str)[:1000])

    action_group = event.get("actionGroup", "enceladus-tools")
    api_path = event.get("apiPath", "")
    http_method = event.get("httpMethod", "GET")
    function_name = event.get("function", "")
    parameters = event.get("parameters", [])
    session_attributes = event.get("sessionAttributes")
    prompt_session_attributes = event.get("promptSessionAttributes")

    # Parse request body if present
    body: Dict[str, Any] = {}
    request_body = event.get("requestBody", {})
    if request_body:
        content = request_body.get("content", {})
        json_body = content.get("application/json", {})
        if "properties" in json_body:
            # Bedrock sends body as list of properties
            for prop in json_body["properties"]:
                body[prop.get("name", "")] = prop.get("value", "")
        elif "body" in json_body:
            try:
                body = json.loads(json_body["body"])
            except (json.JSONDecodeError, TypeError):
                body = {}

    try:
        if function_name:
            result = _dispatch_function_call(function_name, parameters)
            if "error" in result:
                return _error_function_response(
                    action_group,
                    function_name,
                    result["error"],
                    session_attributes=session_attributes,
                    prompt_session_attributes=prompt_session_attributes,
                )

            logger.info("[SUCCESS] Function completed: %s", function_name)
            return _success_function_response(
                action_group,
                function_name,
                result,
                session_attributes=session_attributes,
                prompt_session_attributes=prompt_session_attributes,
            )

        # Route to handler based on apiPath
        if api_path.startswith("/tracker/list/"):
            result = _handle_tracker_list(parameters)
        elif api_path.startswith("/tracker/create"):
            result = _handle_tracker_create(body)
        elif api_path.endswith("/log"):
            result = _handle_tracker_log(parameters, body)
        elif api_path.endswith("/status"):
            result = _handle_tracker_status(parameters, body)
        elif api_path.startswith("/tracker/"):
            result = _handle_tracker_get(parameters)
        elif api_path == "/projects":
            result = _handle_projects_list()
        elif api_path.startswith("/projects/"):
            result = _handle_project_get(parameters)
        elif api_path.startswith("/documents/search"):
            result = _handle_documents_search(parameters)
        elif api_path.startswith("/documents/"):
            result = _handle_document_get(parameters)
        elif api_path.startswith("/deployment/"):
            result = _handle_deployment_state(parameters)
        else:
            return _error_response(action_group, api_path, http_method, 404, f"Unknown path: {api_path}")

        if "error" in result:
            return _error_response(action_group, api_path, http_method, 400, result["error"])

        logger.info("[SUCCESS] Action completed: %s %s", http_method, api_path)
        return _success_response(action_group, api_path, http_method, result)

    except Exception as exc:
        logger.exception("[ERROR] Action failed: %s %s — %s", http_method, api_path, exc)
        return _error_response(action_group, api_path, http_method, 500, str(exc))
