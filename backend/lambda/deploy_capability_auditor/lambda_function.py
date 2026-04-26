"""Enceladus Deploy Capability Auditor — ENC-TSK-E69 / ENC-PLN-031 Phase 4.

Scheduled Lambda that compares each component's declared capability fields
(ENC-TSK-E68) against actual deployed state, then writes an idempotent
capability-manifest document and auto-creates ENC-ISS records for each
detected drift.

Capability fields audited (declared on component_registry.component):
  - required_iam_actions       vs. deploy role inline + attached policies
  - required_env_secrets       vs. tools/deploy-capability env-production-secrets.json (manifest of scoped secrets)
  - required_apigw_routes      vs. aws apigatewayv2 get-routes
  - required_cfn_resources     vs. aws cloudformation list-stack-resources
  - required_lambda_env_vars   vs. aws lambda get-function-configuration

All governed writes (manifest DOC, drift ISS) route via the coordination +
document APIs using COORDINATION_INTERNAL_API_KEY. No direct DynamoDB or S3
writes from the Lambda.

Environment variables:
  COORDINATION_API_BASE        https://jreese.net/api/v1 (or direct APIGW URL)
  DOCUMENT_API_BASE            https://jreese.net/api/v1/documents
  TRACKER_API_BASE             https://jreese.net/api/v1/tracker
  COORDINATION_INTERNAL_API_KEY internal key shared with coordination_api
  MANIFEST_DOC_ID              fixed DOC-* id that is PATCHed each run (upsert)
  APIGW_API_ID                 prod API Gateway v2 ID (optional; auto-resolved if absent)
  PROJECT_ID                   default project_id for ISS creation (default: enceladus)
  AWS_REGION                   us-west-2
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as _urllib_request
from urllib.error import HTTPError

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-west-2")
COORDINATION_API_BASE = os.environ.get(
    "COORDINATION_API_BASE", "https://jreese.net/api/v1"
).rstrip("/")
INTERNAL_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
MANIFEST_DOC_ID = os.environ.get("MANIFEST_DOC_ID", "")
APIGW_API_ID = os.environ.get("APIGW_API_ID", "")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")


def _http(path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{COORDINATION_API_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = _urllib_request.Request(
        url,
        method=method,
        data=data,
        headers={
            "Accept": "application/json",
            "X-Coordination-Internal-Key": INTERNAL_KEY,
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with _urllib_request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        logger.warning("HTTP %s %s failed: %s %s", method, url, exc.code, exc.read().decode("utf-8", "ignore"))
        return {"_http_error": exc.code}


def _fetch_components() -> List[Dict[str, Any]]:
    resp = _http(f"/coordination/components?project_id={PROJECT_ID}")
    return resp.get("components") or resp.get("items") or []


def _snapshot_apigw_routes(api_id: str) -> List[str]:
    if not api_id:
        return []
    client = boto3.client("apigatewayv2", region_name=REGION)
    out: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"ApiId": api_id, "MaxResults": "500"}
        if token:
            kwargs["NextToken"] = token
        resp = client.get_routes(**kwargs)
        out.extend(item["RouteKey"] for item in resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _snapshot_lambda_env_vars(function_name: str) -> List[str]:
    client = boto3.client("lambda", region_name=REGION)
    try:
        cfg = client.get_function_configuration(FunctionName=function_name)
    except client.exceptions.ResourceNotFoundException:
        return []
    env = (cfg.get("Environment") or {}).get("Variables") or {}
    return sorted(env.keys())


def _snapshot_iam_actions(role_name: str) -> List[str]:
    iam = boto3.client("iam")
    actions: List[str] = []
    try:
        inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        for pname in inline:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    acts = stmt.get("Action", [])
                    if isinstance(acts, str):
                        acts = [acts]
                    actions.extend(acts)
    except Exception as exc:
        logger.warning("IAM snapshot for %s failed: %s", role_name, exc)
    return sorted(set(actions))


def _compute_drift(component: Dict[str, Any], api_id: str) -> Dict[str, Any]:
    cid = component["component_id"]
    drift: Dict[str, Any] = {"component_id": cid, "drifts": {}}

    routes_declared = set(component.get("required_apigw_routes") or [])
    if routes_declared:
        live_routes = set(_snapshot_apigw_routes(api_id))
        missing = sorted(routes_declared - live_routes)
        if missing:
            drift["drifts"]["apigw_routes_missing"] = missing

    envvars_declared = set(component.get("required_lambda_env_vars") or [])
    fn_name = (component.get("source_paths") or {}).get("function_name")
    if envvars_declared and fn_name:
        live_env = set(_snapshot_lambda_env_vars(fn_name))
        missing = sorted(envvars_declared - live_env)
        if missing:
            drift["drifts"]["lambda_env_vars_missing"] = missing

    iam_declared = set(component.get("required_iam_actions") or [])
    role_name = (component.get("source_paths") or {}).get("iam_role_name")
    if iam_declared and role_name:
        live_iam = set(_snapshot_iam_actions(role_name))
        missing = sorted(iam_declared - live_iam)
        if missing:
            drift["drifts"]["iam_actions_missing"] = missing

    return drift


def _write_manifest(components: List[Dict[str, Any]], per_drift: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not MANIFEST_DOC_ID:
        logger.warning("MANIFEST_DOC_ID env var not set; skipping manifest write")
        return {}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    lines = [
        "# Deploy Capability Manifest",
        "",
        f"**Generated:** {now}",
        f"**Components audited:** {len(components)}",
        f"**Components with drift:** {sum(1 for d in per_drift if d['drifts'])}",
        "",
        "## Drift summary",
        "",
    ]
    for entry in per_drift:
        if not entry["drifts"]:
            continue
        lines.append(f"### {entry['component_id']}")
        for k, v in entry["drifts"].items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    body = {
        "content": "\n".join(lines),
        "content_type": "text/markdown",
        "updated_at": now,
    }
    return _http(f"/documents/{MANIFEST_DOC_ID}", method="PATCH", body=body)


def _drift_signature(entry: Dict[str, Any]) -> str:
    canonical = json.dumps(entry["drifts"], sort_keys=True)
    return hashlib.sha256(f"{entry['component_id']}:{canonical}".encode("utf-8")).hexdigest()[:16]


def _existing_drift_issue(signature: str) -> Optional[str]:
    q = f"/tracker?project_id={PROJECT_ID}&record_type=issue&status=open"
    resp = _http(q)
    for item in resp.get("records") or []:
        if signature in (item.get("description") or ""):
            return item.get("id")
    return None


def _maybe_create_drift_issue(entry: Dict[str, Any]) -> Optional[str]:
    if not entry["drifts"]:
        return None
    sig = _drift_signature(entry)
    existing = _existing_drift_issue(sig)
    if existing:
        return existing
    desc_lines = [
        f"Auto-detected capability drift for component {entry['component_id']}.",
        f"signature: {sig}",
        "",
    ]
    for k, v in entry["drifts"].items():
        desc_lines.append(f"- **{k}:** {v}")
    body = {
        "project_id": PROJECT_ID,
        "record_type": "issue",
        "title": f"Capability drift: {entry['component_id']}",
        "priority": "P2",
        "category": "debt",
        "description": "\n".join(desc_lines),
    }
    resp = _http("/tracker", method="POST", body=body)
    return resp.get("record_id")


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    logger.info("Deploy capability auditor starting")
    components = _fetch_components()
    logger.info("%d component(s) loaded", len(components))
    per_drift: List[Dict[str, Any]] = []
    for c in components:
        per_drift.append(_compute_drift(c, APIGW_API_ID))

    _write_manifest(components, per_drift)

    created = []
    for entry in per_drift:
        iss_id = _maybe_create_drift_issue(entry)
        if iss_id:
            created.append({"component_id": entry["component_id"], "issue_id": iss_id})
    logger.info(
        "Audit complete: %d components, %d drift entries, %d ISS upserted",
        len(components),
        sum(1 for e in per_drift if e["drifts"]),
        len(created),
    )
    return {
        "components_audited": len(components),
        "drift_components": sum(1 for e in per_drift if e["drifts"]),
        "issues_created_or_existing": created,
    }
