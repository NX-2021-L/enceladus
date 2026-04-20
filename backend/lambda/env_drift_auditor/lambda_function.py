"""env_drift_auditor — ENC-ISS-283.

Hourly scanner that checks each Lambda in env_drift_registry.json for
missing or placeholder values in its REQUIRED_ENV list. On drift, files a
P0 tracker issue via the internal-key tracker API.

Trigger: EventBridge rule on cron(0 * * * ? *)  — every hour on the hour.
Also handles ad-hoc invokes (empty event) for on-demand scans.

Why this exists: three prod Lambdas lost their COORDINATION_INTERNAL_API_KEY
in one week in April 2026 without any drift detection firing. Each failure
was detected only when a human hit the broken surface. ENC-LSN-027
(bifurcation-pattern drift) is the root lesson.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-west-2")
TRACKER_API_BASE = os.environ.get(
    "TRACKER_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker",
)
COORDINATION_INTERNAL_API_KEY = os.environ["COORDINATION_INTERNAL_API_KEY"]
PROJECT_ID = os.environ.get("ISSUE_PROJECT_ID", "enceladus")
SEVERITY = os.environ.get("DRIFT_SEVERITY", "P0")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

# Load registry bundled with the Lambda package
_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "env_drift_registry.json")
with open(_REGISTRY_PATH) as _f:
    REGISTRY = json.load(_f)

PLACEHOLDER_VALUES = set(
    REGISTRY.get("_policy", {}).get("placeholder_values_that_count_as_drift", [])
    + ["", "CHANGE_ME", "TODO", "REPLACE_", "REPLACE_WITH_", "null", "None"]
)


def _audit_lambda(lambda_client: Any, fn_name: str, required: List[str]) -> Tuple[str, List[Dict[str, Any]]]:
    # Returns (status, drift_rows). status in {"ok", "drift", "not_found", "error"}.
    try:
        cfg = lambda_client.get_function_configuration(FunctionName=fn_name)
    except lambda_client.exceptions.ResourceNotFoundException:
        return "not_found", [{"var": None, "reason": "lambda does not exist"}]
    except Exception as exc:
        logger.exception("get_function_configuration failed for %s", fn_name)
        return "error", [{"var": None, "reason": f"aws error: {exc!s}"}]

    env_vars: Dict[str, str] = (cfg.get("Environment") or {}).get("Variables", {}) or {}
    drift: List[Dict[str, Any]] = []
    for var in required:
        val = env_vars.get(var)
        if val is None:
            drift.append({"var": var, "reason": "missing"})
        elif val in PLACEHOLDER_VALUES or val.startswith("REPLACE_"):
            drift.append({"var": var, "reason": f"placeholder value: {val!r}"})
    if drift:
        return "drift", drift
    return "ok", []


def _file_drift_issue(fn_name: str, drift: List[Dict[str, Any]], run_id: str) -> Dict[str, Any]:
    if DRY_RUN:
        logger.info("DRY_RUN: would file drift issue for %s — %s", fn_name, drift)
        return {"dry_run": True}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    missing_vars = ", ".join(d["var"] for d in drift if d.get("var"))
    body = {
        "title": f"[auto-drift] {fn_name} missing required env vars: {missing_vars}",
        "priority": SEVERITY,
        "status": "open",
        "severity": "high",
        "category": "risk",
        "hypothesis": (
            f"env_drift_auditor detected {len(drift)} missing or placeholder "
            f"REQUIRED_ENV values on Lambda {fn_name!r} at {now}. This pattern "
            f"burned prod three times in April 2026 (ENC-ISS-273, ENC-ISS-280, "
            f"and the third instance discovered by this auditor). Root cause: "
            f"deploy.sh / CFN drift from canonical env manifest (ENC-LSN-027 "
            f"bifurcation-pattern). Auditor run_id={run_id}."
        ),
        "evidence": [
            {
                "description": f"env_drift_auditor scan of {fn_name}",
                "observed_by": "env-drift-auditor",
                "timestamp": now,
                "steps_to_duplicate": [
                    f"aws lambda get-function-configuration --function-name {fn_name} --query 'Environment.Variables'",
                    f"Compare against REQUIRED_ENV registry: {missing_vars}",
                ],
                "drift_detail": drift,
                "auditor_run_id": run_id,
            }
        ],
        "technical_notes": (
            "Remediate: (1) add the missing env var to the Lambda's config via "
            "`aws lambda update-function-configuration` for the immediate hotfix, "
            "(2) audit `infrastructure/cloudformation/02-compute.yaml` and the "
            "Lambda's `deploy.sh` to identify which path is the source of truth, "
            "(3) add the env var to whichever config layer is missing it so the "
            "next deploy doesn't regress the fix."
        ),
    }

    req = urllib.request.Request(
        f"{TRACKER_API_BASE}/{PROJECT_ID}/issue",
        method="POST",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"status": resp.status, "body": json.loads(resp.read())}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "error": exc.read().decode("utf-8", errors="replace")}
    except Exception as exc:
        logger.exception("tracker.create failed")
        return {"status": 0, "error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    run_id = getattr(context, "aws_request_id", "manual-run")
    lambda_client = boto3.client("lambda", region_name=REGION)

    results: List[Dict[str, Any]] = []
    drift_count = 0
    ok_count = 0

    for fn_name, required in REGISTRY.get("lambdas", {}).items():
        status, drift = _audit_lambda(lambda_client, fn_name, required)
        entry: Dict[str, Any] = {"lambda": fn_name, "status": status}
        if drift:
            entry["drift"] = drift
            # File an issue — one per Lambda per drift event. Idempotency is
            # best-effort here; the tracker dedup guard may collapse repeated
            # identical titles into the same record.
            entry["issue_filed"] = _file_drift_issue(fn_name, drift, run_id)
            drift_count += 1
        else:
            ok_count += 1
        results.append(entry)

    summary = {
        "run_id": run_id,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": ok_count,
        "drift": drift_count,
        "total": ok_count + drift_count,
        "results": results,
    }
    logger.info("env_drift_auditor run complete: ok=%d drift=%d", ok_count, drift_count)
    return summary
