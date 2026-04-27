# ENC-FTR-091 / ENC-TSK-F87
# v3-v4 Deploy Parity Validator — autonomous pre-merge fixer, deploy watcher, post-deploy doc updater.
#
# One full cycle per PR→merge:
#   (a) pre_merge_check  — inspect DM Lambda env health, scan DPL records, detect gaps, write readiness DOC
#   (b) deploy_watch     — poll GH Deployments API ≤30s until terminal state
#   (c) post-deploy      — patch readiness DOC with per-function outcomes
#
# Triggered by devops-github-integration on PR open/sync/merge events.
# Also reachable via MCP deploy.parity_check action for agent-driven dry runs.
#
# ISS catalogue encoded as detection rules:
#   ISS-273 / ISS-283 — COORDINATION_INTERNAL_API_KEY missing on DM + graph-query Lambdas
#   ISS-269           — ENABLE_HANDOFF_PRIMITIVE / ENABLE_COMPONENT_PROPOSAL missing on MCP Lambdas
#   ISS-279           — enceladus-mcp-code-gamma Lambda missing or inactive
#   ISS-296           — function_name_map gaps (new Lambda dirs not in env manifest)
#   ISS-281 / ISS-282 — ConditionExpression missing (detection only, flag for PR)
#   ISS-284           — PWA filter drift (detection only)
#   LSN-044           — writer removal without reader update (detection only, flag for PR)
#   DOC-D45141D94C55  — CodeSha256 drift on patched Lambdas (detection only, backport PR needed)

import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEPLOY_TABLE         = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
DEPLOY_REGION        = os.environ.get("DEPLOY_REGION", "us-west-2")
DOCUMENT_API_URL     = os.environ.get("DOCUMENT_API_URL", "")
TRACKER_API_URL      = os.environ.get("TRACKER_API_URL", "")
GITHUB_TOKEN_SECRET  = os.environ.get("GITHUB_TOKEN_SECRET", "devops/github-app/token")
INTERNAL_API_KEY     = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
ENVIRONMENT_SUFFIX   = os.environ.get("ENVIRONMENT_SUFFIX", "")  # "" = prod, "-gamma" = gamma
AWS_REGION           = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")

# ENC-TSK-G43 / ENC-FTR-098 AC-7 — mentions_drift_audit config.
# TRACKER_TABLE / DOCUMENTS_TABLE: source-of-truth tables sampled per record_type.
# GRAPHSEARCH_URL: where the audit reads current MENTIONS edges. Falls back to
#   ${TRACKER_API_URL}/graphsearch (same API Gateway base) if unset.
# MENTIONS_AUDIT_SAMPLE_SIZE: total records sampled per run, distributed
#   roughly evenly across record_types in MENTIONS_PROSE_FIELDS.
# MENTIONS_AUDIT_THRESHOLD: mismatch_count / sample_size ratio above which
#   an ENC-ISS record is auto-emitted (spec: 0.01 = 1%).
TRACKER_TABLE        = os.environ.get("TRACKER_TABLE",   "devops-project-tracker")
DOCUMENTS_TABLE      = os.environ.get("DOCUMENTS_TABLE", "documents")
GRAPHSEARCH_URL      = os.environ.get("GRAPHSEARCH_URL", "")
MENTIONS_AUDIT_SAMPLE_SIZE = int(os.environ.get("MENTIONS_AUDIT_SAMPLE_SIZE", "100"))
MENTIONS_AUDIT_THRESHOLD   = float(os.environ.get("MENTIONS_AUDIT_THRESHOLD", "0.01"))

# ENC-TSK-F64 / ENC-FTR-090 AC-20 — daily drift audit config
SNS_TOPIC_ARN        = os.environ.get("SNS_TOPIC_ARN", "")
CFN_DRIFT_STACKS     = [
    s.strip()
    for s in os.environ.get(
        "CFN_DRIFT_STACKS",
        "enceladus-data,enceladus-api,enceladus-github-roles,enceladus-monitoring",
    ).split(",")
    if s.strip()
]
SNAPSTART_MAX_STALE  = int(os.environ.get("SNAPSTART_MAX_STALE_VERSIONS", "5"))
DRIFT_POLL_TIMEOUT   = int(os.environ.get("DRIFT_POLL_TIMEOUT", "240"))
_LAMBDA_FN_PREFIXES  = ("devops-", "enceladus-")

# Deployment Manager pipeline Lambdas — env health checked before every merge.
_DM_BASE_NAMES = [
    "devops-deploy-intake",
    "devops-deploy-decide",
    "devops-deploy-finalize",
    "devops-deploy-orchestrator",
]

# Lambdas that also require COORDINATION_INTERNAL_API_KEY (ISS-273/280 class).
_INTERNAL_KEY_REQUIRED = _DM_BASE_NAMES + ["devops-graph-query-api"]

# MCP Lambdas with feature-flag env vars (ISS-269 class).
_MCP_FLAG_CHECKS: List[Tuple[str, str, str]] = [
    ("enceladus-mcp-code",       "ENABLE_HANDOFF_PRIMITIVE",   "true"),
    ("enceladus-mcp-streamable", "ENABLE_HANDOFF_PRIMITIVE",   "true"),
    ("devops-coordination-api",  "ENABLE_COMPONENT_PROPOSAL",  "true"),
]

# Known-good CodeSha256 values for Lambdas patched out-of-band (DOC-D45141D94C55 §1).
# These are compared post-deploy; drift triggers a flag-only alert (backport PR needed).
_KNOWN_GOOD_SHA: Dict[str, str] = {
    "devops-github-integration": "edcKIK0Ch3rq5GtIlJ4+ePGqBLYv2OaGPCgxEiSAE80=",
    "devops-deploy-intake":      "GAjUgAYV1UJENK33mi+71/gMV5yeRcsRe7bGZsOZcik=",
}

# Lambda dirs intentionally excluded from function_name_map (not provisioned in any env).
_MAP_EXCLUSIONS = {"deploy_capability_auditor"}

# ---------------------------------------------------------------------------
# AWS clients (module-level cache)
# ---------------------------------------------------------------------------
_lambda_client = None
_ddb            = None
_secrets        = None


def _get_lambda():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=DEPLOY_REGION)
    return _lambda_client


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client("dynamodb", region_name=DEPLOY_REGION)
    return _ddb


def _get_secrets():
    global _secrets
    if _secrets is None:
        _secrets = boto3.client("secretsmanager", region_name=DEPLOY_REGION)
    return _secrets


_cfn  = None
_sns  = None


def _get_cfn():
    global _cfn
    if _cfn is None:
        _cfn = boto3.client("cloudformation", region_name=DEPLOY_REGION)
    return _cfn


def _get_sns():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns", region_name=DEPLOY_REGION)
    return _sns


# ---------------------------------------------------------------------------
# GitHub token
# ---------------------------------------------------------------------------
_gh_token_cache: Optional[str] = None
_gh_token_fetched_at: float = 0.0
_GH_TOKEN_TTL = 2700.0


def _github_token() -> str:
    global _gh_token_cache, _gh_token_fetched_at
    if _gh_token_cache and (time.time() - _gh_token_fetched_at) < _GH_TOKEN_TTL:
        return _gh_token_cache
    try:
        r = _get_secrets().get_secret_value(SecretId=GITHUB_TOKEN_SECRET)
        raw = r.get("SecretString", "")
        data = json.loads(raw) if raw.startswith("{") else {}
        _gh_token_cache = data.get("token") or data.get("github_token") or raw.strip()
        _gh_token_fetched_at = time.time()
        return _gh_token_cache
    except ClientError as e:
        logger.warning("GitHub token fetch failed: %s", e)
        return ""


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
def _http(method: str, url: str, body: Optional[Dict] = None,
          extra_headers: Optional[Dict] = None) -> Tuple[int, Any]:
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if INTERNAL_API_KEY:
        headers["X-Coordination-Internal-Key"] = INTERNAL_API_KEY
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# Lambda env inspection + autonomous fixes
# ---------------------------------------------------------------------------
def _get_fn_config(fn_name: str) -> Optional[Dict]:
    try:
        return _get_lambda().get_function_configuration(FunctionName=fn_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _set_env_var(fn_name: str, current_env: Dict[str, str], key: str, value: str) -> bool:
    """Apply a single env-var addition via UpdateFunctionConfiguration."""
    if not value:
        return False
    try:
        _get_lambda().update_function_configuration(
            FunctionName=fn_name,
            Environment={"Variables": {**current_env, key: value}},
        )
        logger.info("[FIX] %s: set %s", fn_name, key)
        return True
    except ClientError as e:
        logger.error("[FIX-FAIL] %s: set %s failed: %s", fn_name, key, e)
        return False


def _check_internal_key_vars(suffix: str) -> Dict[str, Any]:
    """
    ISS-273 / ISS-283: verify COORDINATION_INTERNAL_API_KEY is present on all required
    Lambdas. Autonomously repairs via UpdateFunctionConfiguration if missing and we hold
    the current value in our own env (which we do — same secret rotation wave).
    """
    report: Dict[str, Any] = {}
    for base in _INTERNAL_KEY_REQUIRED:
        fn_name = f"{base}{suffix}"
        cfg = _get_fn_config(fn_name)
        if cfg is None:
            report[fn_name] = {"status": "not_found"}
            continue
        env = cfg.get("Environment", {}).get("Variables", {})
        if env.get("COORDINATION_INTERNAL_API_KEY"):
            report[fn_name] = {"status": "ok"}
        else:
            fixed = _set_env_var(fn_name, env, "COORDINATION_INTERNAL_API_KEY", INTERNAL_API_KEY)
            report[fn_name] = {
                "status": "fixed" if fixed else "fix_failed",
                "issue": "ISS-273",
                "action": "UpdateFunctionConfiguration" if fixed else "manual_required",
            }
    return report


def _check_mcp_feature_flags(suffix: str) -> Dict[str, Any]:
    """
    ISS-269: verify MCP Lambda feature flags are still enabled after any deploy.
    Autonomously repairs via UpdateFunctionConfiguration.
    """
    report: Dict[str, Any] = {}
    for base_name, flag_key, expected_val in _MCP_FLAG_CHECKS:
        fn_name = f"{base_name}{suffix}" if suffix and base_name != "devops-coordination-api" else base_name
        cfg = _get_fn_config(fn_name)
        if cfg is None:
            report[fn_name] = {"status": "not_found"}
            continue
        env = cfg.get("Environment", {}).get("Variables", {})
        actual = env.get(flag_key, "")
        if actual == expected_val:
            report[fn_name] = {"status": "ok", "flag": flag_key}
        else:
            fixed = _set_env_var(fn_name, env, flag_key, expected_val)
            report[fn_name] = {
                "status": "fixed" if fixed else "fix_failed",
                "issue": "ISS-269",
                "flag": flag_key,
                "was": actual or "(unset)",
            }
    return report


def _check_code_sha_drift(suffix: str) -> Dict[str, Any]:
    """
    DOC-D45141D94C55: compare live CodeSha256 against known-good post-patch values.
    Detection only — drift means a CI rebuild erased out-of-band patches (ENC-TSK-F55 backport
    PR must land before any rebuild of github_integration or deploy_intake).
    """
    report: Dict[str, Any] = {}
    for base, expected_sha in _KNOWN_GOOD_SHA.items():
        fn_name = f"{base}{suffix}"
        cfg = _get_fn_config(fn_name)
        if cfg is None:
            report[fn_name] = {"status": "not_found"}
            continue
        live_sha = cfg.get("CodeSha256", "")
        if live_sha == expected_sha:
            report[fn_name] = {"status": "ok"}
        else:
            report[fn_name] = {
                "status": "drift_detected",
                "issue": "DOC-D45141D94C55",
                "expected": expected_sha,
                "live": live_sha,
                "action": "ENC-TSK-F55 backport PR required before next deploy",
            }
    return report


def _check_mcp_gamma_twin() -> Dict[str, Any]:
    """
    ISS-279: verify enceladus-mcp-code-gamma exists and is Active.
    Detection only — creation requires io-dev-admin.
    """
    cfg = _get_fn_config("enceladus-mcp-code-gamma")
    if cfg is None:
        return {
            "enceladus-mcp-code-gamma": {
                "status": "missing",
                "issue": "ISS-279",
                "action": "io-dev-admin: aws lambda create-function (see DOC-D45141D94C55 §1.4)",
            }
        }
    state = cfg.get("State", "Unknown")
    return {
        "enceladus-mcp-code-gamma": {
            "status": "ok" if state == "Active" else "inactive",
            "state": state,
        }
    }


# ---------------------------------------------------------------------------
# DPL record inspection + autonomous fixes
# ---------------------------------------------------------------------------
def _get_queued_dpls(project_id: str = "enceladus") -> List[Dict]:
    """Query deploy pipeline table for non-terminal DPL records."""
    try:
        resp = _get_ddb().query(
            TableName=DEPLOY_TABLE,
            KeyConditionExpression="project_id = :p",
            FilterExpression="#s IN (:pending, :queued, :approved, :awaiting)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":p":       {"S": project_id},
                ":pending": {"S": "pending_approval"},
                ":queued":  {"S": "queued"},
                ":approved": {"S": "approved"},
                ":awaiting": {"S": "awaiting_prod_approval"},
            },
        )
        return resp.get("Items", [])
    except ClientError as e:
        logger.error("DPL query failed: %s", e)
        return []


def _patch_dpl_field(project_id: str, record_id: str, field: str, value: str,
                      condition_field: Optional[str] = None,
                      condition_values: Optional[List[str]] = None) -> bool:
    """
    Update a single metadata field on a DPL record.
    Optional ConditionExpression guards against overwriting terminal rows (ENC-LSN-044).
    """
    kwargs: Dict[str, Any] = {
        "TableName": DEPLOY_TABLE,
        "Key": {
            "project_id": {"S": project_id},
            "record_id":  {"S": record_id},
        },
        "UpdateExpression": "SET #f = :v",
        "ExpressionAttributeNames": {"#f": field},
        "ExpressionAttributeValues": {":v": {"S": value}},
    }
    if condition_field and condition_values:
        placeholders = [f":cv{i}" for i in range(len(condition_values))]
        kwargs["ConditionExpression"] = f"#cf IN ({', '.join(placeholders)})"
        kwargs["ExpressionAttributeNames"]["#cf"] = condition_field
        for ph, cv in zip(placeholders, condition_values):
            kwargs["ExpressionAttributeValues"][ph] = {"S": cv}
    try:
        _get_ddb().update_item(**kwargs)
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ConditionalCheckFailedException":
            logger.info("DPL patch skipped (condition not met): %s.%s", record_id, field)
        else:
            logger.error("DPL patch failed %s.%s: %s", record_id, field, e)
        return False


def _scan_stuck_dpls(dpls: List[Dict], pr_number: int) -> List[Dict]:
    """
    Identify DPL rows that appear stuck: they have an approved/awaiting status but no
    deployment_outcome set and submitted_at is >10 minutes ago. These may be victims
    of the Patch 4 scan-widening regression (DOC-D45141D94C55 §1.1 fn4).
    """
    stuck = []
    now = time.time()
    for row in dpls:
        status  = row.get("status",  {}).get("S", "")
        sub_at  = row.get("submitted_at", {}).get("S", "")
        outcome = row.get("deployment_outcome", {}).get("S", "")
        pr_ref  = row.get("related_pr_number", {}).get("N", "0")
        if status in ("approved", "awaiting_prod_approval") and not outcome:
            try:
                age_s = now - time.mktime(time.strptime(sub_at[:19], "%Y-%m-%dT%H:%M:%S"))
                if age_s > 600:
                    stuck.append({
                        "record_id": row.get("record_id", {}).get("S", ""),
                        "status": status,
                        "age_minutes": round(age_s / 60, 1),
                        "pr_ref": pr_ref,
                    })
            except (ValueError, OverflowError):
                pass
    return stuck


# ---------------------------------------------------------------------------
# function_name_map gap detection (ISS-296)
# ---------------------------------------------------------------------------
def _fn_map_gaps(fn_map: Dict[str, str], lambda_dirs: List[str]) -> List[str]:
    return [d for d in lambda_dirs if d not in fn_map and d not in _MAP_EXCLUSIONS]


# ---------------------------------------------------------------------------
# GH Deployments API polling
# ---------------------------------------------------------------------------
def _poll_gh_deployment(repo: str, commit_sha: str, env_name: str = "v4-gamma",
                         timeout_s: int = 1800, interval_s: int = 30) -> Dict:
    token = _github_token()
    if not token:
        return {"state": "unknown", "error": "no_github_token"}

    gh_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    deadline = time.time() + timeout_s
    deployment_id: Optional[int] = None

    list_url = (f"https://api.github.com/repos/{repo}/deployments"
                f"?ref={commit_sha}&environment={env_name}&per_page=5")
    while time.time() < deadline:
        status, data = _http("GET", list_url, extra_headers=gh_headers)
        if status == 200 and isinstance(data, list) and data:
            deployment_id = data[0]["id"]
            break
        time.sleep(interval_s)

    if not deployment_id:
        return {"state": "not_found", "error": "deployment_record_not_created"}

    status_url = (f"https://api.github.com/repos/{repo}/deployments"
                  f"/{deployment_id}/statuses")
    while time.time() < deadline:
        status, data = _http("GET", status_url, extra_headers=gh_headers)
        if status == 200 and isinstance(data, list) and data:
            state = data[0].get("state", "")
            if state in ("success", "failure", "error", "inactive"):
                return {"state": state, "deployment_id": deployment_id, "status": data[0]}
        time.sleep(interval_s)

    return {"state": "timeout", "deployment_id": deployment_id}


# ---------------------------------------------------------------------------
# Document API helpers
# ---------------------------------------------------------------------------
def _write_readiness_doc(doc_id: str, pr_number: int, commit_sha: str,
                          checks: Dict) -> bool:
    if not DOCUMENT_API_URL:
        logger.warning("DOCUMENT_API_URL not set — skipping readiness DOC write")
        return False
    verdict = "ready"
    for section in checks.values():
        if isinstance(section, dict):
            for fn_report in section.values():
                if isinstance(fn_report, dict) and fn_report.get("status") in (
                    "fix_failed", "drift_detected", "missing", "inactive", "not_found"
                ):
                    verdict = "blocked"
                    break

    body = {
        "document_id": doc_id,
        "project_id": "enceladus",
        "title": f"Pre-merge readiness: PR #{pr_number} @ {commit_sha[:7]}",
        "content": json.dumps({
            "pr_number": pr_number,
            "commit_sha": commit_sha,
            "verdict": verdict,
            "checks": checks,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2),
        "doc_type": "deploy_readiness",
        "related_items": ["ENC-FTR-091", "ENC-TSK-F87"],
        "compliance_score": 100,
    }
    status, _ = _http("PUT", f"{DOCUMENT_API_URL}/documents", body=body)
    return status in (200, 201, 204)


def _patch_readiness_doc(doc_id: str, outcome: Dict) -> bool:
    if not DOCUMENT_API_URL:
        return False
    patch = {
        "patch": {
            "deploy_outcome": outcome,
            "patched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    }
    status, _ = _http("PATCH", f"{DOCUMENT_API_URL}/documents/{doc_id}", body=patch)
    return status in (200, 204)


# ---------------------------------------------------------------------------
# ENC-TSK-F64 / ENC-FTR-090 AC-20 — Daily drift audit
# ---------------------------------------------------------------------------

def _detect_and_poll_stack_drift(stack_name: str) -> Dict:
    """Trigger CFN detect_stack_drift, poll until complete or DRIFT_POLL_TIMEOUT."""
    cfn = _get_cfn()
    try:
        resp = cfn.detect_stack_drift(StackName=stack_name)
        detection_id = resp["StackDriftDetectionId"]
    except Exception as exc:
        return {"stack": stack_name, "status": "detection_error", "error": str(exc)}

    deadline = time.monotonic() + DRIFT_POLL_TIMEOUT
    while time.monotonic() < deadline:
        sr = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        ds = sr.get("DetectionStatus")
        if ds == "DETECTION_COMPLETE":
            drift_status = sr.get("StackDriftStatus", "UNKNOWN")
            return {
                "stack": stack_name,
                "drift_status": drift_status,
                "drifted_resource_count": sr.get("DriftedStackResourceCount", 0),
                "drifted": drift_status == "DRIFTED",
            }
        if ds == "DETECTION_FAILED":
            return {"stack": stack_name, "status": "detection_failed",
                    "reason": sr.get("DetectionStatusReason", "")}
        time.sleep(15)

    return {"stack": stack_name, "status": "detection_timeout", "detection_id": detection_id}


def _list_prod_lambda_names() -> List[str]:
    """Return all Lambda function names matching the devops-/enceladus- prefixes."""
    lc = _get_lambda()
    names: List[str] = []
    paginator = lc.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            name = fn.get("FunctionName", "")
            if any(name.startswith(p) for p in _LAMBDA_FN_PREFIXES):
                names.append(name)
    return names


def _audit_code_size(fn_names: List[str]) -> List[Dict]:
    """CodeSize < 1024 bytes = CFN ZipFile stub overwrite (ENC-FTR-068 AC-5)."""
    lc = _get_lambda()
    anomalies: List[Dict] = []
    for name in fn_names:
        try:
            cfg = lc.get_function_configuration(FunctionName=name)
            size = cfg.get("CodeSize", 0)
            if size < 1024:
                anomalies.append({"lambda": name, "code_size": size,
                                  "reason": "CFN ZipFile stub overwrite (ENC-FTR-068 AC-5)"})
        except Exception as exc:
            logger.warning("code_size check failed for %s: %s", name, exc)
    return anomalies


def _audit_snapstart_versions(fn_names: List[str]) -> List[Dict]:
    """Flag Lambdas with >SNAPSTART_MAX_STALE published versions (SnapStart cost trap)."""
    lc = _get_lambda()
    anomalies: List[Dict] = []
    for name in fn_names:
        try:
            resp = lc.list_versions_by_function(FunctionName=name, MaxItems=50)
            versions = [v for v in resp.get("Versions", []) if v.get("Version") != "$LATEST"]
            if len(versions) > SNAPSTART_MAX_STALE:
                anomalies.append({"lambda": name, "published_versions": len(versions),
                                  "reason": f"{len(versions)} published versions exceeds {SNAPSTART_MAX_STALE} — potential SnapStart storage cost trap"})
        except Exception as exc:
            logger.warning("snapstart version check failed for %s: %s", name, exc)
    return anomalies


def _publish_drift_alert(subject: str, lines: List[str]) -> None:
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set; skipping drift alert")
        return
    try:
        _get_sns().publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message="\n".join(lines)[:262144],
        )
        logger.info("drift alert published: %s", subject)
    except Exception as exc:
        logger.error("SNS publish failed: %s", exc)


def _run_daily_drift_audit() -> Dict:
    """
    ENC-FTR-090 AC-20 daily drift audit: CFN stack drift, CodeSize anomaly,
    SnapStart published-version count. Publishes SNS alert if any anomaly found.
    """
    run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    logger.info("[START] daily_drift_audit run_at=%s stacks=%s", run_at, CFN_DRIFT_STACKS)

    # 1. CFN stack drift
    cfn_results = [_detect_and_poll_stack_drift(s) for s in CFN_DRIFT_STACKS]
    cfn_anomalies = [r for r in cfn_results
                     if r.get("drifted") or r.get("status") in
                     ("detection_error", "detection_failed", "detection_timeout")]

    # 2 & 3. Lambda CodeSize + SnapStart version count
    fn_names = _list_prod_lambda_names()
    size_anomalies = _audit_code_size(fn_names)
    snap_anomalies = _audit_snapstart_versions(fn_names)

    total = len(cfn_anomalies) + len(size_anomalies) + len(snap_anomalies)

    if total > 0:
        lines = [f"deploy-parity-validator daily drift audit: {total} anomaly(ies) at {run_at}", ""]
        if cfn_anomalies:
            lines.append("=== CFN Stack Drift ===")
            for r in cfn_anomalies:
                detail = r.get("drift_status", r.get("status", ""))
                count = r.get("drifted_resource_count", "")
                lines.append(f"  {r['stack']}: {detail}" + (f" ({count} resources)" if count else ""))
        if size_anomalies:
            lines.append("=== CodeSize Anomaly (<1024 bytes — CFN stomp) ===")
            for a in size_anomalies:
                lines.append(f"  {a['lambda']}: {a['code_size']} bytes")
        if snap_anomalies:
            lines.append(f"=== SnapStart Version Count (>{SNAPSTART_MAX_STALE} stale) ===")
            for a in snap_anomalies:
                lines.append(f"  {a['lambda']}: {a['published_versions']} versions")
        _publish_drift_alert(
            subject=f"[drift-audit] {total} anomaly(ies) — {run_at}",
            lines=lines,
        )

    result = {
        "action": "daily_drift_audit",
        "run_at": run_at,
        "cfn_stacks_checked": len(cfn_results),
        "cfn_anomalies": len(cfn_anomalies),
        "lambdas_checked": len(fn_names),
        "code_size_anomalies": len(size_anomalies),
        "snapstart_anomalies": len(snap_anomalies),
        "total_anomalies": total,
        "alert_published": total > 0 and bool(SNS_TOPIC_ARN),
        "cfn_detail": cfn_results,
        "code_size_detail": size_anomalies,
        "snapstart_detail": snap_anomalies,
    }
    logger.info("[END] daily_drift_audit total_anomalies=%d", total)
    return result


# ---------------------------------------------------------------------------
# ENC-TSK-G43 / ENC-FTR-098 AC-7 — mentions_drift_audit
# ---------------------------------------------------------------------------
# Daily sample-and-diff: pull recently-mutated records, recompute the expected
# MENTIONS edge set with the same pure helper graph_sync uses on the live
# path (mentions_extraction.py, copied in via .build_extras), compare against
# Neo4j current state via graphsearch HTTP, emit an ENC-ISS record when the
# divergence ratio exceeds MENTIONS_AUDIT_THRESHOLD.
#
# Catches:
#   - graph_sync handler bugs (extractor regression silently dropping edges).
#   - SQS consumer lag where stream events fall behind real mutations.
#   - Silent placeholder-MERGE failures when target labels can't be inferred.
#
# Reuses the existing devops-parity-drift-daily EventBridge rule by chaining
# a synchronous call from _run_daily_drift_audit. Lambda timeout was raised to
# accommodate both passes in one invocation.

# Loaded via .build_extras at build time. Local import keeps import-time
# cost off cold paths (pre_merge/deploy_watch don't need it).
def _load_mentions_helpers():
    from mentions_extraction import (  # type: ignore[import-not-found]
        MENTIONS_PROSE_FIELDS,
        extract_id_tokens,
        strip_code_fences,
    )
    return MENTIONS_PROSE_FIELDS, extract_id_tokens, strip_code_fences


_TRACKER_RECORD_TYPES = (
    "task", "issue", "feature", "plan", "lesson", "generation",
)
_DOCUMENT_RECORD_TYPE = "document"


def _query_recent_records_by_type(table: str, index: str, record_type: str,
                                    limit: int) -> List[Dict]:
    """Query a (record_type, updated_at) GSI for the N most-recently-mutated rows.

    Used against `devops-project-tracker` + its `type-updated-index` GSI
    (HASH=record_type, RANGE=updated_at, Projection=INCLUDE). ScanIndexForward=False
    yields newest first; the caller MUST follow up with GetItem on the base
    table to obtain prose fields the GSI does not project. The documents
    table has a different shape — see _query_recent_documents.
    """
    try:
        resp = _get_ddb().query(
            TableName=table,
            IndexName=index,
            KeyConditionExpression="record_type = :rt",
            ExpressionAttributeValues={":rt": {"S": record_type}},
            ScanIndexForward=False,
            Limit=limit,
        )
        return resp.get("Items", [])
    except ClientError as e:
        logger.error("recent-records query failed table=%s rt=%s: %s",
                     table, record_type, e)
        return []


def _ddb_to_python(item: Dict) -> Dict[str, Any]:
    """Lossy DDB attribute-value -> python conversion for prose-field reads.

    Only handles the types the audit cares about: S (strings), N (numbers
    coerced to str), and BOOL. Lists/maps/binary are dropped because the
    extractor consumes only string prose fields.
    """
    out: Dict[str, Any] = {}
    for key, val in item.items():
        if "S" in val:
            out[key] = val["S"]
        elif "N" in val:
            out[key] = val["N"]
        elif "BOOL" in val:
            out[key] = val["BOOL"]
    return out


def _get_record_full(table: str, key: Dict[str, Dict]) -> Optional[Dict[str, Any]]:
    """GetItem and convert to a flat python dict the extractor can read."""
    try:
        resp = _get_ddb().get_item(TableName=table, Key=key, ConsistentRead=False)
    except ClientError as e:
        logger.warning("get_item failed table=%s key=%s: %s", table, key, e)
        return None
    item = resp.get("Item")
    return _ddb_to_python(item) if item else None


def _query_recent_documents(limit: int) -> List[Dict]:
    """Query the documents table's project-updated-index GSI for the N most-
    recently-mutated rows under project_id=enceladus.

    Documents are keyed (document_id HASH) only — the base table has no
    record_type or record_id. The project-updated-index GSI has Projection=ALL,
    so the rows returned here already include every prose field the audit
    needs; no follow-up GetItem is required.
    """
    try:
        resp = _get_ddb().query(
            TableName=DOCUMENTS_TABLE,
            IndexName="project-updated-index",
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": "enceladus"}},
            ScanIndexForward=False,
            Limit=limit,
        )
        return resp.get("Items", [])
    except ClientError as e:
        logger.error("recent-documents query failed: %s", e)
        return []


def _sample_recent_records(per_type_limit: int) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Return ~sample_size (record_type, record_id, full_record) tuples.

    Distributes the sample across MENTIONS_PROSE_FIELDS record_types so a
    single high-traffic type cannot starve the others.
    """
    sample: List[Tuple[str, str, Dict[str, Any]]] = []

    # Tracker: query type-updated-index per record_type, then GetItem each
    # row from the base table (the GSI projection is INCLUDE, not ALL).
    for rt in _TRACKER_RECORD_TYPES:
        rows = _query_recent_records_by_type(
            TRACKER_TABLE, "type-updated-index", rt, per_type_limit,
        )
        for row in rows:
            project_id = row.get("project_id", {}).get("S", "")
            record_id  = row.get("record_id", {}).get("S", "")
            if not project_id or not record_id:
                continue
            full = _get_record_full(
                TRACKER_TABLE,
                {"project_id": {"S": project_id}, "record_id": {"S": record_id}},
            )
            if full:
                sample.append((rt, record_id, full))

    # Documents: GSI projection is ALL so the query result is already complete.
    for row in _query_recent_documents(per_type_limit):
        document_id = row.get("document_id", {}).get("S", "")
        if not document_id:
            continue
        full = _ddb_to_python(row)
        sample.append((_DOCUMENT_RECORD_TYPE, document_id, full))

    return sample


def _expected_mentions_for(record_type: str, record_id: str, record: Dict[str, Any],
                            mentions_fields: Dict[str, Tuple[str, ...]],
                            extract_id_tokens: Any,
                            strip_code_fences: Any) -> Set[str]:
    """Mirror graph_sync._reconcile_mentions_edges' extraction logic exactly.

    Drift between the live and audit extractors here would surface as
    false-positive ENC-ISS records, so the helper module is shared (live
    path imports from graph_sync/, audit path imports the same file via
    .build_extras) and this function applies identical rules: fence-strip,
    extract, drop self-mentions.
    """
    fields = mentions_fields.get(record_type, ())
    expected: Set[str] = set()
    for field_name in fields:
        value = record.get(field_name, "")
        if not isinstance(value, str) or not value:
            continue
        cleaned = strip_code_fences(value)
        tokens = extract_id_tokens(cleaned)
        tokens.discard(record_id)
        expected |= tokens
    return expected


def _graphsearch_url() -> str:
    """Resolve the graphsearch endpoint, falling back to the tracker base."""
    if GRAPHSEARCH_URL:
        return GRAPHSEARCH_URL
    if TRACKER_API_URL:
        return f"{TRACKER_API_URL}/graphsearch"
    return ""


def _current_mentions_for(record_id: str, project_id: str = "enceladus") -> Optional[Set[str]]:
    """Query graphsearch for outgoing MENTIONS edges from this record.

    Returns None on transport error so the caller can skip the record
    rather than score it as zero-divergence (which would mask audit gaps).
    """
    url = _graphsearch_url()
    if not url:
        return None
    qs = (f"?project_id={project_id}&search_type=neighbors&record_id={record_id}"
          f"&edge_types=MENTIONS&direction=outgoing&depth=1")
    status, body = _http("GET", url + qs)
    if status != 200 or not isinstance(body, dict):
        return None
    targets: Set[str] = set()
    for edge in body.get("edges", []) or []:
        target = edge.get("target") or edge.get("to") or edge.get("target_id")
        if isinstance(target, str) and target:
            targets.add(target)
    # Some graphsearch responses surface the neighbors as `nodes` with the
    # source filtered out; consume that shape too.
    if not targets:
        for node in body.get("nodes", []) or []:
            nid = node.get("record_id") or node.get("id")
            if isinstance(nid, str) and nid and nid != record_id:
                targets.add(nid)
    return targets


def _emit_drift_iss(run_at: str, sample_size: int, mismatch_count: int,
                     divergent: List[Dict]) -> Optional[str]:
    """Create an ENC-ISS record via tracker_api when the threshold is breached.

    Returns the new record_id on success, None on failure (already logged).
    """
    if not TRACKER_API_URL:
        logger.warning("TRACKER_API_URL not set; cannot emit drift ENC-ISS")
        return None

    detail_lines = [
        f"mentions_drift_audit run_at={run_at}",
        f"sample_size={sample_size} mismatch_count={mismatch_count} ratio={mismatch_count / max(sample_size, 1):.4f}",
        "First divergent records:",
    ]
    for d in divergent[:10]:
        detail_lines.append(
            f"  {d['record_id']} ({d['record_type']}): "
            f"missing={sorted(d['missing'])[:5]} extra={sorted(d['extra'])[:5]}"
        )

    # tracker_mutation route: POST /api/v1/tracker/{project}/{type}.
    # TRACKER_API_URL is the .../api/v1/tracker base, so we append /enceladus/issue.
    # tracker_mutation requires issue records to ship at least one evidence
    # entry with description + steps_to_duplicate (ENC-TSK-805 issue schema).
    repro_steps = [
        "1. Wait for the next scheduled mentions_drift_audit run (cron(0 10 * * ? *) via devops-parity-drift-daily).",
        "2. Inspect /aws/lambda/devops-deploy-parity-validator CloudWatch logs for [START]/[END] mentions_drift_audit lines and the divergent_first_10 payload.",
        "3. For each record_id in divergent_first_10, run search(action='tracker.graphsearch', arguments={record_id, search_type='neighbors', edge_types=['MENTIONS'], direction='outgoing', depth=1}) and compare against the prose-extractor output for the same record.",
    ]
    body = {
        "title":       f"MENTIONS drift detected — {mismatch_count}/{sample_size} records divergent",
        "description": "\n".join(detail_lines),
        "category":    "bug",
        "priority":    "P2",
        "source":      "mentions_drift_audit",
        "evidence": [
            {
                "description":      "\n".join(detail_lines),
                "steps_to_duplicate": repro_steps,
            }
        ],
    }
    status, resp = _http("POST", f"{TRACKER_API_URL}/enceladus/issue", body=body)
    if status not in (200, 201):
        logger.error("[ERROR] drift ENC-ISS create failed status=%s body=%s",
                     status, resp)
        return None
    new_id = (resp or {}).get("item_id") or (resp or {}).get("record_id", "")
    logger.info("[INFO] drift ENC-ISS emitted: %s", new_id)
    return new_id


def _run_mentions_drift_audit() -> Dict:
    """Sample 100 recent records, diff expected vs live MENTIONS edges, emit ISS on >threshold."""
    run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    logger.info("[START] mentions_drift_audit run_at=%s sample_target=%d threshold=%.4f",
                run_at, MENTIONS_AUDIT_SAMPLE_SIZE, MENTIONS_AUDIT_THRESHOLD)

    try:
        mentions_fields, extract_id_tokens, strip_code_fences = _load_mentions_helpers()
    except Exception as exc:
        logger.error("[ERROR] mentions_extraction import failed: %s", exc)
        return {
            "action": "mentions_drift_audit",
            "run_at": run_at,
            "status": "error",
            "error":  f"mentions_extraction import failed: {exc}",
        }

    # Distribute sample across the 6 tracker types + documents, +1 per-type
    # buffer to absorb GetItem misses.
    types_total = len(_TRACKER_RECORD_TYPES) + 1
    per_type_limit = max(1, MENTIONS_AUDIT_SAMPLE_SIZE // types_total + 2)

    sample = _sample_recent_records(per_type_limit)
    if len(sample) > MENTIONS_AUDIT_SAMPLE_SIZE:
        sample = sample[:MENTIONS_AUDIT_SAMPLE_SIZE]

    logger.info("[INFO] mentions_drift_audit sampled=%d records", len(sample))

    divergent: List[Dict] = []
    skipped = 0

    for record_type, record_id, record in sample:
        expected = _expected_mentions_for(
            record_type, record_id, record, mentions_fields,
            extract_id_tokens, strip_code_fences,
        )
        current = _current_mentions_for(record_id)
        if current is None:
            skipped += 1
            continue
        missing = expected - current
        extra   = current - expected
        if missing or extra:
            divergent.append({
                "record_id":   record_id,
                "record_type": record_type,
                "missing":     list(missing),
                "extra":       list(extra),
            })

    effective_sample = max(len(sample) - skipped, 1)
    mismatch_count   = len(divergent)
    ratio            = mismatch_count / effective_sample
    breach           = ratio > MENTIONS_AUDIT_THRESHOLD

    iss_record_id: Optional[str] = None
    if breach:
        iss_record_id = _emit_drift_iss(run_at, effective_sample, mismatch_count, divergent)

    result: Dict[str, Any] = {
        "action":            "mentions_drift_audit",
        "run_at":            run_at,
        "status":            "ok",
        "sample_size":       len(sample),
        "skipped_transport": skipped,
        "effective_sample":  effective_sample,
        "mismatch_count":    mismatch_count,
        "mismatch_ratio":    round(ratio, 4),
        "threshold":         MENTIONS_AUDIT_THRESHOLD,
        "threshold_breached": breach,
        "iss_emitted":       iss_record_id,
        "divergent_first_10": [
            {
                "record_id":   d["record_id"],
                "record_type": d["record_type"],
                "missing":     sorted(d["missing"])[:5],
                "extra":       sorted(d["extra"])[:5],
            }
            for d in divergent[:10]
        ],
    }
    logger.info("[END] mentions_drift_audit mismatch=%d/%d ratio=%.4f breached=%s iss=%s",
                mismatch_count, effective_sample, ratio, breach, iss_record_id or "-")
    return result


# ---------------------------------------------------------------------------
# Pre-merge analysis + fix pass
# ---------------------------------------------------------------------------
def _run_pre_merge(event: Dict) -> Dict:
    pr_number    = event.get("pr_number", 0)
    commit_sha   = event.get("commit_sha") or event.get("head_sha", "unknown")
    fn_map       = event.get("function_name_map", {})
    lambda_dirs  = event.get("lambda_dirs", [])
    suffix       = ENVIRONMENT_SUFFIX  # "" = prod, "-gamma" = gamma

    checks: Dict[str, Any] = {}

    # Rule: ISS-273/283 — COORDINATION_INTERNAL_API_KEY on DM + graph Lambdas
    checks["internal_key_vars"] = _check_internal_key_vars(suffix)

    # Rule: ISS-269 — MCP feature flags
    checks["mcp_feature_flags"] = _check_mcp_feature_flags(suffix)

    # Rule: ISS-279 — mcp-code-gamma twin (only relevant on prod; gamma already IS the twin)
    if not suffix:
        checks["mcp_gamma_twin"] = _check_mcp_gamma_twin()

    # Rule: DOC-D45141D94C55 — CodeSha256 drift on patched Lambdas
    checks["code_sha_drift"] = _check_code_sha_drift(suffix)

    # Rule: ISS-296 — function_name_map gaps
    gaps = _fn_map_gaps(fn_map, lambda_dirs)
    checks["function_name_map_gaps"] = {
        "status": "ok" if not gaps else "gaps_detected",
        "gaps": gaps,
        "issue": "ISS-296" if gaps else None,
        "action": "add entries to envs/*.yaml function_name_map in this PR" if gaps else None,
    }

    # DPL record scan — stuck rows
    dpls = _get_queued_dpls()
    stuck = _scan_stuck_dpls(dpls, pr_number)
    checks["dpl_stuck_rows"] = {
        "status": "ok" if not stuck else "stuck_detected",
        "stuck": stuck,
        "queued_total": len(dpls),
    }

    doc_id = f"readiness-pr{pr_number}-{commit_sha[:7]}"
    _write_readiness_doc(doc_id, pr_number, commit_sha, checks)

    verdict = "ready"
    for section in checks.values():
        if isinstance(section, dict):
            if section.get("status") in ("fix_failed", "drift_detected", "missing",
                                          "inactive", "gaps_detected", "stuck_detected"):
                verdict = "blocked"
                break
            for sub in section.values():
                if isinstance(sub, dict) and sub.get("status") in (
                    "fix_failed", "drift_detected", "missing", "inactive", "not_found"
                ):
                    verdict = "blocked"
                    break

    logger.info("[START] pre_merge PR #%d commit=%s verdict=%s", pr_number, commit_sha[:7], verdict)
    return {
        "action": "pre_merge",
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "verdict": verdict,
        "checks": checks,
        "readiness_doc_id": doc_id,
    }


# ---------------------------------------------------------------------------
# Deploy watch
# ---------------------------------------------------------------------------
def _run_deploy_watch(event: Dict) -> Dict:
    pr_number   = event.get("pr_number", 0)
    commit_sha  = event.get("commit_sha") or event.get("merge_commit_sha", "unknown")
    repo        = event.get("repo", "NX-2021-L/enceladus")
    doc_id      = event.get("readiness_doc_id",
                            f"readiness-pr{pr_number}-{commit_sha[:7]}")
    env_name    = "v4-gamma" if ENVIRONMENT_SUFFIX == "-gamma" else "v3-prod"

    logger.info("[START] deploy_watch PR #%d commit=%s", pr_number, commit_sha[:7])
    outcome = _poll_gh_deployment(repo, commit_sha, env_name=env_name)
    _patch_readiness_doc(doc_id, outcome)

    # Post-deploy: re-check CodeSha256 drift (may have regressed from this deploy)
    sha_drift = _check_code_sha_drift(ENVIRONMENT_SUFFIX)
    patched = _patch_readiness_doc(doc_id, {
        "deploy_outcome": outcome,
        "post_deploy_sha_drift": sha_drift,
        "patched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    logger.info("[END] deploy_watch PR #%d state=%s", pr_number, outcome.get("state"))
    return {
        "action": "deploy_watch",
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "deploy_outcome": outcome,
        "post_deploy_sha_drift": sha_drift,
        "readiness_doc_id": doc_id,
        "doc_patched": patched,
    }


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event: Dict, context: Any) -> Dict:
    action = event.get("action", "pre_merge_check")
    logger.info("[START] deploy_parity_validator action=%s", action)

    try:
        if action in ("pre_merge_check", "pr_opened", "pr_synchronize", "parity_check"):
            result = _run_pre_merge(event)
        elif action in ("deploy_watch", "pr_merged"):
            result = _run_deploy_watch(event)
        elif action == "daily_drift_audit":
            # ENC-TSK-F64 / ENC-FTR-090 AC-20 — triggered by devops-parity-drift-daily schedule.
            # ENC-TSK-G43 chains mentions_drift_audit into the same daily slot per the spec
            # ("schedule daily at the existing cron(0 10 * * ? *) slot via the EventBridge
            # rule devops-parity-drift-daily"); a failure in one pass does not skip the other.
            result = _run_daily_drift_audit()
            try:
                result["mentions_audit"] = _run_mentions_drift_audit()
            except Exception as mexc:
                logger.exception("[ERROR] mentions_drift_audit chain failed: %s", mexc)
                result["mentions_audit"] = {
                    "action": "mentions_drift_audit",
                    "status": "error",
                    "error":  str(mexc),
                }
        elif action == "mentions_drift_audit":
            # ENC-TSK-G43 / ENC-FTR-098 AC-7 — direct dispatch for ad-hoc invocation.
            result = _run_mentions_drift_audit()
        else:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": f"Unknown action: {action}"}),
            }
        logger.info("[END] deploy_parity_validator action=%s", action)
        return {"statusCode": 200, "body": json.dumps(result)}

    except Exception as exc:
        logger.exception("[ERROR] deploy_parity_validator: %s", exc)
        return {"statusCode": 500, "body": json.dumps({"error": str(exc)})}
