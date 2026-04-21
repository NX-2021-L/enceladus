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
from typing import Any, Dict, List, Optional, Tuple

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
