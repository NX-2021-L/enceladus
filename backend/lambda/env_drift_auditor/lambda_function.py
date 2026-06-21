"""env_drift_auditor — ENC-ISS-283.

Hourly scanner that checks each Lambda in env_drift_registry.json for
missing or placeholder values in its REQUIRED_ENV list. On drift it files a
P0 tracker issue via the internal-key tracker API — idempotently: a finding
already tracked by an open issue is bumped, not re-filed (ENC-TSK-H10).

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
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3

# ENC-TSK-H19: shared comparison core — single source for pre- and post-deploy.
# ENC-TSK-H16: critical_vars/advisory_vars read the per-var deploy-critical vs
# advisory classification from the same core, so the auditor and the pre-deploy
# gate split the registry the same way (no second copy).
# ENC-TSK-H10: drift_signature/sig_token/find_signature_match give a finding a
# stable identity so the auditor dedups against an already-open issue (below).
from env_parity_core import (
    advisory_vars,
    build_placeholders,
    classify_required,
    critical_vars,
    drift_signature,
    find_signature_match,
    sig_token,
)

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
# ENC-TSK-H10: cap the open-issue dedup scan. 200/page * 10 pages = 2000 open
# issues, far above any real backlog; bounds the hourly query if the listing ever
# balloons.
_MAX_ISSUE_PAGES = 10

# Load registry bundled with the Lambda package
_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "env_drift_registry.json")
with open(_REGISTRY_PATH) as _f:
    REGISTRY = json.load(_f)

# ENC-TSK-H19 AC2: placeholder set now built by the shared env_parity_core so the
# pre-deploy strip detector and this post-deploy auditor cannot diverge.
PLACEHOLDER_VALUES = build_placeholders(REGISTRY.get("_policy", {}))


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
    # ENC-TSK-H19 AC2: delegate to the shared comparison core (no divergent impl).
    drift = classify_required(required, env_vars, PLACEHOLDER_VALUES)
    if drift:
        return "drift", drift
    return "ok", []


def _file_drift_issue(
    fn_name: str, drift: List[Dict[str, Any]], run_id: str, signature: str
) -> Dict[str, Any]:
    """File a NEW P0 drift issue (ENC-TSK-H10).

    The title carries ``sig_token(signature)`` and the evidence carries the structured
    ``drift_signature`` so a later run can find and bump this record instead of
    re-filing. ``_handle_drift_finding`` only reaches here when no open issue already
    carries this signature, so DRY_RUN and the dedup decision live in the caller.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    missing_vars = ", ".join(d["var"] for d in drift if d.get("var"))
    body = {
        "title": (
            f"[auto-drift] {fn_name} missing required env vars: {missing_vars} "
            f"{sig_token(signature)}"
        ),
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
                "drift_signature": signature,
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
            return {"status": resp.status, "filed": True, "signature": signature,
                    "body": json.loads(resp.read())}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "filed": True, "signature": signature,
                "error": exc.read().decode("utf-8", errors="replace")}
    except Exception as exc:
        logger.exception("tracker.create failed")
        return {"status": 0, "filed": True, "signature": signature, "error": str(exc)}


def _fetch_open_issues() -> List[Dict[str, Any]]:
    """GET every OPEN issue record (paginated) via the internal-key tracker API.

    Used to dedup a drift finding against an issue the auditor already filed
    (ENC-TSK-H10). Raises on transport/HTTP error so the caller can decide whether to
    fail open to filing.
    """
    issues: List[Dict[str, Any]] = []
    cursor = ""
    for _ in range(_MAX_ISSUE_PAGES):
        url = f"{TRACKER_API_BASE}/{PROJECT_ID}?type=issue&status=open&page_size=200"
        if cursor:
            url += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read())
        issues.extend(payload.get("records", []))
        cursor = payload.get("next_cursor", "")
        if not cursor:
            break
    return issues


def _find_existing_drift_issue(signature: str) -> Tuple[Optional[str], bool]:
    """Return (matched_issue_id, query_ok) for an OPEN issue carrying ``signature``.

    query_ok=False means the lookup itself failed; the caller fails OPEN to filing so a
    transient query error never silently drops a real finding (ENC-TSK-H10).
    """
    try:
        issues = _fetch_open_issues()
    except Exception:
        logger.exception("open-issue dedup query failed")
        return None, False
    return find_signature_match(issues, signature), True


def _bump_drift_issue(issue_id: str, fn_name: str, run_id: str, now: str) -> Dict[str, Any]:
    """Append a worklog to an already-open drift issue instead of filing a duplicate
    (ENC-TSK-H10 AC-1). Records that the drift is STILL present at this run, so a
    persistent finding leaves a recurrence trail rather than an hourly P0 storm."""
    body = {
        "description": (
            f"[auto-drift] still present on {fn_name} at {now} (auditor run_id={run_id}). "
            f"Drift unresolved since this issue was filed; bumping instead of filing a "
            f"duplicate P0 (ENC-TSK-H10 signature dedup)."
        ),
        "write_source": {"provider": "env-drift-auditor"},
    }
    req = urllib.request.Request(
        f"{TRACKER_API_BASE}/{PROJECT_ID}/issue/{issue_id}/log",
        method="POST",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"status": resp.status, "deduped": True, "issue_id": issue_id}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "deduped": True, "issue_id": issue_id,
                "error": exc.read().decode("utf-8", errors="replace")}
    except Exception as exc:
        logger.exception("drift issue bump failed for %s", issue_id)
        return {"status": 0, "deduped": True, "issue_id": issue_id, "error": str(exc)}


def _handle_drift_finding(fn_name: str, drift: List[Dict[str, Any]], run_id: str) -> Dict[str, Any]:
    """Idempotent drift emission (ENC-TSK-H10).

    Computes the (lambda, missing-var) signature and, unless an OPEN issue already
    carries it, files a single P0. On a signature match it BUMPS the existing issue
    instead — so one persistent finding yields one record plus hourly worklog bumps,
    not the hourly P0 storm that produced ENC-ISS-369..379.
    """
    missing_var_names = [d["var"] for d in drift if d.get("var")]
    signature = drift_signature(fn_name, missing_var_names)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if DRY_RUN:
        logger.info("DRY_RUN: would emit drift for %s (sig=%s) — %s", fn_name, signature, drift)
        return {"dry_run": True, "signature": signature}

    existing_id, query_ok = _find_existing_drift_issue(signature)
    if existing_id:
        logger.info(
            "drift on %s already tracked by %s (sig=%s) — bumping, not re-filing",
            fn_name, existing_id, signature,
        )
        return _bump_drift_issue(existing_id, fn_name, run_id, now)
    if not query_ok:
        logger.warning(
            "open-issue dedup query failed for %s (sig=%s) — filing without dedup to "
            "avoid missing drift (ENC-TSK-H10 fail-open)", fn_name, signature,
        )
    return _file_drift_issue(fn_name, drift, run_id, signature)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    run_id = getattr(context, "aws_request_id", "manual-run")
    lambda_client = boto3.client("lambda", region_name=REGION)

    results: List[Dict[str, Any]] = []
    drift_count = 0
    ok_count = 0
    advisory_drift_count = 0

    for fn_name, spec in REGISTRY.get("lambdas", {}).items():
        # ENC-TSK-H16: P0 drift issues fire only for deploy-critical vars. Advisory
        # vars are reported but never file a P0 — the pre-deploy gate WARNs on them
        # too, so the post-deploy auditor and the gate classify the registry the
        # same way. critical_vars/advisory_vars also accept legacy flat-list entries
        # (every var deploy-critical), so pre-H16 registries behave unchanged.
        required = critical_vars(spec)
        status, drift = _audit_lambda(lambda_client, fn_name, required)
        entry: Dict[str, Any] = {"lambda": fn_name, "status": status}
        if drift:
            entry["drift"] = drift
            # ENC-TSK-H10: emit idempotently. A persistent finding is filed ONCE,
            # then bumped each hour — never re-filed. The old code filed
            # unconditionally on the assumption that a tracker-side dedup guard
            # collapsed identical titles; no such guard exists, so one finding
            # produced 11 byte-identical P0s (ENC-ISS-369..379).
            entry["issue_filed"] = _handle_drift_finding(fn_name, drift, run_id)
            drift_count += 1
        else:
            ok_count += 1

        advisory = advisory_vars(spec)
        if advisory:
            # Report-only: surface advisory misses without filing a P0 issue.
            _, adv_drift = _audit_lambda(lambda_client, fn_name, advisory)
            if adv_drift:
                entry["advisory_drift"] = adv_drift
                advisory_drift_count += 1
        results.append(entry)

    summary = {
        "run_id": run_id,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": ok_count,
        "drift": drift_count,
        "advisory_drift": advisory_drift_count,
        "total": ok_count + drift_count,
        "results": results,
    }
    logger.info(
        "env_drift_auditor run complete: ok=%d drift=%d advisory_drift=%d",
        ok_count, drift_count, advisory_drift_count,
    )
    return summary
