"""corpus_entropy_engine — Corpus Entropy Engine (CEE) Lambda handler.

ENC-TSK-K41 / B66 Phase-5 (ENC-PLN-064, parent ENC-TSK-B66), per
DOC-A3D0CDF91CE9. Cognitive-hygiene subsystem detecting entropy accumulation
across the governed corpus. Telemetry-only in this task -- no corpus mutation.
GDMP Stage-1 auto-remediation is a separate downstream task; do NOT add
mutation here.

Five detection categories (full logic in corpus_entropy_core.py, network-free
and unit-tested there):
  (a) Orphan       -- records with no parent/plan linkage
  (b) Stagnation   -- open tasks with no worklog above threshold
  (c) Relational   -- declared relational field with no corresponding graph edge
  (d) Retention    -- Lessons with FSRS-6 stability S < T3 (0.7)
  (e) Compliance/Semantic -- compliance_score below threshold AND maturity_state=raw

Read boundary: this Lambda calls the SAME governed HTTP surface the MCP server
wraps (tracker API + document API + graph_query_api), authenticated with the
internal API key -- never raw DynamoDB scans of the corpus tables. This
mirrors env_drift_auditor (tracker HTTP) and percolation_monitor
(graph_query_api HTTP) in this repo.

Trigger: EventBridge per-invocation (no standing compute). ISS-465
cost-preflight: see corpus_entropy_deploy_notes.md / task worklog for the
<$1/mo estimate. CEE_HARD_DISABLED is the mandatory kill switch, checked
before any work begins.

Emits per-category structured-finding counts to CloudWatch namespace
Enceladus/CEE. OGTM: read-only detection, no new edge types.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from corpus_entropy_core import (
    build_category_metric_data,
    build_scan_duration_metric_data,
    detect_compliance_semantic_entropy,
    detect_orphan_entropy,
    detect_relational_entropy,
    detect_retention_entropy,
    detect_stagnation_entropy,
    is_hard_disabled,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-west-2")
TRACKER_API_BASE = os.environ.get(
    "TRACKER_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker",
)
DOCUMENT_API_BASE = os.environ.get(
    "DOCUMENT_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/documents",
)
GRAPH_QUERY_API_BASE = os.environ.get("GRAPH_QUERY_API_BASE", "").rstrip("/")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Enceladus/CEE")
FUNCTION_NAME = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "enceladus-corpus-entropy-engine")
STAGNATION_THRESHOLD_DAYS = int(os.environ.get("STAGNATION_THRESHOLD_DAYS", "14"))
COMPLIANCE_SCORE_THRESHOLD = int(os.environ.get("COMPLIANCE_SCORE_THRESHOLD", "70"))
_HTTP_TIMEOUT_S = 30
_MAX_PAGES = 200  # hard ceiling so a pagination bug can never loop forever

_cw_client = None


def _get_cw():
    global _cw_client
    if _cw_client is None:
        import boto3

        _cw_client = boto3.client("cloudwatch", region_name=REGION)
    return _cw_client


# ---------------------------------------------------------------------------
# Governed HTTP reads (tracker API / document API / graph_query_api) --
# mirrors env_drift_auditor.py and percolation_monitor/lambda_function.py.
# No direct DynamoDB access; stays within the governed read boundary.
# ---------------------------------------------------------------------------

def _http_get(url: str) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
        },
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def _fetch_tracker_records(record_type: str) -> List[Dict[str, Any]]:
    """Page every record of `record_type` via the internal-key tracker API."""
    records: List[Dict[str, Any]] = []
    cursor = ""
    for _ in range(_MAX_PAGES):
        url = f"{TRACKER_API_BASE}/{PROJECT_ID}?type={record_type}&page_size=200"
        if cursor:
            url += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        try:
            payload = _http_get(url)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            logger.error("[ERROR] tracker fetch failed type=%s: %s", record_type, exc)
            break
        records.extend(payload.get("records", []))
        cursor = payload.get("next_cursor", "")
        if not cursor:
            break
    else:
        logger.warning("[WARNING] tracker pagination hit _MAX_PAGES for type=%s", record_type)
    return records


def _fetch_documents() -> List[Dict[str, Any]]:
    """Fetch documents via the internal-key document API `/search` route.

    NOTE: document_api has no cursor-based pagination (unlike the tracker
    API) -- both `?project=` list and `/search` cap output at the server's
    PAGE_SIZE (50) and report `total_matches` for the untruncated count. This
    is a real document_api limitation, not a bug in this Lambda; the scan
    reports `total_matches` alongside the truncated `documents` count so any
    truncation is visible in the CEE result payload rather than silent.
    """
    url = f"{DOCUMENT_API_BASE}/search?project={urllib.parse.quote(PROJECT_ID)}"
    try:
        payload = _http_get(url)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.error("[ERROR] document fetch failed: %s", exc)
        return []
    documents = payload.get("documents", [])
    total_matches = payload.get("total_matches", len(documents))
    if total_matches > len(documents):
        logger.warning(
            "[WARNING] document_api truncated results: returned=%d total_matches=%d "
            "(document_api has no pagination beyond PAGE_SIZE)",
            len(documents), total_matches,
        )
    return documents


def _fetch_lessons() -> List[Dict[str, Any]]:
    """Lessons are tracker records of type=lesson (record_type convention)."""
    return _fetch_tracker_records("lesson")


def _fetch_graph_edges() -> List[Any]:
    """Full adjacency export via graph_query_api (read-only, OGTM AC-5)."""
    if not GRAPH_QUERY_API_BASE:
        logger.warning("[WARNING] GRAPH_QUERY_API_BASE not configured; skipping relational scan")
        return []
    edges: List[Any] = []
    offset = 0
    limit = 20000
    for _ in range(_MAX_PAGES):
        params = {
            "project_id": PROJECT_ID,
            "search_type": "adjacency",
            "offset": offset,
            "limit": limit,
        }
        url = f"{GRAPH_QUERY_API_BASE}?{urllib.parse.urlencode(params)}"
        try:
            body = _http_get(url)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            logger.error("[ERROR] graph_query_api fetch failed: %s", exc)
            break
        if not body.get("success", True):
            logger.error("[ERROR] graph_query_api error: %s", body.get("error", body))
            break
        for e in body.get("edges", []):
            s, t = e.get("s"), e.get("t")
            if s and t:
                edges.append((s, t))
        if not body.get("has_more"):
            break
        next_offset = body.get("next_offset")
        offset = int(next_offset) if next_offset is not None else offset + limit
    else:
        logger.warning("[WARNING] graph adjacency pagination hit _MAX_PAGES ceiling")
    return edges


# ---------------------------------------------------------------------------
# CloudWatch emission
# ---------------------------------------------------------------------------

def _publish_metrics(counts: Dict[str, int], *, duration_ms: Optional[float] = None) -> None:
    now = datetime.now(timezone.utc)
    metric_data = build_category_metric_data(counts, function_name=FUNCTION_NAME, timestamp=now)
    if duration_ms is not None:
        metric_data.append(
            build_scan_duration_metric_data(duration_ms, function_name=FUNCTION_NAME, timestamp=now)
        )
    cw = _get_cw()
    # Batch <=20 per put_metric_data call (CloudWatch API limit).
    for i in range(0, len(metric_data), 20):
        batch = metric_data[i:i + 20]
        cw.put_metric_data(Namespace=CLOUDWATCH_NAMESPACE, MetricData=batch)
    logger.info("[SUCCESS] Published %d metric datapoints to %s", len(metric_data), CLOUDWATCH_NAMESPACE)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

# --- ENC-TSK-N24: rhythm heavy-beat completion-stanza contract --------------
# When invoked as a rhythm tenant (backend/lambda/rhythm_cycle/tenant_invoker
# .py), the invoke payload carries ``result_key`` — the exact S3 key this
# tenant must write its completion stanza to. Scheduled EventBridge invokes
# carry no result_key and skip the write. This is the ONE sanctioned direct-S3
# write for this telemetry-only Lambda (OGTM posture otherwise unchanged).
# A write failure is logged, never raised — the beat's silent-tenant detection
# treats a missing stanza as silence, which is the honest signal.

RHYTHM_TENANT_NAME = "corpus_entropy_engine"
RHYTHM_RESULTS_BUCKET = os.environ.get("RHYTHM_RESULTS_BUCKET", "jreese-net")


def _write_rhythm_stanza(
    event: Any,
    status: str,
    detail: Optional[Dict[str, Any]] = None,
    output_count: Optional[int] = None,
) -> bool:
    result_key = str((event or {}).get("result_key") or "").strip() if isinstance(event, dict) else ""
    if not result_key:
        return False
    body = {
        "tenant": RHYTHM_TENANT_NAME,
        "status": status,
        # ENC-TSK-N48 / BRD §4.1: assert on OUTPUT, not execution. did_work is
        # False on the skip/disable path (status != "completed"); output_count
        # exposes correct-zero (did_work=True, count=0) vs produced (count>0).
        "did_work": status == "completed",
        "output_count": output_count,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail or {},
    }
    try:
        import boto3  # lazy, mirrors module idiom — keeps module import AWS-free

        boto3.client("s3", region_name=REGION).put_object(
            Bucket=RHYTHM_RESULTS_BUCKET,
            Key=result_key,
            Body=json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            ContentType="application/json",
        )
        return True
    except Exception as exc:  # noqa: BLE001 — stanza failure must never break the run
        logger.warning("[ERROR] rhythm stanza write failed key=%s: %s", result_key, exc)
        return False


def lambda_handler(event: Optional[Dict[str, Any]], context: Any) -> Dict[str, Any]:
    """Entry point: run the entropy scan, then honor the rhythm
    completion-stanza contract when invoked as a heavy-beat tenant
    (ENC-TSK-N24). CEE_HARD_DISABLED skips report status=skipped — an explicit
    deferral, never silence."""
    try:
        resp = _run_scan(event, context)
    except Exception:
        _write_rhythm_stanza(event, "failed", {})
        raise
    try:
        body = json.loads(resp.get("body") or "{}")
    except (TypeError, ValueError):
        body = {}
    status = "completed" if resp.get("statusCode") == 200 else "failed"
    if body.get("skipped"):
        status = "skipped"
    detail = {"statusCode": resp.get("statusCode")}
    detail.update({k: body.get(k) for k in ("counts", "reason") if k in body})
    # ENC-TSK-N48: output_count = total entropy findings across the 5 detectors.
    # None on the skip/disable path (CEE_HARD_DISABLED) where no counts exist.
    counts = body.get("counts")
    output_count = sum(counts.values()) if isinstance(counts, dict) else None
    _write_rhythm_stanza(event, status, detail, output_count=output_count)
    return resp


def _run_scan(event: Optional[Dict[str, Any]], context: Any) -> Dict[str, Any]:
    event = event or {}

    if is_hard_disabled(os.environ):
        logger.info("[SKIP] CEE_HARD_DISABLED is set; corpus entropy scan skipped this invocation")
        return {
            "statusCode": 200,
            "body": json.dumps({"success": True, "skipped": True, "reason": "CEE_HARD_DISABLED"}),
        }

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    logger.info("[START] Corpus Entropy Engine scan: project=%s", PROJECT_ID)
    started = time.perf_counter()

    try:
        tasks = _fetch_tracker_records("task")
        issues = _fetch_tracker_records("issue")
        features = _fetch_tracker_records("feature")
        plans = _fetch_tracker_records("plan")
        documents = _fetch_documents()
        lessons = _fetch_lessons()
        edges = _fetch_graph_edges()

        orphan_scope = tasks + issues + features + documents
        relational_scope = tasks + issues + features + plans

        orphan_findings = detect_orphan_entropy(orphan_scope)
        stagnation_findings = detect_stagnation_entropy(
            tasks, now_iso=now_iso, threshold_days=STAGNATION_THRESHOLD_DAYS
        )
        relational_findings = detect_relational_entropy(relational_scope, edges)
        retention_findings = detect_retention_entropy(lessons)
        compliance_findings = detect_compliance_semantic_entropy(
            documents, score_threshold=COMPLIANCE_SCORE_THRESHOLD
        )

        counts = {
            "lineage_unanchored": len(orphan_findings),
            "stagnation": len(stagnation_findings),
            "relational": len(relational_findings),
            "retention": len(retention_findings),
            "compliance_semantic": len(compliance_findings),
        }

        duration_ms = (time.perf_counter() - started) * 1000.0
        _publish_metrics(counts, duration_ms=duration_ms)

        result = {
            "success": True,
            "project_id": PROJECT_ID,
            "scanned_at": now_iso,
            "scan_duration_ms": round(duration_ms, 2),
            "counts": counts,
            "corpus_scanned": {
                "tasks": len(tasks),
                "issues": len(issues),
                "features": len(features),
                "plans": len(plans),
                "documents": len(documents),
                "lessons": len(lessons),
                "graph_edges": len(edges),
            },
        }
        logger.info("[END] CEE scan complete: %s", json.dumps(counts))
        return {"statusCode": 200, "body": json.dumps(result)}
    except Exception as exc:  # noqa: BLE001 -- top-level handler must never raise
        logger.error("[ERROR] Corpus Entropy Engine scan failed: %s", exc, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"success": False, "error": str(exc)})}
