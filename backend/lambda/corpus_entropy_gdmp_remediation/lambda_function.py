"""corpus_entropy_gdmp_remediation — GDMP Stage-1 auto-remediation Lambda handler.

ENC-TSK-K42 / B66 Phase-5 (ENC-PLN-064, parent ENC-TSK-B66), per
DOC-A3D0CDF91CE9. Consumes K41's Compliance/Semantic detector output
(corpus_entropy_core.detect_compliance_semantic_entropy) and deterministically
resolves a whitelist of `compliance_warnings` classes via `documents.patch`,
advancing raw documents to compliant `document_maturity_state` with no agent
session involvement.

Read/write boundary: this Lambda calls the SAME governed HTTP surface the MCP
server wraps (tracker API for the compliance/semantic scan reuse + document
API for GET/PATCH), authenticated with the internal API key — never raw
DynamoDB/S3 writes. Mirrors corpus_entropy_engine/lambda_function.py (K41)
for reads and adds governed PATCH calls for remediation.

DATA-SAFETY:
  * GDMP_DRY_RUN=1 (default) — no document mutations, candidate report only.
  * GDMP_MUTATION_ENABLED=0 (default) — report-only even when dry_run off.
  * GDMP_IO_APPROVAL_RUNS=3 — first three live runs emit reports only
    (FTR-106 AC-4 / ENC-TSK-K03 io-approval-ramp pattern, reused verbatim).
  * Only the deterministic whitelist in gdmp_remediation_core.py is ever
    auto-patched; ambiguous/content-changing warnings are left for agent
    review. Every auto-patch is logged with before/after compliance_score.
  * CEE_GDMP_HARD_DISABLED is the mandatory kill switch, checked before any
    work begins (mirrors CEE_HARD_DISABLED / K41 convention).

Trigger: EventBridge per-invocation (no standing compute), scheduled after
the CEE nightly detection scan so remediation always sees fresh findings.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from corpus_entropy_core import detect_compliance_semantic_entropy, is_hard_disabled as _cee_is_hard_disabled
from gdmp_remediation_core import (
    COMPLIANT_MATURITY_STATE,
    build_candidate_report_body,
    is_already_compliant,
    is_dry_run,
    is_hard_disabled,
    mutation_allowed,
    plan_remediation,
    remediate_content,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-west-2")
DOCUMENT_API_BASE = os.environ.get(
    "DOCUMENT_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/documents",
)
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")
COMPLIANCE_SCORE_THRESHOLD = int(os.environ.get("COMPLIANCE_SCORE_THRESHOLD", "70"))
GDMP_STATE_BUCKET = os.environ.get("GDMP_STATE_BUCKET", "")
GDMP_STATE_PREFIX = os.environ.get("GDMP_STATE_PREFIX", "gdmp-remediation-state")
_HTTP_TIMEOUT_S = 30
_MAX_DOCS_PER_RUN = int(os.environ.get("GDMP_MAX_DOCS_PER_RUN", "200"))

_s3_client = None


def _get_s3():
    global _s3_client
    if _s3_client is None:
        import boto3

        _s3_client = boto3.client("s3", region_name=REGION)
    return _s3_client


# ---------------------------------------------------------------------------
# Governed HTTP (document API) -- mirrors corpus_entropy_engine/lambda_function.py.
# No direct DynamoDB/S3 document access; stays within the governed read/write
# boundary (internal API key auth against the same surface the MCP server wraps).
# ---------------------------------------------------------------------------

def _http_request(url: str, *, method: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
        },
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def _fetch_documents() -> List[Dict[str, Any]]:
    url = f"{DOCUMENT_API_BASE}/search?project={urllib.parse.quote(PROJECT_ID)}"
    try:
        payload = _http_request(url, method="GET")
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.error("[ERROR] document fetch failed: %s", exc)
        return []
    return payload.get("documents", [])


def _fetch_document_with_content(document_id: str) -> Optional[Dict[str, Any]]:
    url = f"{DOCUMENT_API_BASE}/{urllib.parse.quote(document_id, safe='')}"
    try:
        payload = _http_request(url, method="GET")
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.error("[ERROR] document GET failed id=%s: %s", document_id, exc)
        return None
    return payload.get("document") or payload


def _patch_document(document_id: str, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    url = f"{DOCUMENT_API_BASE}/{urllib.parse.quote(document_id, safe='')}"
    try:
        return _http_request(url, method="PATCH", body=body)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.error("[ERROR] document PATCH failed id=%s: %s", document_id, exc)
        return None


# ---------------------------------------------------------------------------
# io-approval ramp state (S3 run counter) -- verbatim pattern from
# unlearning/lambda_function.py (_load_run_counter / _save_run_counter).
# ---------------------------------------------------------------------------

def _load_run_counter() -> int:
    if not GDMP_STATE_BUCKET:
        return 0
    key = f"{GDMP_STATE_PREFIX.strip().strip('/')}/run_counter.json"
    try:
        resp = _get_s3().get_object(Bucket=GDMP_STATE_BUCKET, Key=key)
        payload = json.loads(resp["Body"].read().decode("utf-8"))
        return int(payload.get("run_count") or 0)
    except Exception:
        return 0


def _save_run_counter(run_count: int) -> None:
    if not GDMP_STATE_BUCKET:
        return
    key = f"{GDMP_STATE_PREFIX.strip().strip('/')}/run_counter.json"
    _get_s3().put_object(
        Bucket=GDMP_STATE_BUCKET,
        Key=key,
        Body=json.dumps({"run_count": run_count}).encode("utf-8"),
        ContentType="application/json",
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Optional[Dict[str, Any]], context: Any) -> Dict[str, Any]:
    event = event or {}

    if is_hard_disabled(os.environ) or _cee_is_hard_disabled(os.environ):
        logger.info("[SKIP] CEE_GDMP_HARD_DISABLED (or CEE_HARD_DISABLED) is set; GDMP Stage-1 skipped")
        return {
            "statusCode": 200,
            "body": json.dumps({"success": True, "skipped": True, "reason": "hard_disabled"}),
        }

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    dry_run = is_dry_run(event)
    run_count = _load_run_counter()
    logger.info(
        "[START] GDMP Stage-1 remediation: project=%s dry_run=%s run_count=%s",
        PROJECT_ID, dry_run, run_count,
    )

    try:
        documents = _fetch_documents()
        findings = detect_compliance_semantic_entropy(
            documents, score_threshold=COMPLIANCE_SCORE_THRESHOLD
        )
        # Join findings back to their full compliance_warnings list (the
        # detector output only carries score/maturity/threshold, not the
        # warning strings themselves -- fetch from the source document row).
        by_id = {
            (d.get("record_id") or d.get("document_id") or d.get("item_id") or ""): d
            for d in documents
        }

        plans: List[Dict[str, Any]] = []
        for finding in findings[:_MAX_DOCS_PER_RUN]:
            record_id = finding.get("record_id") or ""
            doc_row = by_id.get(record_id, {})
            enriched_finding = dict(finding)
            enriched_finding["compliance_warnings"] = doc_row.get("compliance_warnings") or []
            plans.append(plan_remediation(enriched_finding))

        allow_mutate = mutation_allowed(run_count=run_count, dry_run=dry_run)

        applied: List[Dict[str, Any]] = []
        skipped_idempotent: List[str] = []

        if allow_mutate:
            for plan in plans:
                if plan["action"] not in ("remediate", "partial_remediate"):
                    continue
                document_id = plan["record_id"]
                if not document_id:
                    continue

                doc = _fetch_document_with_content(document_id)
                if not doc:
                    continue

                # AC-4 idempotency guard: never re-patch an already-compliant
                # document, even if it was queued from a stale scan.
                if is_already_compliant(doc):
                    skipped_idempotent.append(document_id)
                    continue

                content = doc.get("content")
                if not content:
                    continue

                before_score = doc.get("compliance_score")
                remediated_content = remediate_content(content, plan["deterministic_findings"])
                if remediated_content == content:
                    # No actual text change produced (e.g. fixer found nothing
                    # left to do) -- idempotent no-op, do not PATCH.
                    skipped_idempotent.append(document_id)
                    continue

                patch_resp = _patch_document(document_id, {"content": remediated_content})
                if not patch_resp or patch_resp.get("success") is False:
                    logger.error("[ERROR] content PATCH failed for %s", document_id)
                    continue

                after_score = (patch_resp.get("document") or patch_resp).get("compliance_score")
                after_warnings = (patch_resp.get("document") or patch_resp).get(
                    "compliance_warnings", []
                )

                maturity_patch_resp = None
                if after_score is not None and after_score >= COMPLIANCE_SCORE_THRESHOLD and not after_warnings:
                    maturity_patch_resp = _patch_document(
                        document_id, {"document_maturity_state": COMPLIANT_MATURITY_STATE}
                    )

                applied.append({
                    "record_id": document_id,
                    "before_compliance_score": before_score,
                    "after_compliance_score": after_score,
                    "remaining_warnings": after_warnings,
                    "advanced_to_compliant": bool(
                        maturity_patch_resp and maturity_patch_resp.get("success", True)
                    ),
                    "deterministic_classes_applied": sorted(
                        {f["class"] for f in plan["deterministic_findings"]}
                    ),
                })
                logger.info(
                    "[REMEDIATED] %s before_score=%s after_score=%s advanced_to_compliant=%s",
                    document_id, before_score, after_score,
                    bool(maturity_patch_resp and maturity_patch_resp.get("success", True)),
                )

        report_body = build_candidate_report_body(
            PROJECT_ID, plans, run_count=run_count, dry_run=dry_run, mutation_enabled=allow_mutate,
        )

        if not dry_run:
            _save_run_counter(run_count + 1)

        result = {
            "success": True,
            "project_id": PROJECT_ID,
            "scanned_at": now_iso,
            "dry_run": dry_run,
            "run_count": run_count,
            "mutation_allowed": allow_mutate,
            "candidate_count": len(plans),
            "remediated_count": len(applied),
            "skipped_idempotent_count": len(skipped_idempotent),
            "applied": applied,
            "report_preview": report_body[:2000],
        }
        logger.info(
            "[END] GDMP Stage-1 run complete: candidates=%d remediated=%d idempotent_skips=%d",
            len(plans), len(applied), len(skipped_idempotent),
        )
        return {"statusCode": 200, "body": json.dumps(result)}
    except Exception as exc:  # noqa: BLE001 -- top-level handler must never raise
        logger.error("[ERROR] GDMP Stage-1 remediation failed: %s", exc, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"success": False, "error": str(exc)})}
