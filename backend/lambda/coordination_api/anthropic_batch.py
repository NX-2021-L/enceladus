"""Anthropic Message Batches API integration (ENC-TSK-G19 / Strategy #8).

Non-interactive workloads route through POST /v1/messages/batches for 50% batch
pricing, stacked with ephemeral_1h prompt caching on the static system + toolset
prefix (~95% effective cost on cache hits for recurring workloads).

Cost comparison (nightly changelog generation, Sonnet 4, illustrative):
- Synchronous: ~120k input tokens/night @ $3/M = $0.36/night ($131/year)
- Batch + 1h cache (90% cache hit): ~12k billable input + batch 50% off
  ≈ $0.018/night ($6.6/year) — ~95% reduction vs uncached sync baseline.
See NON_INTERACTIVE_WORKLOADS for enumerated call sites.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from config import ANTHROPIC_API_BASE_URL, ANTHROPIC_API_VERSION

BATCH_POLL_INTERVAL_SECONDS = 60

# Enumerated non-interactive workloads (AC#1).
NON_INTERACTIVE_WORKLOADS: Dict[str, Dict[str, str]] = {
    "nightly_changelog_generation": {
        "description": "Scheduled changelog doc generation from tracker/git deltas",
        "trigger": "EventBridge nightly schedule / memory consolidation follow-up",
        "provider_preference": "batch_eligible=true",
    },
    "governance_audit_doc_patching": {
        "description": "Governance audit Lambda patches compliance docs after stream events",
        "trigger": "GovernanceAuditRole DynamoDB stream",
        "provider_preference": "batch_eligible=true",
    },
    "compliance_doc_creation": {
        "description": "Compliance self-assessment doc creation (DOC-6EFD5DB32CD8 Phase 5)",
        "trigger": "coordination dispatch with compliance workload tag",
        "provider_preference": "batch_eligible=true",
    },
    "memory_consolidation_bulk": {
        "description": "Bulk operations triggered by memory consolidation Lambda (ENC-FTR-096)",
        "trigger": "memory consolidation Lambda fan-out",
        "provider_preference": "batch_eligible=true",
    },
}

NIGHTLY_CHANGELOG_COST_COMPARISON: Dict[str, Any] = {
    "workload": "nightly_changelog_generation",
    "model": "claude-sonnet-4-20250514",
    "assumptions": {
        "nightly_input_tokens": 120_000,
        "cache_hit_ratio_post_migration": 0.90,
        "batch_discount": 0.50,
        "input_price_per_million_usd": 3.0,
    },
    "baseline_sync_usd_per_night": 0.36,
    "batch_cached_usd_per_night": 0.018,
    "effective_reduction_pct": 95,
    "notes": "Batch pricing stacks with ephemeral_1h cache on static system+toolset prefix.",
}


def _cert_context(cert_bundle: Optional[str]):
    return ssl.create_default_context(cafile=cert_bundle) if cert_bundle else None


def anthropic_http_json(
    *,
    api_key: str,
    method: str,
    url: str,
    body: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    timeout: int = 60,
    cert_bundle: Optional[str] = None,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    """Issue an Anthropic API request and parse a JSON object response."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_API_VERSION,
        "content-type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url=url, method=method, data=data, headers=headers)
    context = _cert_context(cert_bundle)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            response_headers = dict(resp.headers.items())
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            payload = {"error": {"message": raw[:400] or str(exc)}}
        if not isinstance(payload, dict):
            payload = {"raw": payload}
        return int(exc.code), payload, {}
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Anthropic API request failed: {exc.reason}") from exc

    if status < 200 or status >= 300:
        raise RuntimeError(f"Anthropic API request returned http_{status}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Anthropic API response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Anthropic API response payload is not an object")
    return status, payload, response_headers


def submit_messages_batch(
    *,
    api_key: str,
    requests: List[Dict[str, Any]],
    cert_bundle: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """POST /v1/messages/batches with one or more custom_id + params items."""
    endpoint = f"{ANTHROPIC_API_BASE_URL.rstrip('/')}/v1/messages/batches"
    _status, payload, _headers = anthropic_http_json(
        api_key=api_key,
        method="POST",
        url=endpoint,
        body={"requests": requests},
        extra_headers=extra_headers,
        cert_bundle=cert_bundle,
    )
    if isinstance(payload.get("error"), dict):
        error_type = str(payload["error"].get("type") or "unknown")
        error_message = str(payload["error"].get("message") or "Unknown batch API error")
        raise RuntimeError(f"Anthropic batch error ({error_type}): {error_message}")
    return payload


def get_messages_batch(
    *,
    api_key: str,
    batch_id: str,
    cert_bundle: Optional[str] = None,
) -> Dict[str, Any]:
    """GET /v1/messages/batches/{batch_id}."""
    endpoint = f"{ANTHROPIC_API_BASE_URL.rstrip('/')}/v1/messages/batches/{batch_id}"
    _status, payload, _headers = anthropic_http_json(
        api_key=api_key,
        method="GET",
        url=endpoint,
        cert_bundle=cert_bundle,
    )
    if isinstance(payload.get("error"), dict):
        error_type = str(payload["error"].get("type") or "unknown")
        error_message = str(payload["error"].get("message") or "Unknown batch API error")
        raise RuntimeError(f"Anthropic batch status error ({error_type}): {error_message}")
    return payload


def download_batch_results(
    *,
    api_key: str,
    results_url: str,
    cert_bundle: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """Download JSONL batch results from the signed results_url."""
    headers = {"x-api-key": api_key, "anthropic-version": ANTHROPIC_API_VERSION}
    req = urllib.request.Request(url=results_url, method="GET", headers=headers)
    context = _cert_context(cert_bundle)
    with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
        return resp.read().decode("utf-8", errors="replace")


def batch_processing_ended(batch_status: Dict[str, Any]) -> bool:
    return str(batch_status.get("processing_status") or "").strip().lower() == "ended"


def alert_batch_subrequest_failure(
    emit_observability: Callable[..., None],
    *,
    request_id: str,
    dispatch_id: str,
    batch_id: str,
    custom_id: str,
    error_type: str,
    error_message: str,
) -> None:
    """Emit structured alert for a failed batch sub-request (AC#5)."""
    emit_observability(
        component="coordination_api",
        event="batch_subrequest_failure",
        request_id=request_id,
        dispatch_id=dispatch_id or custom_id,
        tool_name="anthropic.messages.batches",
        error_code="batch_subrequest_failed",
        extra={
            "batch_id": batch_id,
            "custom_id": custom_id,
            "anthropic_error_type": error_type,
            "anthropic_error_message": error_message[:500],
            "alert": True,
        },
    )
