"""Async, fail-open Bedrock enrichment for anomaly issues -- ENC-TSK-R83-0A (ENC-FTR-150 AC-6).

Tenet (BRD DOC-8E2CFF602B33 s1, ruling D-7): deterministic on the critical path, probabilistic off it.
Intake (adapter -> idempotent create -> push) never calls this module inline. After the issue exists, the
handler fires ONE async self-invoke (InvocationType=Event, no new resource); this module then:

  1. checks the feature flag (ANOMALY_ENRICHMENT_ENABLED, code default OFF; CFN sets it on gamma only);
  2. skips if the issue already carries the marker for this {key, impact-version} (idempotent);
  3. builds read-only context: the normalized payload, the truthful cost digest (settled / settled_day /
     settled_day_spend, read from the S3 digest object), and open issue titles in the target project;
  4. invokes a small Bedrock model and parses a strict JSON reply;
  5. writes ONLY the advisory text fields below, each stamped with model id + UTC timestamp.

Routing, priority and severity stay deterministic (devops default). The model may only PROPOSE a re-route /
priority; the proposal is recorded as text inside `technical_notes`, never applied.

FAIL-OPEN: every error (flag read, S3, Bedrock, parse, tracker) is logged, appended best-effort to the issue
worklog, and swallowed. enrich() never raises.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger()

# The ONLY issue fields enrichment may write (ENC-FTR-150 AC-6; everything else is deterministic).
ADVISORY_FIELDS = ("hypothesis", "technical_notes", "location_hint")
MARKER_PREFIX = "[enrichment:"

DEFAULT_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", "us-west-2")
DIGEST_BUCKET = os.environ.get("COST_DIGEST_BUCKET", "jreese-net")
DIGEST_KEY = os.environ.get("COST_DIGEST_KEY", "governance/cost-digest/latest.json")
MAX_OPEN_TITLES = 10
MAX_FIELD_CHARS = 1500
VALID_PRIORITIES = ("P0", "P1", "P2", "P3")

_bedrock = None
_s3 = None


def enabled() -> bool:
    return os.environ.get("ANOMALY_ENRICHMENT_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


def model_id() -> str:
    return os.environ.get("ANOMALY_ENRICHMENT_MODEL_ID", DEFAULT_MODEL_ID)


def get_bedrock_runtime() -> Any:
    global _bedrock
    if _bedrock is None:
        import boto3
        from botocore.config import Config
        _bedrock = boto3.client(
            "bedrock-runtime", region_name=BEDROCK_REGION,
            config=Config(retries={"max_attempts": 2, "mode": "standard"}, read_timeout=25, connect_timeout=5),
        )
    return _bedrock


def get_s3() -> Any:
    global _s3
    if _s3 is None:
        import boto3
        _s3 = boto3.client("s3")
    return _s3


def version_marker(key: str, norm: Dict[str, Any]) -> str:
    """Idempotency token per anomaly version: same {key, impact} => same marker => no second Bedrock call."""
    impact = json.dumps(norm.get("impact") or {}, sort_keys=True, default=str)
    return MARKER_PREFIX + hashlib.sha256(f"{key}|{impact}".encode()).hexdigest()[:10] + "]"


def read_cost_digest() -> Dict[str, Any]:
    """Read-only. Returns only the truthful settled fields; {} on any failure (fail-open)."""
    try:
        raw = get_s3().get_object(Bucket=DIGEST_BUCKET, Key=DIGEST_KEY)["Body"].read()
        d = json.loads(raw)
        return {k: d.get(k) for k in ("date", "settled", "settled_day", "settled_day_spend", "median_7d", "regression")}
    except Exception as exc:  # noqa: BLE001
        logger.warning("enrichment: cost digest unavailable: %s", exc)
        return {}


def _open_titles(client: Any, project: str) -> List[str]:
    try:
        page = client.list_issues(project, "open", "")
        return [str(r.get("title") or "")[:140] for r in (page.get("records") or [])[:MAX_OPEN_TITLES]]
    except Exception as exc:  # noqa: BLE001
        logger.warning("enrichment: open-issue context unavailable: %s", exc)
        return []


def build_prompt(norm: Dict[str, Any], digest: Dict[str, Any], open_titles: List[str]) -> str:
    context = {
        "anomaly": {k: norm.get(k) for k in ("source", "anomaly_id", "title", "impact")},
        "evidence": (norm.get("evidence") or [])[:1],
        "cost_digest": digest,
        "open_issues_in_project": open_titles,
    }
    return (
        "You assist an engineer triaging a cloud cost anomaly. Using ONLY the JSON context, reply with a single "
        "JSON object, no prose, with string keys: hypothesis (likely root cause, <=600 chars), technical_notes "
        "(what to check, <=600 chars), location_hint (services/resources/code areas to inspect, <=300 chars), "
        "suggested_priority (one of P0,P1,P2,P3 or empty), suggested_project (project id if this clearly belongs "
        "elsewhere, else empty). If cost_digest.settled is false the latest day is unsettled: say so, do not "
        "infer a regression from it. Do not invent resource names.\n\nCONTEXT:\n" + json.dumps(context, default=str)[:12000]
    )


def invoke_model(prompt: str) -> Dict[str, Any]:
    body = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 700, "temperature": 0,
            "messages": [{"role": "user", "content": prompt}]}
    resp = get_bedrock_runtime().invoke_model(
        modelId=model_id(), contentType="application/json", accept="application/json", body=json.dumps(body))
    payload = json.loads(resp["body"].read())
    text = "".join(b.get("text", "") for b in payload.get("content") or [] if isinstance(b, dict))
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("model reply had no JSON object")
    out = json.loads(text[start:end + 1])
    if not isinstance(out, dict):
        raise ValueError("model reply JSON was not an object")
    return out


def _clip(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    return str(value or "").strip()[:limit]


def compose_fields(model_out: Dict[str, Any], marker: str, now: str, mid: str) -> Dict[str, str]:
    """Map the model reply onto ADVISORY_FIELDS only; proposals live as text in technical_notes."""
    stamp = f"[ENRICHMENT ADVISORY model={mid} at={now}]"
    notes = [_clip(model_out.get("technical_notes"))]
    prio = _clip(model_out.get("suggested_priority"), 4).upper()
    proj = _clip(model_out.get("suggested_project"), 40)
    if prio in VALID_PRIORITIES:
        notes.append(f"Proposed priority (advisory, not applied): {prio}")
    if proj:
        notes.append(f"Proposed project re-route (advisory, not applied): {proj}")
    notes.append(f"{stamp} {marker}")
    fields = {
        "hypothesis": f"{_clip(model_out.get('hypothesis'))}\n{stamp}".strip(),
        "technical_notes": "\n".join(n for n in notes if n),
        "location_hint": _clip(model_out.get("location_hint"), 400),
    }
    return {k: v for k, v in fields.items() if k in ADVISORY_FIELDS and v}


def _already_enriched(client: Any, project: str, issue_id: str, marker: str) -> bool:
    try:
        rec = client.get_issue(project, issue_id)
        rec = rec.get("record", rec) if isinstance(rec, dict) else {}
        return marker in str(rec.get("technical_notes") or "")
    except Exception as exc:  # noqa: BLE001
        logger.warning("enrichment: idempotency lookup failed (proceeding): %s", exc)
        return False


def enrich(request: Dict[str, Any], client: Any) -> Dict[str, Any]:
    """request = {norm, key, project, issue_id}. NEVER raises."""
    if not enabled():
        return {"status": "disabled"}
    project, issue_id = request.get("project"), request.get("issue_id")
    try:
        norm, key = request["norm"], request["key"]
        marker = version_marker(key, norm)
        if _already_enriched(client, project, issue_id, marker):
            return {"status": "skipped_idempotent", "issue_id": issue_id}
        prompt = build_prompt(norm, read_cost_digest(), _open_titles(client, project))
        out = invoke_model(prompt)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fields = compose_fields(out, marker, now, model_id())
        for name, value in fields.items():
            client.set_field(project, issue_id, name, value)
        logger.info(json.dumps({"event": "anomaly_enrichment_written", "issue_id": issue_id, "fields": sorted(fields)}))
        return {"status": "enriched", "issue_id": issue_id, "fields": sorted(fields)}
    except Exception as exc:  # noqa: BLE001 -- fail-open by contract
        logger.error("enrichment failed for %s: %s", issue_id, exc)
        try:
            client.log(project, issue_id, f"[ERROR] Bedrock enrichment failed (intake and push unaffected): {str(exc)[:300]}")
        except Exception:  # noqa: BLE001
            pass
        return {"status": "failed_open", "issue_id": issue_id}


def dispatch_async(function_name: str, request: Dict[str, Any]) -> bool:
    """Fire-and-forget self-invoke. Returns False (and logs) on any failure; never raises."""
    if not enabled() or not function_name or not request.get("issue_id"):
        return False
    try:
        import boto3
        boto3.client("lambda").invoke(
            FunctionName=function_name, InvocationType="Event",
            Payload=json.dumps({"enrichment_request": request}, default=str).encode())
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("enrichment dispatch failed (intake unaffected): %s", exc)
        return False
