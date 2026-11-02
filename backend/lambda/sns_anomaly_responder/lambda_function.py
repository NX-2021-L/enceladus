"""sns_anomaly_responder -- ENC-TSK-R81-0B (ENC-FTR-150 AC-1 / AC-3 / AC-8 seam).

Anomaly -> governed issue primitive. SNS (AWS Cost Anomaly Detection first) delivers a
source payload; a SOURCE ADAPTER normalizes it deterministically (no LLM, no Bedrock on this
critical path); the source-agnostic primitive below then performs an idempotent create:

    adapter(source) -> normalized {source, anomaly_id, project, title, evidence[]}
    key = "{source}:{anomaly_id}"            <- the dedupe KEY (stable id from the source)
    existing issue carries the key? -> replay: refresh evidence + append worklog (NO create)
    else                            -> tracker create with idempotency_key=key

Replays (AWS re-sends one anomaly up to ~3x/day as impact changes) therefore yield exactly one
issue. The key travels three ways: the create body's idempotency_key (server-side ID Service
contract, ENC-TSK-L06), a `[aws-cad:<id>]` title token, and evidence[].source_key, so the
lookup survives a flag-off ID Service and a restart.

Out of scope here (later waves): per-invocation agent.register/claim SCI minting (W2.1,
ENC-TSK-R82-0A), notify v2 push (W2.3), Bedrock enrichment (W3.1). The agent type
(surface `sns-anomaly-responder`) is registered through agent.type.register (W0.6 path).

Auth: internal-key tracker API, same service-to-service convention as env_drift_auditor.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import aws_cad_adapter
import source_adapters

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TRACKER_API_BASE = os.environ.get(
    "TRACKER_API_BASE", "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker"
).rstrip("/")
PROVIDER = "sns-anomaly-responder"
MAX_LOOKUP_PAGES = int(os.environ.get("ANOMALY_LOOKUP_MAX_PAGES", "10") or 10)
MAX_EVIDENCE_ENTRIES = 20
LOOKUP_STATUSES = ("open", "in-progress", "closed")

# AC-8 seam: source name -> adapter module (SOURCE + parse(message) -> [normalized]).
ADAPTERS = source_adapters.REGISTRY  # AdapterRegistry (dict subclass); see source_adapters.py contract


class TrackerError(RuntimeError):
    pass


def idempotency_key(norm: Dict[str, Any]) -> str:
    return f"{norm['source']}:{norm['anomaly_id']}"


def _internal_key() -> str:
    return os.environ.get("COORDINATION_INTERNAL_API_KEY", "")


def _http(method: str, url: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    headers = {"X-Coordination-Internal-Key": _internal_key()}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise TrackerError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except Exception as exc:  # noqa: BLE001
        raise TrackerError(f"{method} {url} failed: {exc}") from exc


class TrackerClient:
    """Thin internal-key tracker API client. Tests substitute a fake with the same 4 methods."""

    def list_issues(self, project: str, status: str, cursor: str = "") -> Dict[str, Any]:
        url = f"{TRACKER_API_BASE}/{project}?type=issue&status={status}&page_size=200"
        if cursor:
            url += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        return _http("GET", url)

    def create_issue(self, project: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return _http("POST", f"{TRACKER_API_BASE}/{project}/issue", body)

    def set_field(self, project: str, issue_id: str, field: str, value: Any) -> Dict[str, Any]:
        return _http(
            "PATCH", f"{TRACKER_API_BASE}/{project}/issue/{issue_id}",
            {"field": field, "value": value, "write_source": {"provider": PROVIDER}},
        )

    def log(self, project: str, issue_id: str, description: str) -> Dict[str, Any]:
        return _http(
            "POST", f"{TRACKER_API_BASE}/{project}/issue/{issue_id}/log",
            {"description": description, "write_source": {"provider": PROVIDER}},
        )


def _record_id(rec: Dict[str, Any]) -> str:
    return str(rec.get("item_id") or rec.get("issue_id") or rec.get("id") or "")


def _carries_key(rec: Dict[str, Any], key: str) -> bool:
    token = f"[{key}]"
    if token in str(rec.get("title") or ""):
        return True
    for ev in rec.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("source_key") == key:
            return True
    return False


def find_existing(client: Any, project: str, key: str) -> Optional[Dict[str, Any]]:
    """Locate the canonical issue carrying `key` across open/in-progress/closed (a re-send
    after the issue was closed must not mint a duplicate). Raises TrackerError on transport
    failure: the caller must NOT create blindly when the dedupe lookup failed."""
    for status in LOOKUP_STATUSES:
        cursor = ""
        for _ in range(MAX_LOOKUP_PAGES):
            page = client.list_issues(project, status, cursor)
            for rec in page.get("records") or []:
                if _carries_key(rec, key):
                    return rec
            cursor = page.get("next_cursor") or ""
            if not cursor:
                break
    return None


def _impact_line(norm: Dict[str, Any]) -> str:
    i = norm.get("impact") or {}
    return (
        f"total_impact_usd={i.get('total_impact_usd')} actual={i.get('total_actual_spend_usd')} "
        f"expected={i.get('total_expected_spend_usd')} pct={i.get('total_impact_pct')}"
    )


def create_body(norm: Dict[str, Any]) -> Dict[str, Any]:
    key = idempotency_key(norm)
    return {
        "title": norm["title"],
        "priority": norm.get("priority", "P2"),
        "severity": norm.get("severity", "medium"),
        "category": norm.get("category", "risk"),
        "status": "open",
        "evidence": norm["evidence"],
        "hypothesis": (
            f"{norm['source']} reported anomaly {norm['anomaly_id']} ({_impact_line(norm)}). "
            "Deterministic intake; root-cause hypothesis is added asynchronously by enrichment."
        ),
        "idempotency_key": key,
        "write_source": {"provider": PROVIDER},
    }


def process_anomaly(norm: Dict[str, Any], client: Any) -> Dict[str, Any]:
    """Source-agnostic create-or-replay. Exactly one issue per {source}:{anomaly_id}."""
    key = idempotency_key(norm)
    project = norm["project"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    existing = find_existing(client, project, key)
    if existing is None:
        try:
            created = client.create_issue(project, create_body(norm))
            issue_id = str(created.get("record_id") or created.get("item_id") or created.get("id") or "")
            logger.info(json.dumps({"event": "anomaly_issue_created", "key": key, "issue_id": issue_id}))
            return {"action": "created", "key": key, "issue_id": issue_id, "project": project}
        except TrackerError:
            # A concurrent delivery may have won the race (ID-service idempotency replay returns
            # the same id and the second write conflicts). Re-check before surfacing the error.
            existing = find_existing(client, project, key)
            if existing is None:
                raise
    issue_id = _record_id(existing)
    prior = [e for e in (existing.get("evidence") or []) if isinstance(e, dict)]
    new_ev = norm["evidence"][0]
    if not prior or (prior[-1].get("impact") or {}) != new_ev.get("impact"):
        merged = (prior + [new_ev])[-MAX_EVIDENCE_ENTRIES:]
        client.set_field(project, issue_id, "evidence", merged)
    client.log(project, issue_id, f"[INFO] {key} re-delivered at {now}: {_impact_line(norm)}")
    logger.info(json.dumps({"event": "anomaly_issue_replayed", "key": key, "issue_id": issue_id}))
    return {"action": "replayed", "key": key, "issue_id": issue_id, "project": project}


def _select_adapter(event_source: str) -> Any:
    return ADAPTERS.resolve(os.environ.get("ANOMALY_SOURCE"), aws_cad_adapter.SOURCE)


def lambda_handler(event: Any, context: Any, client: Optional[Any] = None) -> Dict[str, Any]:
    client = client or TrackerClient()
    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    suppressed = 0
    for record in (event or {}).get("Records") or []:
        sns = record.get("Sns") or {}
        adapter = _select_adapter(str(sns.get("TopicArn") or ""))
        try:
            anomalies = source_adapters.parse_message(adapter, sns.get("Message") or "")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"normalize: {exc}")
            continue
        if not anomalies:
            suppressed += 1
        for norm in anomalies:
            try:
                results.append(process_anomaly(norm, client))
            except Exception as exc:  # noqa: BLE001
                logger.error("anomaly %s failed: %s", norm.get("anomaly_id"), exc)
                errors.append(f"{norm.get('anomaly_id')}: {exc}")
    summary = {"event": "anomaly_responder_complete", "processed": len(results),
               "suppressed_or_unparsed": suppressed, "errors": len(errors)}
    logger.info(json.dumps(summary))
    if errors:
        # Fail the invocation so SNS retries; replay safety comes from the dedupe key.
        raise RuntimeError("; ".join(errors)[:1000])
    return {"summary": summary, "results": results}


handler = lambda_handler
