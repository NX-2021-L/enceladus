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

Identity + notify (ENC-TSK-R82-0A, ENC-FTR-150 AC-2/AC-4): every invocation first fetches a
governance_hash and performs agent.register + agent.claim through the W1.1 fail-closed path
(agent_type_id ENC-AGT-00R, surface `sns-anomaly-responder`); register bumps the type's
usage_count (W1.8). Each tracker mutation then carries write_source.provider=<ENC-SES>, the
claimed `sci` and that governance_hash. If the identity cannot be established (422 non-ACTIVE
type, 400 enum, any transport error) the invocation FAILS before any mutation. The FIRST create
(never a replay) sends a notify v2 push of type `anomaly` through the coordination API; the push
is independent of any enrichment and a push failure never fails the intake.

Out of scope here (later waves): Bedrock enrichment (W3.1).

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
# ENC-TSK-R82-0A: identity (fail-closed register/claim) + notify.
AGENT_TYPE_ID = os.environ.get("ANOMALY_AGENT_TYPE_ID", "ENC-AGT-00R")
AGENT_RUNTIME = os.environ.get("ANOMALY_AGENT_RUNTIME", "aws_lambda")
PARENT_SESSION_ID = os.environ.get("ANOMALY_PARENT_SESSION_ID", "root")
# https://<apigw>/api/v1  (tracker + coordination share one API Gateway per plane)
API_ROOT = os.environ.get("COORDINATION_API_BASE", "").rstrip("/") or (
    TRACKER_API_BASE[: -len("/tracker")] if TRACKER_API_BASE.endswith("/tracker") else TRACKER_API_BASE
)
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


class Identity:
    """Per-invocation agent identity: minted session, its SCI and the invocation's governance hash."""

    def __init__(self, session_id: str, sci: str, governance_hash: str, agent_type_id: str = "") -> None:
        self.session_id = session_id
        self.sci = sci
        self.governance_hash = governance_hash
        self.agent_type_id = agent_type_id


def acquire_identity(http: Callable[..., Dict[str, Any]] = _http) -> Identity:
    """governance hash -> agent.register -> agent.claim, all in THIS invocation (FTR-150 AC-2).

    Fail-closed: any rejection (422 agent-type-not-active, 400 INVALID_ENUM, transport error)
    raises TrackerError so the caller aborts before a single tracker mutation."""
    gov = http("GET", f"{API_ROOT}/governance/hash")
    governance_hash = str(gov.get("governance_hash") or "").strip()
    if not governance_hash:
        raise TrackerError("governance hash unavailable; refusing to mutate")
    reg = http("POST", f"{API_ROOT}/coordination/agents/sessions", {
        "agent_type_id": AGENT_TYPE_ID, "runtime": AGENT_RUNTIME, "parent_session_id": PARENT_SESSION_ID,
    })
    session_id = str((reg.get("session") or {}).get("session_id") or "").strip()
    if not session_id:
        raise TrackerError("agent.register returned no session_id")
    claim = http("POST", f"{API_ROOT}/coordination/agents/sessions/claim", {
        "session_id": session_id, "expected_agent_type_id": AGENT_TYPE_ID,
    })
    sci = str(claim.get("sci") or "").strip()
    if not sci:
        raise TrackerError(f"agent.claim returned no SCI for {session_id}")
    logger.info(json.dumps({"event": "anomaly_identity_acquired", "session_id": session_id,
                            "agent_type_id": AGENT_TYPE_ID}))
    return Identity(session_id, sci, governance_hash, AGENT_TYPE_ID)


def retire_identity(identity: Identity, http: Callable[..., Dict[str, Any]] = _http) -> None:
    """Best-effort graceful close of the per-invocation session (never raises)."""
    try:
        http("POST", f"{API_ROOT}/coordination/agents/sessions/{identity.session_id}/retire", {})
    except Exception as exc:  # noqa: BLE001
        logger.warning("session retire failed for %s: %s", identity.session_id, exc)


class TrackerClient:
    """Thin internal-key tracker API client. Tests substitute a fake with the same methods.

    Every mutation is stamped with the invocation identity (provider=ENC-SES, sci,
    governance_hash); without an identity a mutation is refused (fail closed)."""

    identity: Optional[Identity] = None

    def set_identity(self, identity: Identity) -> None:
        self.identity = identity

    def _stamp(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if self.identity is None:
            raise TrackerError("no agent identity for this invocation; mutation refused")
        out = dict(body)
        out["write_source"] = {"provider": self.identity.session_id}
        out["sci"] = self.identity.sci
        out["governance_hash"] = self.identity.governance_hash
        return out

    def notify_anomaly(self, project: str, issue_id: str, norm: Dict[str, Any]) -> Dict[str, Any]:
        return _http("POST", f"{API_ROOT}/coordination/notifications/anomaly", anomaly_push_body(project, issue_id, norm))

    def list_issues(self, project: str, status: str, cursor: str = "") -> Dict[str, Any]:
        url = f"{TRACKER_API_BASE}/{project}?type=issue&status={status}&page_size=200"
        if cursor:
            url += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        return _http("GET", url)

    def create_issue(self, project: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return _http("POST", f"{TRACKER_API_BASE}/{project}/issue", self._stamp(body))

    def set_field(self, project: str, issue_id: str, field: str, value: Any) -> Dict[str, Any]:
        return _http(
            "PATCH", f"{TRACKER_API_BASE}/{project}/issue/{issue_id}",
            self._stamp({"field": field, "value": value}),
        )

    def log(self, project: str, issue_id: str, description: str) -> Dict[str, Any]:
        return _http(
            "POST", f"{TRACKER_API_BASE}/{project}/issue/{issue_id}/log",
            self._stamp({"description": description}),
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


def anomaly_push_body(project: str, issue_id: str, norm: Dict[str, Any]) -> Dict[str, Any]:
    """Payload for the coordination notify route: issue_id, service(s), total impact, severity."""
    services: List[str] = []
    for ev in norm.get("evidence") or []:
        for row in (ev.get("breakdown") or []) if isinstance(ev, dict) else []:
            svc = str(row.get("service") or "").strip()
            if svc and svc not in services:
                services.append(svc)
    impact = (norm.get("impact") or {}).get("total_impact_usd")
    return {
        "issue_id": issue_id, "project_id": project, "service": ", ".join(services[:3]) or "unknown",
        "total_impact_usd": impact if isinstance(impact, (int, float)) else None,
        "severity": norm.get("severity", "medium"),
    }


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


def _notify_created(client: Any, project: str, issue_id: str, norm: Dict[str, Any]) -> bool:
    """FTR-150 AC-4: push on FIRST create only. Independent of enrichment; never fails intake."""
    sender = getattr(client, "notify_anomaly", None)
    if sender is None or not issue_id:
        return False
    try:
        sender(project, issue_id, norm)
        return True
    except Exception as exc:  # noqa: BLE001 -- the issue exists; a lost push must not cause a retry storm
        logger.warning("anomaly push failed for %s: %s", issue_id, exc)
        return False


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
            notified = _notify_created(client, project, issue_id, norm)
            return {"action": "created", "key": key, "issue_id": issue_id, "project": project, "notified": notified}
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


def lambda_handler(event: Any, context: Any, client: Optional[Any] = None,
                   identity: Optional[Identity] = None) -> Dict[str, Any]:
    owns_identity = False
    if client is None:
        client = TrackerClient()
        if identity is None and (event or {}).get("Records"):
            identity = acquire_identity()  # raises (fail closed) BEFORE any mutation
            owns_identity = True
    if identity is not None and hasattr(client, "set_identity"):
        client.set_identity(identity)
    try:
        return _run(event, client)
    finally:
        if owns_identity and identity is not None:
            retire_identity(identity)


def _run(event: Any, client: Any) -> Dict[str, Any]:
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
