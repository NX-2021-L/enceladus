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

Bedrock enrichment lives in enrichment.py (ENC-TSK-R83-0A, ENC-FTR-150 AC-6): async self-invoked leg after
intake, fail-open, advisory fields only (deterministic on the critical path, probabilistic off it).

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
import enrichment
import source_adapters

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TRACKER_API_BASE = os.environ.get(
    "TRACKER_API_BASE", "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker"
).rstrip("/")
PROVIDER = "sns-anomaly-responder"
# ENC-TSK-R82-0A: identity (fail-closed register/claim) + notify.
# Agent-type ids are per-environment (prod ENC-AGT-00R does not exist on gamma): resolved at
# cold start via env override else idempotent agent.type.register, cached per container.
TYPE_SURFACE = "sns-anomaly-responder"
TYPE_MODEL = "deterministic-no-llm"
TYPE_COST_TIER = "low"
_TYPE_ID_CACHE: Dict[str, str] = {}
AGENT_RUNTIME = os.environ.get("ANOMALY_AGENT_RUNTIME", "aws_lambda")
PARENT_SESSION_ID = os.environ.get("ANOMALY_PARENT_SESSION_ID", "root")
# https://<apigw>/api/v1  (tracker + coordination share one API Gateway per plane)
API_ROOT = os.environ.get("COORDINATION_API_BASE", "").rstrip("/") or (
    TRACKER_API_BASE[: -len("/tracker")] if TRACKER_API_BASE.endswith("/tracker") else TRACKER_API_BASE
)
MAX_LOOKUP_PAGES = int(os.environ.get("ANOMALY_LOOKUP_MAX_PAGES", "10") or 10)
MAX_EVIDENCE_ENTRIES = 20
LOOKUP_STATUSES = ("open", "in-progress", "closed")
# ENC-TSK-R82-0C (FTR-150 AC-5 / FTR-100 AC-4): update-push thresholds, read at CALL time from env
# (a Lambda configuration change, never a code change). Push on a re-delivery iff total impact
# reached >= RATIO x the last-pushed impact OR grew by >= ABS_USD dollars since the last push.
DEFAULT_UPDATE_PUSH_RATIO = 2.0
DEFAULT_UPDATE_PUSH_ABS_USD = 5.0

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


def resolve_agent_type_id(http: Callable[..., Dict[str, Any]] = _http) -> str:
    """ANOMALY_AGENT_TYPE_ID env wins; else find-or-mint via agent.type.register (once per container).

    Fail-closed: any error or missing id raises TrackerError before any mutation."""
    override = os.environ.get("ANOMALY_AGENT_TYPE_ID", "").strip()
    if override:
        return override
    cached = _TYPE_ID_CACHE.get("id")
    if cached:
        return cached
    resp = http("POST", f"{API_ROOT}/coordination/agents/types", {
        "surface": TYPE_SURFACE, "model": TYPE_MODEL, "cost_tier": TYPE_COST_TIER,
    })
    type_id = str((resp.get("agent_type") or {}).get("agent_type_id") or "").strip()
    if not type_id:
        raise TrackerError("agent.type.register returned no agent_type_id; refusing to mutate")
    _TYPE_ID_CACHE["id"] = type_id
    return type_id


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
    agent_type_id = resolve_agent_type_id(http)
    reg = http("POST", f"{API_ROOT}/coordination/agents/sessions", {
        "agent_type_id": agent_type_id, "runtime": AGENT_RUNTIME, "parent_session_id": PARENT_SESSION_ID,
    })
    session_id = str((reg.get("session") or {}).get("session_id") or "").strip()
    if not session_id:
        raise TrackerError("agent.register returned no session_id")
    claim = http("POST", f"{API_ROOT}/coordination/agents/sessions/claim", {
        "session_id": session_id, "expected_agent_type_id": agent_type_id,
    })
    sci = str(claim.get("sci") or "").strip()
    if not sci:
        raise TrackerError(f"agent.claim returned no SCI for {session_id}")
    logger.info(json.dumps({"event": "anomaly_identity_acquired", "session_id": session_id,
                            "agent_type_id": agent_type_id}))
    return Identity(session_id, sci, governance_hash, agent_type_id)


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

    def notify_anomaly_update(self, project: str, issue_id: str, norm: Dict[str, Any],
                              prior_usd: Optional[float]) -> Dict[str, Any]:
        """ENC-TSK-R82-0C: threshold-crossing re-delivery push via the same anomaly notify route
        (route ignores unknown keys; `update`/`prior_total_impact_usd` are advisory)."""
        impact = (norm.get("impact") or {}).get("total_impact_usd")
        services = sorted({str(r.get("service")) for ev in norm.get("evidence") or [] if isinstance(ev, dict)
                           for r in ev.get("breakdown") or [] if r.get("service")})
        base = TRACKER_API_BASE[: -len("/tracker")] if TRACKER_API_BASE.endswith("/tracker") else TRACKER_API_BASE
        return _http("POST", f"{base}/coordination/notifications/anomaly", {
            "issue_id": issue_id, "project_id": project, "service": ", ".join(services[:3]) or "unknown",
            "total_impact_usd": impact if isinstance(impact, (int, float)) else None,
            "severity": norm.get("severity", "medium"), "update": True, "prior_total_impact_usd": prior_usd,
        })

    def list_issues(self, project: str, status: str, cursor: str = "") -> Dict[str, Any]:
        url = f"{TRACKER_API_BASE}/{project}?type=issue&status={status}&page_size=200"
        if cursor:
            url += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        return _http("GET", url)

    def create_issue(self, project: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return _http("POST", f"{TRACKER_API_BASE}/{project}/issue", self._stamp(body))

    def get_issue(self, project: str, issue_id: str) -> Dict[str, Any]:
        return _http("GET", f"{TRACKER_API_BASE}/{project}/issue/{issue_id}")

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
    if "total_impact_usd" not in i:  # non-CAD source: generic, deterministic rendering
        return "impact=" + json.dumps(i, sort_keys=True, default=str)
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


def _env_nonneg_float(name: str, default: float) -> float:
    try:
        val = float(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return val if val >= 0 else default


def update_push_thresholds() -> Dict[str, float]:
    """Runtime-configurable (ENC-FTR-100 AC-4): ANOMALY_UPDATE_PUSH_RATIO, ANOMALY_UPDATE_PUSH_ABS_USD.
    Invalid / negative values fall back to the defaults (2x, $5)."""
    return {
        "ratio": _env_nonneg_float("ANOMALY_UPDATE_PUSH_RATIO", DEFAULT_UPDATE_PUSH_RATIO),
        "abs_usd": _env_nonneg_float("ANOMALY_UPDATE_PUSH_ABS_USD", DEFAULT_UPDATE_PUSH_ABS_USD),
    }


def _total_impact(ev: Any) -> Optional[float]:
    v = ((ev or {}).get("impact") or {}).get("total_impact_usd") if isinstance(ev, dict) else None
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def push_baseline(prior: List[Dict[str, Any]]) -> Optional[float]:
    """Impact at the LAST PUSH: the newest evidence entry flagged `pushed`, else the first entry
    (the create-time push). Comparing to the last push, not the last delivery, stops a slow creep
    of sub-threshold re-sends from ever escaping notification."""
    for ev in reversed(prior):
        if ev.get("pushed") and _total_impact(ev) is not None:
            return _total_impact(ev)
    return _total_impact(prior[0]) if prior else None


def should_push_update(prior_usd: Optional[float], new_usd: Optional[float],
                       th: Optional[Dict[str, float]] = None) -> bool:
    """FTR-150 AC-5: push only when impact crossed the threshold; unknown impact never pushes."""
    if new_usd is None:
        return False
    th = th or update_push_thresholds()
    if prior_usd is None:
        return new_usd >= th["abs_usd"]
    if new_usd - prior_usd >= th["abs_usd"]:
        return True
    return prior_usd > 0 and new_usd >= th["ratio"] * prior_usd


def _notify_updated(client: Any, project: str, issue_id: str, norm: Dict[str, Any],
                    prior_usd: Optional[float]) -> bool:
    """Threshold-crossing re-delivery push; same route as the create push. Never fails intake."""
    sender = getattr(client, "notify_anomaly_update", None)
    if sender is None or not issue_id:
        return False
    try:
        sender(project, issue_id, norm, prior_usd)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("anomaly update push failed for %s: %s", issue_id, exc)
        return False


def process_closed_signal(norm: Dict[str, Any], client: Any) -> Dict[str, Any]:
    """FTR-150 AC-5: a source anomaly-closed signal appends a worklog entry to the existing issue
    and NEVER changes its status (a human closes it). Never creates; no push."""
    key = idempotency_key(norm)
    project = norm["project"]
    existing = find_existing(client, project, key)
    if existing is None:
        logger.info(json.dumps({"event": "anomaly_closed_signal_unmatched", "key": key}))
        return {"action": "closed_signal_unmatched", "key": key, "project": project}
    issue_id = _record_id(existing)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    client.log(project, issue_id, (
        f"[INFO] {key} reported CLOSED by source at {now}: {_impact_line(norm)}. "
        "Issue left open for human review (anomaly-closed never auto-closes)."))
    logger.info(json.dumps({"event": "anomaly_closed_signal_logged", "key": key, "issue_id": issue_id}))
    return {"action": "closed_logged", "key": key, "issue_id": issue_id, "project": project}


def process_anomaly(norm: Dict[str, Any], client: Any) -> Dict[str, Any]:
    """Source-agnostic create-or-replay. Exactly one issue per {source}:{anomaly_id}."""
    key = idempotency_key(norm)
    project = norm["project"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if norm.get("lifecycle") == "closed":
        return process_closed_signal(norm, client)
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
    prior_usd = push_baseline(prior)
    push = should_push_update(prior_usd, _total_impact(new_ev))
    if push:
        new_ev = dict(new_ev, pushed=True)  # becomes the baseline for the next threshold check
    if not prior or (prior[-1].get("impact") or {}) != new_ev.get("impact"):
        merged = (prior + [new_ev])[-MAX_EVIDENCE_ENTRIES:]
        client.set_field(project, issue_id, "evidence", merged)
    client.log(project, issue_id, f"[INFO] {key} re-delivered at {now}: {_impact_line(norm)}"
               + (f" (push threshold crossed; prior pushed impact={prior_usd})" if push else " (below push threshold; no push)"))
    notified = _notify_updated(client, project, issue_id, norm, prior_usd) if push else False
    logger.info(json.dumps({"event": "anomaly_issue_replayed", "key": key, "issue_id": issue_id, "pushed": notified}))
    return {"action": "replayed", "key": key, "issue_id": issue_id, "project": project, "notified": notified}


def _select_adapter(event_source: Any) -> Any:
    """Per-record source (SNS MessageAttributes.anomaly_source, ENC-TSK-R83-0B) wins over the
    ANOMALY_SOURCE env default, so one responder serves every registered source."""
    per_record = ""
    if isinstance(event_source, dict):
        attr = (event_source.get("MessageAttributes") or {}).get("anomaly_source") or {}
        per_record = str(attr.get("Value") or "").strip()
    return ADAPTERS.resolve(per_record or os.environ.get("ANOMALY_SOURCE"), aws_cad_adapter.SOURCE)


def run_scheduled_digest(event: Dict[str, Any], client: Any, collect: Optional[Any] = None) -> Dict[str, Any]:
    """Scheduled (EventBridge) intake: ``{"digest_source": "<registered source>"}``. The adapter
    collects its own read-only snapshot (``collect_message``) and the anomalies flow through the
    same idempotent ``process_anomaly`` create path as SNS-delivered ones (ENC-TSK-R83-0C)."""
    source = str(event.get("digest_source") or "")
    adapter = ADAPTERS.get(source)
    collect_fn = collect or getattr(adapter, "collect_message", None)
    if adapter is None or collect_fn is None:
        raise RuntimeError(f"digest_source {source!r} is not a registered collecting adapter")
    anomalies = source_adapters.parse_message(adapter, collect_fn())
    results = [process_anomaly(norm, client) for norm in anomalies]
    summary = {"event": "anomaly_digest_complete", "source": source, "processed": len(results)}
    logger.info(json.dumps(summary))
    return {"summary": summary, "results": results}


def lambda_handler(event: Any, context: Any, client: Optional[Any] = None,
                   identity: Optional[Identity] = None) -> Dict[str, Any]:
    is_enrich = isinstance(event, dict) and "enrichment_request" in event
    owns_identity = False
    if client is None:
        client = TrackerClient()
        if identity is None and ((event or {}).get("Records") or is_enrich or (event or {}).get("digest_source")):
            if is_enrich:
                # ENC-TSK-R83-0A is fail-open: no identity -> no advisory write, never an error.
                try:
                    identity = acquire_identity()
                    owns_identity = True
                except Exception as exc:  # noqa: BLE001
                    logger.warning("enrichment skipped, identity unavailable: %s", exc)
                    return {"enrichment": {"skipped": "identity_unavailable"}}
            else:
                identity = acquire_identity()  # raises (fail closed) BEFORE any mutation
                owns_identity = True
    if identity is not None and hasattr(client, "set_identity"):
        client.set_identity(identity)
    try:
        if is_enrich:
            # ENC-TSK-R83-0A: async enrichment leg (self-invoked after intake). Never raises (fail-open).
            return {"enrichment": enrichment.enrich(event["enrichment_request"], client)}
        return _run(event, client)
    finally:
        if owns_identity and identity is not None:
            retire_identity(identity)


def _run(event: Any, client: Any) -> Dict[str, Any]:
    if isinstance(event, dict) and event.get("digest_source"):
        return run_scheduled_digest(event, client)  # ENC-TSK-R83-0C weekly schedule
    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    suppressed = 0
    for record in (event or {}).get("Records") or []:
        sns = record.get("Sns") or {}
        adapter = _select_adapter(sns)
        try:
            anomalies = source_adapters.parse_message(adapter, sns.get("Message") or "")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"normalize: {exc}")
            continue
        if not anomalies:
            suppressed += 1
        for norm in anomalies:
            try:
                res = process_anomaly(norm, client)
                results.append(res)
                # Single enrichment call site: AFTER the issue exists. Async + fail-open; a dispatch
                # failure can never fail intake or the SNS retry contract.
                if res.get("issue_id"):
                    try:
                        enrichment.dispatch_async(
                            getattr(context, "function_name", "") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME", ""),
                            {"norm": norm, "key": res["key"], "project": res["project"], "issue_id": res["issue_id"]})
                    except Exception as exc:  # noqa: BLE001 -- enrichment must never fail intake
                        logger.error("enrichment dispatch raised (ignored): %s", exc)
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
