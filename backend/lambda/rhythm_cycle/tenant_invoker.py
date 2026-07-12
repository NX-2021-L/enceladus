"""Rhythm tenant orchestration — ENC-TSK-N18 / BRD DOC-44230223DD1C §4.1.

Heavy Integrate and Light Integrate become tenant ORCHESTRATORS: each beat
resolves an ordered tenant manifest from AppConfig (application/environment
shared with the rest of Enceladus per enceladus_shared.appconfig_flags idiom;
dedicated configuration profile ``rhythm-tenants``, env-overridable — mirrors
coordination_api/budget_hierarchy.py's ``_appconfig_budget_config`` pattern
but adds an in-invocation cache since this fires on every beat). One boolean
flag per tenant addresses as ``rhythm.tenant.<name>.enabled`` (physically the
``enabled`` key nested under ``tenants.<name>`` in the profile JSON, since
AppConfig hosted config is a single JSON document, not flat key/value flags).

For each enabled tenant the beat fires an ASYNCHRONOUS (InvocationType=Event)
Lambda invoke with a uniform payload and never waits — the beat must stay
under a minute; tenants own their own timeouts. Tenants report completion by
writing a JSON "stanza" (write_completion_stanza) to a per-beat S3 result
prefix. The *next* occurrence of the same beat (12h later for heavy, 6h for
light) aggregates the previous window's stanzas against the manifest it
invoked, tracks a per-tenant consecutive-silence streak in the beat's own S3
artifact (mirrors the existing deferral_streaks idiom previously in
heavy_integrate.py), and emits an Enceladus/Rhythm CloudWatch stall metric
once a tenant has been silent for two consecutive windows.

A tenant's ``enabled`` flag doubles as its kill switch: flipping it false in
AppConfig removes it from the manifest with no redeploy.

The manifest ships with ZERO enabled tenants by default — this module is
mechanism only. Wiring real tenants into the ``rhythm-tenants`` AppConfig
profile is ENC-TSK-N23/N24's job.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

from artifact_store import read_latest
from config import CLOUDWATCH_NAMESPACE, PROJECT_ID, S3_BUCKET, TIER_PREDECESSOR, artifact_prefix
from identity import resolve_identity

logger = logging.getLogger(__name__)

_lambda = boto3.client("lambda")
_s3 = boto3.client("s3")
_cw = boto3.client("cloudwatch")

# --- AppConfig retrieval: same extension/URL idiom as enceladus_shared
# ---     .appconfig_flags / budget_hierarchy._appconfig_budget_config, but
# ---     targeting a dedicated "rhythm-tenants" configuration profile, with
# ---     an in-invocation cache (ENC-TSK-N18 requires caching; the beat can
# ---     call get_manifest() more than once per invocation).
_APPCONFIG_PORT = os.environ.get("AWS_APPCONFIG_EXTENSION_HTTP_PORT", "2772")
_APPCONFIG_CONFIGURATION = os.environ.get("RHYTHM_TENANTS_APPCONFIG_CONFIGURATION", "rhythm-tenants")
_CACHE: Dict[str, Any] = {}
_CACHE_AT: float = 0.0
_CACHE_TTL: float = float(os.environ.get("AWS_APPCONFIG_EXTENSION_POLL_INTERVAL_SECONDS", "45"))

# Two consecutive silent windows before a tenant is considered stalled
# (DOC-44230223DD1C §4.1: "two consecutive silent windows").
STALL_THRESHOLD = 2

# ENC-TSK-N21: fallback used when governed-identity resolution is degraded
# (RHYTHM_AGENT_TYPE_ID unset or the coordination API unreachable) — same
# string the "session_identity" payload field carried before N21 landed.
SESSION_IDENTITY_PLACEHOLDER = os.environ.get(
    "RHYTHM_TENANT_SESSION_IDENTITY", "rhythm-cycle-beat-unidentified"
)


def _session_identity() -> str:
    """ENC-TSK-N21 / BRD §4.3: resolve the rhythm's governed ENC-SES identity
    for the ``session_identity`` tenant-invoke payload field. Falls back to
    SESSION_IDENTITY_PLACEHOLDER when identity resolution is degraded — never
    raises, since one tenant's identity curiosity must never block a beat.
    """
    identity = resolve_identity()
    return str(identity.get("session_id") or "") or SESSION_IDENTITY_PLACEHOLDER


def _fetch_tenant_config() -> Dict[str, Any]:
    app = os.environ.get("APPCONFIG_APPLICATION", "")
    env = os.environ.get("APPCONFIG_ENVIRONMENT", "")
    if not app or not env:
        return {}
    url = (
        f"http://localhost:{_APPCONFIG_PORT}/applications/{app}/environments/{env}"
        f"/configurations/{_APPCONFIG_CONFIGURATION}"
    )
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:  # noqa: S310 - localhost extension
            data = json.loads(resp.read())
        return data if isinstance(data, dict) else {}
    except (urllib.error.URLError, OSError, ValueError):
        return {}


def _tenant_config() -> Dict[str, Any]:
    global _CACHE, _CACHE_AT
    now = time.monotonic()
    if not _CACHE or now - _CACHE_AT >= _CACHE_TTL:
        fresh = _fetch_tenant_config()
        if fresh:
            _CACHE = fresh
            _CACHE_AT = now
    return _CACHE


@dataclass
class TenantDef:
    name: str
    beat: str
    function_name: str
    order: int = 0
    expected_output_contract: Dict[str, Any] = field(default_factory=dict)


def get_manifest(beat_type: str) -> List[TenantDef]:
    """Ordered, enabled-only tenant manifest for ``beat_type``.

    Reads the ``tenants`` object from the ``rhythm-tenants`` AppConfig
    profile: ``{"tenants": {"<name>": {"beat": ..., "enabled": ..., ...}}}``.
    A tenant is included only if its ``beat`` matches and ``enabled`` is
    true — the same flag is the kill switch. Ordering is by explicit
    ``order`` (ties broken by name) so manifest order never depends on JSON
    key order.
    """
    tenants = (_tenant_config().get("tenants") or {})
    out: List[TenantDef] = []
    if not isinstance(tenants, dict):
        return out
    for name, raw in tenants.items():
        if not isinstance(raw, dict):
            continue
        if raw.get("beat") != beat_type:
            continue
        if not bool(raw.get("enabled", False)):
            continue
        function_name = str(raw.get("function_name") or "").strip()
        if not function_name:
            logger.warning("rhythm tenant %s enabled but missing function_name; skipping", name)
            continue
        out.append(
            TenantDef(
                name=str(name),
                beat=beat_type,
                function_name=function_name,
                order=int(raw.get("order") or 0),
                expected_output_contract=dict(raw.get("expected_output_contract") or {}),
            )
        )
    out.sort(key=lambda t: (t.order, t.name))
    return out


def result_prefix_for(beat_type: str, beat_ts: datetime) -> str:
    """Per-beat S3 result prefix tenants write completion stanzas under."""
    ts = beat_ts.astimezone(timezone.utc)
    return (
        f"{artifact_prefix()}/{beat_type}/tenant-results/"
        f"{ts.year:04d}{ts.month:02d}{ts.day:02d}-{ts.hour:02d}{ts.minute:02d}{ts.second:02d}"
    )


def invoke_tenants(
    beat_type: str,
    beat_ts: datetime,
    predecessor_artifact_key: Optional[str],
    manifest: Optional[List[TenantDef]] = None,
) -> Dict[str, Any]:
    """Fire-and-forget (Event) invoke every enabled tenant for this beat.

    Never blocks on and never raises for an individual tenant's invoke
    failure — logs and continues, since the beat must stay under a minute
    and tenants own their own completion/timeout handling.
    """
    manifest = get_manifest(beat_type) if manifest is None else manifest
    prefix = result_prefix_for(beat_type, beat_ts)
    beat_iso = beat_ts.astimezone(timezone.utc).isoformat()
    invoked: List[Dict[str, Any]] = []
    # Resolved once per invoke_tenants call — every tenant in this beat shares
    # the same governed identity (or the same degraded fallback).
    session_identity = _session_identity()

    for tenant in manifest:
        result_key = f"{prefix}/{tenant.name}.json"
        payload = {
            "beat_id": f"{beat_type}-{beat_iso}",
            "beat_type": beat_type,
            "beat_at": beat_iso,
            "predecessor_artifact_key": predecessor_artifact_key,
            "expected_output_contract": tenant.expected_output_contract,
            # ENC-TSK-N21 / BRD §4.3: governed rhythm identity (ENC-SES id, or
            # SESSION_IDENTITY_PLACEHOLDER on degraded resolution).
            "session_identity": session_identity,
            "result_key": result_key,
        }
        try:
            _lambda.invoke(
                FunctionName=tenant.function_name,
                InvocationType="Event",
                Payload=json.dumps(payload).encode("utf-8"),
            )
            invoked.append({"name": tenant.name, "function_name": tenant.function_name, "result_key": result_key})
        except Exception as exc:  # noqa: BLE001 - one tenant's failure must never break the beat
            logger.warning(
                "async invoke failed tenant=%s fn=%s: %s", tenant.name, tenant.function_name, exc
            )

    return {
        "beat_type": beat_type,
        "result_prefix": prefix,
        "invoked_tenants": invoked,
        "manifest_size": len(manifest),
    }


def write_completion_stanza(
    result_key: str, tenant_name: str, status: str, detail: Optional[Dict[str, Any]] = None
) -> None:
    """Contract helper for tenant Lambdas: write their completion stanza.

    Not yet called by any tenant in this repo (ENC-TSK-N23/N24 wires real
    tenants) — the shape is fixed now so the contract doesn't move under
    them later. ``result_key`` is the value the beat sent as
    ``payload["result_key"]``.
    """
    body = {
        "tenant": tenant_name,
        "status": status,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail or {},
    }
    _s3.put_object(
        Bucket=S3_BUCKET,
        Key=result_key,
        Body=json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        ContentType="application/json",
    )


def _list_stanza_tenants(result_prefix: str) -> List[str]:
    if not result_prefix:
        return []
    prefix = result_prefix.rstrip("/") + "/"
    found: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": S3_BUCKET, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        try:
            resp = _s3.list_objects_v2(**kwargs)
        except Exception as exc:
            logger.warning("list_objects_v2 failed prefix=%s: %s", result_prefix, exc)
            return found
        for obj in resp.get("Contents", []):
            key = obj.get("Key", "")
            name = key[len(prefix):]
            if name.endswith(".json"):
                name = name[: -len(".json")]
            if name:
                found.append(name)
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return found


def check_silent_tenants(
    prior_invoked_names: List[str],
    prior_result_prefix: Optional[str],
    prior_streaks: Dict[str, int],
) -> Dict[str, Any]:
    """Compare the previous window's invoked tenants against the completion
    stanzas actually found under its result prefix.

    Returns updated per-tenant consecutive-silence streaks plus which
    tenants just reached/crossed ``STALL_THRESHOLD``.
    """
    reported = set(_list_stanza_tenants(prior_result_prefix)) if prior_result_prefix else set()
    invoked_set = set(prior_invoked_names)
    streaks = {k: v for k, v in (prior_streaks or {}).items() if k in invoked_set}
    silent: List[str] = []
    stalled: List[str] = []

    for name in prior_invoked_names:
        if name in reported:
            streaks[name] = 0
        else:
            streaks[name] = int(streaks.get(name, 0)) + 1
            silent.append(name)
            if streaks[name] >= STALL_THRESHOLD:
                stalled.append(name)

    return {
        "silent_tenants": silent,
        "stalled_tenants": stalled,
        "tenant_silence_streaks": streaks,
        "reporting_tenants": sorted(reported & invoked_set),
    }


def emit_stall_metrics(beat_type: str, stalled_tenants: List[str]) -> None:
    """Emit an Enceladus/Rhythm CloudWatch metric per tenant that just
    crossed the stall threshold, suitable for alarming."""
    for name in stalled_tenants:
        try:
            _cw.put_metric_data(
                Namespace=CLOUDWATCH_NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "tenant_stall",
                        "Dimensions": [
                            {"Name": "Tier", "Value": beat_type},
                            {"Name": "ProjectId", "Value": PROJECT_ID},
                            {"Name": "Tenant", "Value": name},
                        ],
                        "Value": 1.0,
                        "Unit": "Count",
                    }
                ],
            )
        except Exception as exc:
            logger.warning("tenant_stall metric emission failed tenant=%s: %s", name, exc)


def run_tenant_orchestration(beat_type: str, beat_ts: datetime) -> Dict[str, Any]:
    """Single entry point tier beats call: aggregate the previous window's
    tenant reports (silent-tenant + stall detection), then fire this
    window's asynchronous tenant invocations. Never blocks/raises past a
    handled tenant failure."""
    predecessor_tier = TIER_PREDECESSOR.get(beat_type)
    predecessor_artifact = read_latest(predecessor_tier) if predecessor_tier else None
    predecessor_key = None
    if predecessor_artifact:
        predecessor_key = predecessor_artifact.get("timestamped_key") or predecessor_artifact.get("latest_key")

    prior = read_latest(beat_type) or {}
    prior_orch = prior.get("tenant_orchestration") or {}

    silence = check_silent_tenants(
        prior_invoked_names=[t["name"] for t in (prior_orch.get("invoked_tenants") or [])],
        prior_result_prefix=prior_orch.get("result_prefix"),
        prior_streaks=prior_orch.get("tenant_silence_streaks") or {},
    )
    emit_stall_metrics(beat_type, silence["stalled_tenants"])

    invocation = invoke_tenants(beat_type, beat_ts, predecessor_key)
    invocation.update(
        {
            "tenant_silence_streaks": silence["tenant_silence_streaks"],
            "silent_tenants_last_window": silence["silent_tenants"],
            "stalled_tenants": silence["stalled_tenants"],
            "reporting_tenants_last_window": silence["reporting_tenants"],
        }
    )
    return invocation
