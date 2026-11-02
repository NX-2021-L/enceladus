"""aws-cad source adapter (ENC-FTR-150 AC-1/AC-3/AC-8; absorbs ENC-FTR-100 AC-2/AC-3).

Pure, deterministic, no AWS calls, no LLM. Turns an AWS Cost Anomaly Detection SNS
message body (anomalyId, anomalyStartDate/EndDate, impact{...}, rootCauses[], ...) into
the source-agnostic normalized shape the primitive consumes:

    {source, anomaly_id, project, title, evidence[], priority, severity, category,
     impact{...}, breakdown[...]}

Adapter contract (the AC-8 seam; see sns_anomaly_responder.lambda_function):
    SOURCE: str
    parse(message: str) -> list[dict]      # normalized anomalies, threshold already applied
A second adapter (MENTIONS drift, weekly magnitude digest, v5 capture-plane events) only
has to provide these two names; dedupe/create/notify/enrich never read source internals.

FTR-100 AC-2: significance = absolute-dollar floor AND (optional) percentage threshold.
FTR-100 AC-3: per-service + per-usage-type breakdown is carried in evidence.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SOURCE = "aws-cad"
# D-7 (W0.5, 2026-11-02): cost anomalies route to `devops`; enrichment may only PROPOSE a re-route.
DEFAULT_PROJECT = "devops"
DEFAULT_MIN_IMPACT_USD = 1.0
DEFAULT_MIN_IMPACT_PCT = 35.0  # FTR-100 AC-2 initial target (~35% day-over-day)
MAX_BREAKDOWN_ROWS = 25


def _f(value: Any) -> Optional[float]:
    try:
        if value is None or isinstance(value, bool):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return default
    return val if val >= 0 else default


def thresholds() -> Dict[str, float]:
    """Configurable without a code change (FTR-100 AC-2/AC-4): Lambda env vars."""
    return {
        "min_impact_usd": _env_float("CAD_MIN_IMPACT_USD", DEFAULT_MIN_IMPACT_USD),
        "min_impact_pct": _env_float("CAD_MIN_IMPACT_PCT", DEFAULT_MIN_IMPACT_PCT),
    }


def is_significant(impact_usd: Optional[float], impact_pct: Optional[float], th: Dict[str, float]) -> bool:
    """Absolute-dollar floor is mandatory; the percentage gate applies only when AWS supplied a
    percentage (new spend with no baseline has none and is always significant above the floor)."""
    if impact_usd is None or impact_usd < th["min_impact_usd"]:
        return False
    if impact_pct is None or th["min_impact_pct"] <= 0:
        return True
    return impact_pct >= th["min_impact_pct"]


_CLOSED_STATES = {"CLOSED", "RESOLVED", "ENDED", "COMPLETED"}


def is_closed_signal(payload: Dict[str, Any]) -> bool:
    """ENC-FTR-150 AC-5: a CAD anomaly-closed signal (explicit state/status field or closed flag).
    An ongoing anomaly's anomalyEndDate is merely the latest observed day, so it is NOT used."""
    if payload.get("closed") is True:
        return True
    for key in ("anomalyStatus", "status", "state", "anomalyState"):
        if str(payload.get(key) or "").strip().upper() in _CLOSED_STATES:
            return True
    return False


def _breakdown(root_causes: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(root_causes, list):
        return rows
    for rc in root_causes[:MAX_BREAKDOWN_ROWS]:
        if not isinstance(rc, dict):
            continue
        row = {
            "service": rc.get("service") or "",
            "usage_type": rc.get("usageType") or rc.get("usage_type") or "",
            "region": rc.get("region") or "",
            "linked_account": rc.get("linkedAccountName") or rc.get("linkedAccount") or "",
        }
        contribution = _f((rc.get("impact") or {}).get("contribution")) if isinstance(rc.get("impact"), dict) else None
        if contribution is not None:
            row["contribution_usd"] = round(contribution, 2)
        rows.append(row)
    return rows


def normalize(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Deterministic normalize of ONE CAD anomaly. Returns None when the payload is not a CAD
    anomaly (no anomalyId). Thresholding is applied by parse(), not here, so callers/tests can
    inspect suppressed anomalies."""
    anomaly_id = str(payload.get("anomalyId") or "").strip()
    if not anomaly_id:
        return None
    impact_in = payload.get("impact") if isinstance(payload.get("impact"), dict) else {}
    total_impact = _f(impact_in.get("totalImpact"))
    impact = {
        "total_impact_usd": total_impact,
        "max_impact_usd": _f(impact_in.get("maxImpact")),
        "total_actual_spend_usd": _f(impact_in.get("totalActualSpend")),
        "total_expected_spend_usd": _f(impact_in.get("totalExpectedSpend")),
        "total_impact_pct": _f(impact_in.get("totalImpactPercentage")),
    }
    breakdown = _breakdown(payload.get("rootCauses"))
    services = sorted({r["service"] for r in breakdown if r["service"]})
    if not services and payload.get("dimensionValue"):
        services = [str(payload["dimensionValue"])]
    svc_label = ", ".join(services) if services else "unattributed"
    impact_label = f"${total_impact:,.2f}" if total_impact is not None else "unknown impact"
    title = f"[cost-anomaly] {svc_label}: {impact_label} above expected spend [aws-cad:{anomaly_id}]"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    steps = [
        f"Open the AWS Cost Anomaly Detection anomaly {anomaly_id}"
        + (f" ({payload['anomalyDetailsLink']})" if payload.get("anomalyDetailsLink") else ""),
        "aws ce get-anomalies --region us-east-1 --date-interval "
        f"StartDate={str(payload.get('anomalyStartDate') or '')[:10]},EndDate={str(payload.get('anomalyEndDate') or '')[:10]}",
    ]
    for row in breakdown:
        steps.append(
            f"Compare {row['service'] or 'service'} / {row['usage_type'] or 'usage-type'}"
            f" ({row['region'] or 'region n/a'}) against its trailing baseline in Cost Explorer"
        )
    evidence = [
        {
            "description": (
                f"AWS Cost Anomaly Detection {anomaly_id}: {impact_label} total impact "
                f"({impact['total_actual_spend_usd']} actual vs {impact['total_expected_spend_usd']} expected USD)"
            ),
            "observed_by": "sns-anomaly-responder",
            "timestamp": now,
            "steps_to_duplicate": steps,
            "source": SOURCE,
            "anomaly_id": anomaly_id,
            "source_key": f"{SOURCE}:{anomaly_id}",
            "anomaly_start": payload.get("anomalyStartDate"),
            "anomaly_end": payload.get("anomalyEndDate"),
            "monitor": payload.get("monitorName") or payload.get("monitorArn"),
            "impact": impact,
            "breakdown": breakdown,
        }
    ]
    out = {
        "source": SOURCE,
        "anomaly_id": anomaly_id,
        "project": os.environ.get("ANOMALY_DEFAULT_PROJECT", DEFAULT_PROJECT).strip() or DEFAULT_PROJECT,
        "title": title,
        "evidence": evidence,
        "priority": "P2",
        "severity": "medium",
        "category": "risk",
        "impact": impact,
        "breakdown": breakdown,
        "raw_ref": payload.get("anomalyDetailsLink"),
    }
    if is_closed_signal(payload):
        out["lifecycle"] = "closed"
    return out


def parse(message: str) -> List[Dict[str, Any]]:
    """SNS Message string -> significant normalized anomalies. A CAD IMMEDIATE alert carries one
    anomaly object; a list is tolerated. Non-JSON / non-CAD bodies yield []."""
    try:
        body = json.loads(message)
    except (TypeError, ValueError):
        return []
    items = body if isinstance(body, list) else [body]
    th = thresholds()
    out: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        norm = normalize(item)
        if norm is None:
            continue
        imp = norm["impact"]
        if norm.get("lifecycle") == "closed":
            out.append(norm)  # closed signals bypass the significance gate: they annotate an existing issue
            continue
        if not is_significant(imp["total_impact_usd"], imp["total_impact_pct"], th):
            norm["suppressed"] = True
            continue
        out.append(norm)
    return out
