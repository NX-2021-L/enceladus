"""Rhythm Cycle beat Lambda — ENC-PLN-068 / ENC-FTR-123..126.

EventBridge Scheduler (or rule) invokes with {"tier": "<name>"}.
Each beat: read predecessor artifact -> tier work -> write artifact -> emit metrics.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict

from artifact_store import read_latest
from baseline import run_baseline_capture
from config import TIER_PREDECESSOR
from legacy_schedules import inventory_document
from metrics import publish_beat_metrics
from tiers.coherence import run_coherence
from tiers.decide import run_decide
from tiers.heavy_integrate import run_heavy_integrate
from tiers.light_integrate import run_light_integrate
from tiers.sense import run_sense

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TIER_HANDLERS: Dict[str, Callable[[], Dict[str, Any]]] = {
    "sense": run_sense,
    "decide": run_decide,
    "light_integrate": run_light_integrate,
    "heavy_integrate": run_heavy_integrate,
    "coherence": run_coherence,
    # ENC-TSK-N26: on-demand pre-cutover baseline capture. Deliberately absent
    # from config.TIER_ORDER / TIER_PREDECESSOR -- not part of the scheduled
    # harmonic beat chain, invoked standalone via {"tier": "baseline_capture"}.
    "baseline_capture": run_baseline_capture,
}


def _cost_estimate(tier: str, duration_ms: float) -> float:
    # Nominal USD micro-estimates for telemetry validation (DOC-BDDE755DB874 §6).
    base = {"sense": 0.0001, "light_integrate": 0.001, "decide": 0.002, "heavy_integrate": 0.01, "coherence": 0.0005}
    return round(base.get(tier, 0.001) + duration_ms * 1e-7, 6)


def run_beat(tier: str) -> Dict[str, Any]:
    tier = (tier or "").strip().lower()
    if tier not in TIER_HANDLERS:
        raise ValueError(f"Unknown rhythm tier: {tier}")

    predecessor = TIER_PREDECESSOR.get(tier)
    if predecessor:
        pred_art = read_latest(predecessor)
        if pred_art is None:
            logger.warning("Predecessor artifact missing for tier=%s pred=%s", tier, predecessor)

    started = time.perf_counter()
    result = TIER_HANDLERS[tier]()
    duration_ms = (time.perf_counter() - started) * 1000.0

    artifact_bytes = int(result.get("bytes") or 0)
    extra = {}
    if tier == "heavy_integrate":
        extra["deferral_count"] = float(result.get("deferral_count") or 0)
    if tier == "decide":
        extra["backlog_open_leaves"] = float(result.get("backlog_open_leaves") or 0)

    publish_beat_metrics(
        tier,
        duration_ms=duration_ms,
        cost_estimate=_cost_estimate(tier, duration_ms),
        artifact_bytes=artifact_bytes,
        backlog_delta=result.get("open_task_delta") or result.get("backlog_open_leaves_delta"),
        extra=extra or None,
    )
    result["duration_ms"] = duration_ms
    return result


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    if event.get("action") == "legacy_inventory":
        return inventory_document()

    tier = event.get("tier") or event.get("detail", {}).get("tier")
    if not tier and event.get("resources"):
        # EventBridge rule name heuristic: rhythm-sense-hourly-gamma -> sense
        for r in event["resources"]:
            if "sense" in r:
                tier = "sense"
            elif "decide" in r:
                tier = "decide"
            elif "light" in r:
                tier = "light_integrate"
            elif "heavy" in r:
                tier = "heavy_integrate"
            elif "coherence" in r:
                tier = "coherence"

    if not tier:
        return {"error": "tier required", "event": event}

    try:
        body = run_beat(str(tier))
        return {"statusCode": 200, "body": json.dumps(body)}
    except Exception as exc:
        logger.exception("beat failed tier=%s", tier)
        return {"statusCode": 500, "body": json.dumps({"error": str(exc), "tier": tier})}
