"""Heavy Integrate — full sweeps + contention deferral (ENC-TSK-K89/K90)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from artifact_store import read_latest, write_artifact
from config import COORDINATION_API_BASE, PROJECT_ID
from http_client import post_json

logger = logging.getLogger(__name__)

DEFERRAL_ALERT_THRESHOLD = 3


def _active_checkout_components(sense: Dict[str, Any]) -> Set[str]:
    comps: Set[str] = set()
    for row in sense.get("active_checkouts") or []:
        for c in row.get("components") or []:
            comps.add(str(c))
    return comps


def _prior_deferrals() -> Dict[str, int]:
    prior = read_latest("heavy_integrate") or {}
    return dict(prior.get("deferral_streaks") or {})


def run_heavy_integrate() -> Dict[str, Any]:
    sense = read_latest("sense") or {}
    blocked = _active_checkout_components(sense)
    streaks = _prior_deferrals()

    scopes = ["embeddings", "summarization", "governance_hash_recompute", "library_health"]
    deferred: List[str] = []
    executed: List[str] = []

    for scope in scopes:
        if scope in blocked:
            deferred.append(scope)
            streaks[scope] = int(streaks.get(scope, 0)) + 1
        else:
            executed.append(scope)
            streaks[scope] = 0

    chronic = [s for s, n in streaks.items() if n >= DEFERRAL_ALERT_THRESHOLD]

    recompute_result: Dict[str, Any] = {}
    if "governance_hash_recompute" in executed and COORDINATION_API_BASE:
        try:
            recompute_result = post_json(
                f"{COORDINATION_API_BASE}/api/v1/governance/recompute",
                {"project_id": PROJECT_ID, "trigger": "rhythm-heavy-integrate"},
            )
        except Exception as exc:
            logger.warning("hash recompute hook failed: %s", exc)
            recompute_result = {"error": str(exc)}

    report = {
        "beat_type": "heavy_integrate",
        "executed_scopes": executed,
        "deferred_scopes": deferred,
        "deferral_count": len(deferred),
        "deferral_streaks": streaks,
        "chronic_deferral_alert": chronic,
        "embedding_refresh_window": True,
        "recompute_backlog": recompute_result,
    }
    keys = write_artifact("heavy_integrate", report, datetime.now(timezone.utc))
    report.update(keys)
    return report
