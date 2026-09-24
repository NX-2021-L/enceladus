"""Heavy Integrate — tenant orchestration beat (ENC-TSK-K89/K90, ENC-TSK-N18).

Scope execution (embeddings/summarization/library_health) moved from
in-beat stub marking to asynchronous tenant invocation via tenant_invoker —
see DOC-44230223DD1C §4.1. The governance-hash recompute hook stays in-beat
(it may become the first wired tenant later; ENC-TSK-N23/N24 decide), with
its contention-deferral behavior against an active governance_hash_recompute
checkout preserved from the prior implementation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Set

import tenant_invoker
from artifact_store import read_latest, write_artifact
from config import COORDINATION_API_BASE, PROJECT_ID
from http_client import post_json

logger = logging.getLogger(__name__)

BEAT_TYPE = "heavy_integrate"


def _active_checkout_components(sense: Dict[str, Any]) -> Set[str]:
    comps: Set[str] = set()
    for row in sense.get("active_checkouts") or []:
        for c in row.get("components") or []:
            comps.add(str(c))
    return comps


def _run_governance_recompute_hook(blocked: Set[str]) -> Dict[str, Any]:
    """In-beat governance-hash recompute hook (preserved from the prior
    executed_scopes-driven implementation, contention-deferred the same way:
    skipped while governance_hash_recompute is an actively checked-out
    component)."""
    if "governance_hash_recompute" in blocked or not COORDINATION_API_BASE:
        return {}
    try:
        # ENC-TSK-N18 fix: COORDINATION_API_BASE already ends in /api/v1 —
        # the old f"{COORDINATION_API_BASE}/api/v1/governance/recompute"
        # double-prefixed and 404'd.
        return post_json(
            f"{COORDINATION_API_BASE}/governance/recompute",
            {"project_id": PROJECT_ID, "trigger": "rhythm-heavy-integrate"},
        )
    except Exception as exc:
        logger.warning("hash recompute hook failed: %s", exc)
        return {"error": str(exc)}


def run_heavy_integrate() -> Dict[str, Any]:
    sense = read_latest("sense") or {}
    blocked = _active_checkout_components(sense)
    beat_ts = datetime.now(timezone.utc)

    recompute_result = _run_governance_recompute_hook(blocked)
    tenant_orchestration = tenant_invoker.run_tenant_orchestration(BEAT_TYPE, beat_ts)

    report = {
        "beat_type": BEAT_TYPE,
        "recompute_backlog": recompute_result,
        "tenant_orchestration": tenant_orchestration,
        "embedding_refresh_window": True,
    }
    keys = write_artifact(BEAT_TYPE, report, beat_ts)
    report.update(keys)
    return report
