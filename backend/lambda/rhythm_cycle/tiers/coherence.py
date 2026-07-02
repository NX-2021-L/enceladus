"""Coherence-point snapshots at 00:00/12:00 UTC (ENC-TSK-K92)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from artifact_store import read_latest, write_artifact

TIERS = ("sense", "light_integrate", "decide", "heavy_integrate")


def run_coherence() -> Dict[str, Any]:
    combined: Dict[str, Any] = {}
    for tier in TIERS:
        combined[tier] = read_latest(tier)

    snapshot = {
        "beat_type": "coherence",
        "alignment_point_utc": datetime.now(timezone.utc).replace(minute=0, second=0).isoformat(),
        "tier_artifacts": combined,
    }
    keys = write_artifact("coherence", snapshot, datetime.now(timezone.utc))
    snapshot.update(keys)
    return snapshot
