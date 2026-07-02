"""Legacy schedule inventory for K91 migration tracking."""

from __future__ import annotations

from typing import Any, Dict, List

# Gamma schedules superseded by rhythm tiers when RHYTHM_CYCLE_ENABLED=true.
LEGACY_SCHEDULE_INVENTORY: List[Dict[str, Any]] = [
    {
        "rule_name": "enceladus-memory-consolidation-nightly-gamma",
        "legacy_cadence": "cron(0 2 * * ? *)",
        "rhythm_tier": "heavy_integrate",
        "rollback": "Re-enable EventBridge rule State=ENABLED",
    },
    {
        "rule_name": "devops-recompute-governance-backstop-gamma",
        "legacy_cadence": "rate(1 hour)",
        "rhythm_tier": "heavy_integrate",
        "rollback": "Re-enable EventBridge rule State=ENABLED",
    },
    {
        "rule_name": "enceladus-graph-health-metrics-daily-gamma",
        "legacy_cadence": "cron(0 6 * * ? *)",
        "rhythm_tier": "sense",
        "rollback": "Re-enable EventBridge rule State=ENABLED",
    },
    {
        "rule_name": "devops-titan-embedding-backfill-gamma",
        "legacy_cadence": "on-demand / legacy",
        "rhythm_tier": "heavy_integrate",
        "rollback": "Restore prior EventBridge trigger if any",
    },
]


def inventory_document() -> Dict[str, Any]:
    return {
        "inventory_version": "1",
        "legacy_jobs": LEGACY_SCHEDULE_INVENTORY,
        "migration_policy": "Disable superseded gamma EventBridge rules when RhythmCycleEnabled parameter is true",
    }
