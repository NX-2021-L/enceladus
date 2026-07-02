"""Light Integrate — delta-only consolidation (ENC-TSK-K88)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr

from artifact_store import read_latest, write_artifact
from config import PROJECTS_TABLE

logger = logging.getLogger(__name__)
_ddb = boto3.resource("dynamodb")


def _changed_since(iso_ts: str) -> List[str]:
    if not iso_ts:
        return []
    table = _ddb.Table(PROJECTS_TABLE)
    changed: List[str] = []
    scan_kwargs: Dict[str, Any] = {"FilterExpression": Attr("updated_at").gt(iso_ts)}
    while True:
        resp = table.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            rid = item.get("item_id") or item.get("record_id")
            if rid:
                changed.append(str(rid))
        token = resp.get("LastEvaluatedKey")
        if not token:
            break
        scan_kwargs["ExclusiveStartKey"] = token
    return changed


def run_light_integrate() -> Dict[str, Any]:
    prior = read_latest("light_integrate") or {}
    since = str(prior.get("beat_at") or "")
    changed = _changed_since(since)

    report = {
        "beat_type": "light_integrate",
        "changed_record_ids": changed,
        "delta_count": len(changed),
        "actions": ["fsrs_decay_tick", "incremental_doc_summary", "changed_graph_touch"],
        "embedding_refresh": False,
    }
    keys = write_artifact("light_integrate", report, datetime.now(timezone.utc))
    report.update(keys)
    return report
