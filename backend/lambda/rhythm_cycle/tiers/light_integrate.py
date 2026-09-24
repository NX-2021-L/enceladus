"""Light Integrate — delta-only consolidation + tenant orchestration
(ENC-TSK-K88, ENC-TSK-N18).

Scope execution routes through the same tenant_invoker mechanism as
Heavy Integrate — see DOC-44230223DD1C §4.1.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr

import tenant_invoker
from artifact_store import read_latest, write_artifact
from config import PROJECTS_TABLE

logger = logging.getLogger(__name__)
_ddb = boto3.resource("dynamodb")

BEAT_TYPE = "light_integrate"


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
    prior = read_latest(BEAT_TYPE) or {}
    since = str(prior.get("beat_at") or "")
    changed = _changed_since(since)
    beat_ts = datetime.now(timezone.utc)

    tenant_orchestration = tenant_invoker.run_tenant_orchestration(BEAT_TYPE, beat_ts)

    report = {
        "beat_type": BEAT_TYPE,
        "changed_record_ids": changed,
        "delta_count": len(changed),
        "actions": ["fsrs_decay_tick", "incremental_doc_summary", "changed_graph_touch"],
        "tenant_orchestration": tenant_orchestration,
        "embedding_refresh": False,
    }
    keys = write_artifact(BEAT_TYPE, report, beat_ts)
    report.update(keys)
    return report
