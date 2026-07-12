"""Rhythm Cycle configuration (ENC-PLN-068 / DOC-BDDE755DB874)."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")
S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")
S3_PREFIX = os.environ.get("S3_PREFIX", "rhythm-cycle").strip("/")
S3_ENV_PREFIX = os.environ.get("S3_ENV_PREFIX", "").strip("/")

TRACKER_API_BASE = os.environ.get("TRACKER_API_BASE", "").rstrip("/")
COORDINATION_API_BASE = os.environ.get("COORDINATION_API_BASE", "").rstrip("/")
GRAPH_QUERY_API_BASE = os.environ.get("GRAPH_QUERY_API_BASE", "").rstrip("/")
INTERNAL_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")

CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Enceladus/Rhythm")
SNS_TOPIC_ARN = os.environ.get("RHYTHM_SNS_TOPIC_ARN", "")

PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
AGENT_SESSIONS_TABLE = os.environ.get("AGENT_SESSIONS_TABLE", "agent-sessions")
# ENC-TSK-N26: percolation_monitor's own telemetry table, read-only from here.
# Default matches percolation_monitor/lambda_function.py's PERCOLATION_TABLE default.
PERCOLATION_TABLE = os.environ.get("PERCOLATION_TABLE", "enceladus-percolation-telemetry")

# JSON list of record_id prefixes or exact ids allowed for in-beat dispatch.
PRE_APPROVED_SCOPES_RAW = os.environ.get("PRE_APPROVED_DISPATCH_SCOPES", "[]")

TIER_ORDER = ("sense", "light_integrate", "decide", "heavy_integrate", "coherence")

TIER_PREDECESSOR = {
    "sense": None,
    "light_integrate": "sense",
    "decide": "light_integrate",
    "heavy_integrate": "decide",
    "coherence": "heavy_integrate",
}


def artifact_prefix() -> str:
    parts = [p for p in (S3_ENV_PREFIX, S3_PREFIX) if p]
    return "/".join(parts)


def pre_approved_scopes() -> List[str]:
    try:
        parsed = json.loads(PRE_APPROVED_SCOPES_RAW or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(x).strip() for x in parsed if str(x).strip()]


def internal_headers() -> Dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if INTERNAL_KEY:
        headers["X-Coordination-Internal-Key"] = INTERNAL_KEY
    return headers
