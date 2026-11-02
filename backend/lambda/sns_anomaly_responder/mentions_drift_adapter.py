"""MENTIONS drift adapter (ENC-TSK-R83-0B / ENC-FTR-150 AC-9).

Second source behind the source-adapter boundary (see source_adapters.py). The daily
mentions_drift_audit in devops-deploy-parity-validator used to POST a new ENC-ISS every breach
with run-specific counts in the title, which is what produced the ~40 "MENTIONS drift detected"
clones. It now hands its finding to the anomaly primitive, which dedupes on
``mentions-drift:{anomaly_id}``.

Input body (JSON, built by the audit; no wall-clock or sample-specific value feeds the id):

    {"audit": "mentions_drift_audit", "run_at": "...", "sample_size": 96, "mismatch_count": 33,
     "ratio": 0.34, "threshold": 0.01, "threshold_breached": true,
     "divergent": [{"record_id": "...", "record_type": "task", "missing": [...], "extra": [...]}]}

DRIFT SIGNATURE: the DIRECTION of the divergence across the sampled records, one of
``missing`` / ``extra`` / ``missing+extra``. The sample is a random recent window, so record ids,
counts and ratios vary run to run and must not enter the id; the direction is the failure mode
that tells an operator what kind of drift is open. At most three issues can ever exist.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List

SOURCE = "mentions-drift"
DEFAULT_PROJECT = "enceladus"
_STEPS = [
    "1. Wait for the next scheduled mentions_drift_audit run (devops-parity-drift-daily) or invoke devops-deploy-parity-validator with {\"action\": \"mentions_drift_audit\"}.",
    "2. Inspect the function's CloudWatch logs for the [START]/[END] mentions_drift_audit lines and the divergent_first_10 payload.",
    "3. For each divergent record_id run search(action='tracker.graphsearch', arguments={record_id, search_type='neighbors', edge_types=['MENTIONS'], direction='outgoing', depth=1}) and compare with the prose-extractor output.",
]


def drift_signature(divergent: List[Dict[str, Any]], body: Dict[str, Any] = None) -> str:
    """Direction set. The audit sends has_missing/has_extra computed over ALL divergent records
    (the list it ships is truncated to 10); fall back to the list when absent."""
    body = body or {}
    has_missing = bool(body["has_missing"]) if "has_missing" in body else any(
        d.get("missing") for d in divergent)
    has_extra = bool(body["has_extra"]) if "has_extra" in body else any(
        d.get("extra") for d in divergent)
    return "+".join(n for n, on in (("missing", has_missing), ("extra", has_extra)) if on)


def anomaly_id_for(signature: str) -> str:
    return "md-" + hashlib.sha256(f"mentions-drift:{signature}".encode()).hexdigest()[:12]


def parse(message: str) -> List[Dict[str, Any]]:
    try:
        body = json.loads(message)
    except (TypeError, ValueError):
        return []
    if not isinstance(body, dict) or not body.get("threshold_breached"):
        return []
    divergent = [d for d in (body.get("divergent") or []) if isinstance(d, dict)]
    signature = drift_signature(divergent, body)
    if not signature:
        return []
    aid = anomaly_id_for(signature)
    key = f"{SOURCE}:{aid}"
    mismatch = int(body.get("mismatch_count") or 0)
    sample = int(body.get("sample_size") or 0)
    ratio = body.get("ratio")
    impact = {"mismatch_count": mismatch, "sample_size": sample, "ratio": ratio, "signature": signature}
    lines = [
        f"mentions_drift_audit run_at={body.get('run_at')} signature={signature}",
        f"sample_size={sample} mismatch_count={mismatch} ratio={ratio} threshold={body.get('threshold')}",
        "First divergent records:",
    ]
    for d in divergent[:10]:
        lines.append(
            f"  {d.get('record_id')} ({d.get('record_type')}): "
            f"missing={sorted(d.get('missing') or [])[:5]} extra={sorted(d.get('extra') or [])[:5]}"
        )
    project = os.environ.get("MENTIONS_DRIFT_PROJECT", DEFAULT_PROJECT).strip() or DEFAULT_PROJECT
    return [{
        "source": SOURCE,
        "anomaly_id": aid,
        "project": project,
        "title": f"MENTIONS drift detected ({signature}) [{key}]",
        "evidence": [{
            "description": "\n".join(lines),
            "observed_by": "devops-deploy-parity-validator",
            "steps_to_duplicate": list(_STEPS),
            "source": SOURCE,
            "anomaly_id": aid,
            "source_key": key,
            "impact": impact,
        }],
        "impact": impact,
        "breakdown": [],
        "severity": "medium",
        "priority": "P2",
        "category": "bug",
        "raw_ref": None,
    }]
