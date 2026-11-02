"""Reference/stub second adapter (ENC-TSK-R82-0D, ENC-FTR-150 AC-8 proof).

Not registered in the default REGISTRY (production intake stays aws-cad only). It exists to
prove a new source plugs in with zero change to the primitive, and as the template the MENTIONS
drift adapter (ENC-FTR-150 AC-9) copies. Input body:

    {"signals": [{"id": "<stable signature>", "title": "...", "magnitude": 3, "project": "devops"}]}

Select it with ANOMALY_SOURCE=stub after ``REGISTRY.register(stub_adapter)``.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "stub"
DEFAULT_PROJECT = "devops"


def parse(message: str) -> List[Dict[str, Any]]:
    try:
        body = json.loads(message)
    except (TypeError, ValueError):
        return []
    signals = body.get("signals") if isinstance(body, dict) else None
    out: List[Dict[str, Any]] = []
    for sig in signals or []:
        if not isinstance(sig, dict):
            continue
        sig_id = str(sig.get("id") or "").strip()
        if not sig_id:
            continue
        magnitude = sig.get("magnitude")
        impact = {"magnitude": magnitude}
        project = str(sig.get("project") or os.environ.get("ANOMALY_DEFAULT_PROJECT", DEFAULT_PROJECT)).strip() or DEFAULT_PROJECT
        out.append({
            "source": SOURCE,
            "anomaly_id": sig_id,
            "project": project,
            "title": f"[stub] {sig.get('title') or sig_id} [{SOURCE}:{sig_id}]",
            "evidence": [{
                "description": f"stub signal {sig_id} magnitude={magnitude}",
                "observed_by": "sns-anomaly-responder",
                "steps_to_duplicate": [f"Re-run the stub detector for signal {sig_id}"],
                "source": SOURCE,
                "anomaly_id": sig_id,
                "source_key": f"{SOURCE}:{sig_id}",
                "impact": impact,
            }],
            "impact": impact,
            "breakdown": [],
            "severity": "low",
            "priority": "P3",
            "category": "risk",
            "raw_ref": None,
        })
    return out
