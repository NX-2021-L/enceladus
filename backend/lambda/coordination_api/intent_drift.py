"""intent_drift.py — Wave-level intent-centroid drift telemetry (ENC-FTR-084 Phase 1, AC-3).

ENC-TSK-I93. Computes a rolling intent vector per coordination wave as the mean
of the Titan V2 embeddings (the FTR-089 raw-embedding egress) for the records
dispatched in that wave, derives a scalar `intent_centroid_drift` (cosine
distance between consecutive wave centroids), and best-effort persists that
scalar into the `enceladus-drift-telemetry` table ALONGSIDE the FTR-087
`d_centroid` field as a NEW, NULLABLE, BACKWARD-COMPATIBLE column.

Backward-compatibility contract:
  * The drift-telemetry table is owned by FTR-087 (Wave-Close Drift Telemetry),
    which is still `planned`. This module therefore NEVER creates the table and
    NEVER writes the FTR-087 `d_centroid` / `d_spectral` fields — it only SETs
    the new `intent_centroid_drift` column (plus a timestamp). When the table or
    env var is absent, persistence is a graceful no-op.
  * `intent_centroid_drift` is nullable: the first wave (no previous centroid)
    yields None, stored as a DynamoDB NULL, and readers must tolerate its
    absence on pre-existing rows.

Inference-only (AC-5): no training, no weight writes.
"""

from __future__ import annotations

import logging
import math
import os
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# Owned by FTR-087; empty default => persistence no-ops until the table is
# provisioned and the env var is set on the gamma stack.
DRIFT_TELEMETRY_TABLE = os.environ.get("DRIFT_TELEMETRY_TABLE", "").strip()
DRIFT_TELEMETRY_WAVE_KEY = os.environ.get("DRIFT_TELEMETRY_WAVE_KEY", "wave_id").strip() or "wave_id"

# New nullable columns this task contributes (never overwrites FTR-087 fields).
INTENT_CENTROID_DRIFT_ATTR = "intent_centroid_drift"
INTENT_CENTROID_DRIFT_TS_ATTR = "intent_centroid_drift_updated_at"


def compute_intent_centroid(
    embeddings: Sequence[Sequence[float]],
) -> Optional[List[float]]:
    """Rolling intent vector for a wave = element-wise mean of the embeddings.

    Returns the mean vector, or None when there are no usable embeddings.
    Embeddings of inconsistent dimensionality are skipped defensively (the
    dimension of the first valid embedding sets the expected width).
    """
    if not embeddings:
        return None
    accum: Optional[List[float]] = None
    dim = 0
    count = 0
    for emb in embeddings:
        if not isinstance(emb, (list, tuple)) or not emb:
            continue
        if accum is None:
            dim = len(emb)
            accum = [0.0] * dim
        if len(emb) != dim:
            continue
        for i in range(dim):
            try:
                accum[i] += float(emb[i])
            except (TypeError, ValueError):
                accum = None
                break
        if accum is None:
            return None
        count += 1
    if accum is None or count == 0:
        return None
    return [v / count for v in accum]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = na = nb = 0.0
    for x, y in zip(a, b):
        xf = float(x)
        yf = float(y)
        dot += xf * yf
        na += xf * xf
        nb += yf * yf
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def compute_intent_centroid_drift(
    previous_centroid: Optional[Sequence[float]],
    current_centroid: Optional[Sequence[float]],
) -> Optional[float]:
    """Cosine distance (1 - cosine similarity) between consecutive wave centroids.

    Returns None when either centroid is missing (e.g. the first wave) — the
    nullable, backward-compatible contract. Result is clamped to [0.0, 2.0].
    """
    if not previous_centroid or not current_centroid:
        return None
    if len(previous_centroid) != len(current_centroid):
        return None
    drift = 1.0 - _cosine(previous_centroid, current_centroid)
    if drift < 0.0:
        return 0.0
    if drift > 2.0:
        return 2.0
    return drift


def persist_intent_centroid_drift(
    wave_id: str,
    intent_centroid_drift: Optional[float],
    *,
    now_iso: str,
    table_name: Optional[str] = None,
    ddb: Any = None,
) -> Dict[str, Any]:
    """Best-effort write of the new nullable `intent_centroid_drift` column.

    SETs only the new column (+ timestamp) on the wave's drift-telemetry item via
    update_item, leaving any FTR-087 `d_centroid` / `d_spectral` attributes
    untouched. Returns a status dict and NEVER raises: a missing table, missing
    env var, key-schema mismatch, or access error degrades to
    {"persisted": False, "reason": ...}.
    """
    table = (table_name or DRIFT_TELEMETRY_TABLE).strip()
    if not table:
        return {"persisted": False, "reason": "drift_telemetry_table_not_configured"}
    wid = str(wave_id or "").strip()
    if not wid:
        return {"persisted": False, "reason": "missing_wave_id"}

    if intent_centroid_drift is None:
        drift_value: Dict[str, Any] = {"NULL": True}
    else:
        drift_value = {"N": repr(float(intent_centroid_drift))}

    try:
        if ddb is None:
            from aws_clients import _get_ddb  # local import: keep module import-light

            ddb = _get_ddb()
        ddb.update_item(
            TableName=table,
            Key={DRIFT_TELEMETRY_WAVE_KEY: {"S": wid}},
            UpdateExpression="SET #d = :d, #t = :t",
            ExpressionAttributeNames={
                "#d": INTENT_CENTROID_DRIFT_ATTR,
                "#t": INTENT_CENTROID_DRIFT_TS_ATTR,
            },
            ExpressionAttributeValues={":d": drift_value, ":t": {"S": str(now_iso)}},
        )
        return {
            "persisted": True,
            "table": table,
            "wave_id": wid,
            "intent_centroid_drift": intent_centroid_drift,
        }
    except Exception as exc:  # noqa: BLE001 — telemetry is best-effort, never fatal
        logger.warning(
            "intent_drift: best-effort persist of intent_centroid_drift skipped "
            "(table=%s wave=%s): %s",
            table,
            wid,
            exc,
        )
        return {"persisted": False, "reason": "persist_failed", "error": str(exc)[:300]}
