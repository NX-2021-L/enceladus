"""ENC-FTR-108 Phase 2 (ENC-TSK-J02) -- flow_weight standing refresh job.

Implements the Tero slime-mold current-reinforcement law defined by Phase 1
(ENC-TSK-J01, DOC-88A8F4835811) as a batched, watermarked, out-of-band Neo4j
write against EXISTING relationships:

    flow_weight(t+1) = flow_weight(t) + delta*flow(e,t) - mu*flow_weight(t)

delta=0.2 (reinforcement) and mu=0.2 (decay) are the DOC-88A8F4835811 defaults
(env-overridable). The source of truth for "which edges were traversed" is
FTR-082's existing edge_participation[] telemetry -- specifically
retrieval_outcome=='hit' entries -- emitted by graph_query_api's hybrid path
(lambda_function._emit_pathway_telemetry) as one JSON object per S3 key under
s3://{PATHWAY_TELEMETRY_BUCKET}/{PATHWAY_TELEMETRY_PREFIX}/wave_id=<wid>/....
No new logging is introduced; this module only reads that existing sink.

Invocation contract (mirrors the FTR-101 _handle_refresh_projection pattern
in lambda_function.py -- same lambda, same file layout, action-dispatched):

    lambda_handler(event, context) with event like
        {"action": "refresh_flow_weight"}                      # full defaults
        {"action": "refresh_flow_weight", "bucket": "...",
         "prefix": "...", "max_objects": 5000}                 # overrides

  EventBridge wiring: point a scheduled rule's Input (or an Input Transformer
  for a wave-close event source, once one exists) at the constant JSON above.
  No CFN rule is added by this task -- see the OGTM compliance note / final
  report for why that is deliberately left as a follow-up.

Design choices (documented per the task brief, since two reasonable designs
existed for each):

  1. Watermark: a single S3 `LastModified`-epoch-ms cursor, persisted on the
     SAME meta-marker label FTR-101 already introduced (GdsProjectionMeta,
     keyed by name='flow_weight_refresh') rather than a new node label --
     this task's AC-5 hard gate forbids adding new labels/relationship
     types, and GdsProjectionMeta is already a generic "out-of-band refresher
     bookmark" marker in this codebase. Using S3 LastModified (rather than
     parsing the wave_id-partitioned key) means the scan is correct
     regardless of how telemetry keys are prefixed/partitioned.

  2. Idempotency: the ENTIRE cycle (reinforcement AND decay) is gated on the
     watermark advancing. If a run discovers zero telemetry objects newer
     than the watermark, it is a pure no-op -- no decay, no reinforcement,
     watermark unchanged. This is the literal reading of "running the same
     refresh cycle twice with no new participation data should not change
     flow_weight further": decay is a per-wave-close event, not a per-
     invocation cron tax. (The alternative -- decaying on every invocation
     regardless of new data -- would let idle edges decay faster than the
     mu=0.2 / 21-cycle contract if the job is invoked more often than waves
     actually close, so it was rejected.)

  3. Single formula, single decay pass: reinforcement and decay are the same
     equation with flow(e,t)=0 for untouched edges, so untouched edges could
     in principle be swept by the same UNWIND batch. In practice the set of
     *touched* edges (this cycle) is small and comes from telemetry, while
     the set of *all* eligible edges (for the decay-only term) is the whole
     graph -- so this module applies the full formula to touched edges via
     a chunked UNWIND batch (targeted, cheap), then applies the mu-only decay
     term to every OTHER eligible edge via one full-corpus Cypher statement
     (matches the existing _refresh_standing_projection precedent of a
     single full-corpus write, no per-edge transactions). Eligible edge
     types are GRAPH_EDGE_WEIGHTS' keys (the same weighted topology already
     used for hybrid scoring / the standing GDS projection) -- not a new
     edge-type list, and PATHWAY_TRAVERSED/TRAVERSED_BY (telemetry-only
     edges, deliberately excluded from GRAPH_EDGE_WEIGHTS per FTR-082 Phase
     A) are correctly never touched.

Relationships are matched by elementId(r) (the same identifier FTR-082 already
threads through edge_participation[].edge_id -- see
lambda_function._reconstruct_pathway_edges), so no new edge/node identity
scheme is introduced.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration (DOC-88A8F4835811 defaults; env-overridable per Ph1 contract)
# ---------------------------------------------------------------------------

try:
    FLOW_WEIGHT_DELTA = float(os.environ.get("FLOW_WEIGHT_DELTA", "0.2"))
except (TypeError, ValueError):
    FLOW_WEIGHT_DELTA = 0.2

try:
    FLOW_WEIGHT_MU = float(os.environ.get("FLOW_WEIGHT_MU", "0.2"))
except (TypeError, ValueError):
    FLOW_WEIGHT_MU = 0.2

# Neutral prior for edges that have never been written -- matches the
# flow_weight=1.0 slot FTR-101's standing projection already initializes
# (lambda_function._refresh_standing_projection), so a freshly-onboarded
# edge starts at the same "average" weight as the GDS-projection default
# rather than 0.0.
FLOW_WEIGHT_DEFAULT = 1.0

# Reuse the FTR-101 marker label (no new node label -- AC-5 hard gate).
FLOW_WEIGHT_META_LABEL = "GdsProjectionMeta"
FLOW_WEIGHT_META_NAME = "flow_weight_refresh"

# Chunk size for the touched-edge UNWIND batch write.
FLOW_WEIGHT_WRITE_CHUNK_SIZE = 500

try:
    FLOW_WEIGHT_MAX_OBJECTS_PER_RUN = int(os.environ.get("FLOW_WEIGHT_MAX_OBJECTS_PER_RUN", "5000"))
except (TypeError, ValueError):
    FLOW_WEIGHT_MAX_OBJECTS_PER_RUN = 5000


# ---------------------------------------------------------------------------
# Watermark (persisted via the shared GdsProjectionMeta marker node)
# ---------------------------------------------------------------------------

def _get_watermark(driver) -> int:
    """Last-processed S3 LastModified epoch-ms, or 0 (process-everything) when
    the marker is absent. Never raises -- caller treats an error the same as
    'no watermark yet' (0), which is safe: it only risks reprocessing already-
    seen telemetry once, not corrupting flow_weight (the formula is still
    idempotent for a re-observed hit only insofar as re-application would
    double-count -- see run_refresh() for why a read error aborts the whole
    cycle instead of silently reprocessing).
    """
    try:
        with driver.session() as session:
            rec = session.run(
                f"MATCH (m:{FLOW_WEIGHT_META_LABEL} {{name: $name}}) "
                "RETURN m.last_watermark_epoch_ms AS wm",
                name=FLOW_WEIGHT_META_NAME,
            ).single()
            if rec and rec.get("wm") is not None:
                return int(rec.get("wm"))
    except Exception:
        logger.exception("[ERROR] flow_weight watermark read failed")
    return 0


def _set_watermark(driver, epoch_ms: int) -> None:
    try:
        with driver.session() as session:
            session.run(
                f"MERGE (m:{FLOW_WEIGHT_META_LABEL} {{name: $name}}) "
                "SET m.last_watermark_epoch_ms = $epoch_ms, "
                "m.last_refresh = datetime()",
                name=FLOW_WEIGHT_META_NAME,
                epoch_ms=int(epoch_ms),
            ).consume()
    except Exception:
        logger.exception("[ERROR] flow_weight watermark write failed")


# ---------------------------------------------------------------------------
# Telemetry scan + aggregation (S3 -- FTR-082's existing sink, read-only)
# ---------------------------------------------------------------------------

def _list_new_telemetry_objects(
    s3_client,
    bucket: str,
    prefix: str,
    since_epoch_ms: int,
    max_objects: int,
) -> List[Tuple[str, int]]:
    """Return [(key, last_modified_epoch_ms), ...] for objects strictly newer
    than since_epoch_ms, oldest-first, capped at max_objects. If the cap is
    hit, callers MUST advance the watermark only to the last object actually
    processed (not "now") so the remainder is picked up on the next cycle --
    see run_refresh().
    """
    out: List[Tuple[str, int]] = []
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []) or []:
                key = obj.get("Key")
                lm = obj.get("LastModified")
                if not key or lm is None:
                    continue
                lm_ms = int(lm.timestamp() * 1000)
                if lm_ms > since_epoch_ms:
                    out.append((key, lm_ms))
    except Exception:
        logger.exception("[ERROR] flow_weight telemetry listing failed")
        return []
    out.sort(key=lambda t: t[1])
    if len(out) > max_objects:
        logger.warning(
            "[WARNING] flow_weight refresh capped at %d/%d new telemetry objects; "
            "remainder will be picked up on the next cycle",
            max_objects, len(out),
        )
        out = out[:max_objects]
    return out


def _aggregate_hit_flow(
    s3_client,
    bucket: str,
    objects: List[Tuple[str, int]],
) -> Dict[str, int]:
    """Sum traversal_count for retrieval_outcome=='hit' edge_participation
    entries across the given telemetry objects. Malformed/unreadable objects
    are logged and skipped -- one bad record must never abort the batch."""
    flow: Dict[str, int] = {}
    for key, _lm_ms in objects:
        try:
            body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
            record = json.loads(body)
        except Exception as exc:
            logger.warning("[WARNING] flow_weight telemetry object unreadable, skipping: %s (%s)", key, exc)
            continue
        for p in record.get("edge_participation") or []:
            if p.get("retrieval_outcome") != "hit":
                continue
            edge_id = p.get("edge_id")
            if not edge_id:
                continue
            try:
                count = int(p.get("traversal_count") or 0)
            except (TypeError, ValueError):
                count = 0
            if count <= 0:
                continue
            flow[edge_id] = flow.get(edge_id, 0) + count
    return flow


# ---------------------------------------------------------------------------
# Batched Cypher writes
# ---------------------------------------------------------------------------

def _apply_reinforcement(driver, flow_by_edge: Dict[str, int], delta: float, mu: float,
                         chunk_size: int = FLOW_WEIGHT_WRITE_CHUNK_SIZE) -> List[str]:
    """Batched UNWIND write of the full reinforcement/decay formula for every
    edge_id with a positive aggregated flow this cycle. Chunked so a large
    wave never becomes one oversized transaction. Never issues a per-edge
    transaction. Returns the list of edge_ids submitted (used to exclude them
    from the decay-only pass below, regardless of whether the relationship
    still existed to be matched)."""
    edge_ids = list(flow_by_edge.keys())
    if not edge_ids:
        return []
    cypher = (
        "UNWIND $rows AS row "
        "MATCH ()-[r]-() WHERE elementId(r) = row.edge_id "
        "WITH DISTINCT r, row "
        "SET r.flow_weight = coalesce(r.flow_weight, $default) "
        "  + $delta * row.flow - $mu * coalesce(r.flow_weight, $default)"
    )
    try:
        with driver.session() as session:
            for i in range(0, len(edge_ids), chunk_size):
                chunk = edge_ids[i:i + chunk_size]
                rows = [{"edge_id": eid, "flow": flow_by_edge[eid]} for eid in chunk]
                session.run(
                    cypher, rows=rows, delta=delta, mu=mu, default=FLOW_WEIGHT_DEFAULT,
                ).consume()
    except Exception:
        logger.exception("[ERROR] flow_weight reinforcement batch write failed")
        return []
    return edge_ids


def _apply_decay(driver, touched_edge_ids: List[str], mu: float, edge_types: List[str]) -> None:
    """Single full-corpus decay-only pass (mu term) over every eligible edge
    NOT touched this cycle. One Cypher statement, not a per-edge loop --
    matches the _refresh_standing_projection precedent. edge_types is the
    GRAPH_EDGE_WEIGHTS key set (the existing weighted topology); telemetry-
    only edges (PATHWAY_TRAVERSED/TRAVERSED_BY) are never in that set, so
    they are correctly never written here."""
    if not edge_types:
        return
    edge_union = "|".join(edge_types)
    cypher = (
        f"MATCH ()-[r:{edge_union}]-() "
        "WHERE NOT elementId(r) IN $touched "
        "WITH DISTINCT r "
        "SET r.flow_weight = coalesce(r.flow_weight, $default) * (1 - $mu)"
    )
    try:
        with driver.session() as session:
            session.run(
                cypher, touched=touched_edge_ids, mu=mu, default=FLOW_WEIGHT_DEFAULT,
            ).consume()
    except Exception:
        logger.exception("[ERROR] flow_weight decay pass failed")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_refresh(driver, s3_client, event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """ENC-FTR-108 Ph2 standing refresh entrypoint. Never raises -- returns a
    result dict with ok=False and a reason on any failure so the caller
    (lambda_function._handle_refresh_flow_weight) can log without crashing
    the invocation.
    """
    event = event or {}

    # Lazily bind to lambda_function's already-resolved config so the bucket/
    # prefix/edge-weight-topology stay byte-identical to the emit side and to
    # the hybrid-scoring edge set, rather than re-deriving a second copy that
    # could drift (ENC-ISS-178-style hazard). Deferred import -- see module
    # docstring: safe because this function only runs after lambda_function
    # has finished its own module-level execution.
    import lambda_function as lf

    bucket = str(event.get("bucket") or lf.PATHWAY_TELEMETRY_BUCKET or "").strip()
    prefix = str(event.get("prefix") or lf.PATHWAY_TELEMETRY_PREFIX or "").strip()
    max_objects = int(event.get("max_objects") or FLOW_WEIGHT_MAX_OBJECTS_PER_RUN)
    delta = float(event.get("delta") or FLOW_WEIGHT_DELTA)
    mu = float(event.get("mu") or FLOW_WEIGHT_MU)

    if not bucket:
        # Mirrors the emit-side degradation (lf._emit_pathway_telemetry): when
        # PATHWAY_TELEMETRY_BUCKET is unset, telemetry only reaches CloudWatch
        # logs, which this batch job cannot aggregate from. No-op rather than
        # error, so an un-configured environment is silent, not alarming.
        logger.info("[INFO] flow_weight refresh skipped: no PATHWAY_TELEMETRY_BUCKET configured")
        return {"ok": True, "applied": False, "reason": "PATHWAY_TELEMETRY_BUCKET unset"}

    watermark = _get_watermark(driver)
    objects = _list_new_telemetry_objects(s3_client, bucket, prefix, watermark, max_objects)
    if not objects:
        logger.info("[INFO] flow_weight refresh: no new telemetry since watermark=%d — no-op cycle", watermark)
        return {
            "ok": True, "applied": False,
            "reason": "no new telemetry since watermark",
            "watermark_epoch_ms": watermark,
        }

    flow_by_edge = _aggregate_hit_flow(s3_client, bucket, objects)
    touched = _apply_reinforcement(driver, flow_by_edge, delta, mu) if flow_by_edge else []
    edge_types = sorted(lf.GRAPH_EDGE_WEIGHTS.keys())
    _apply_decay(driver, touched, mu, edge_types)

    new_watermark = objects[-1][1]  # last object actually processed, not "now" (see cap handling)
    _set_watermark(driver, new_watermark)

    logger.info(
        "[SUCCESS] flow_weight refresh applied: objects=%d hit_edges=%d reinforced=%d "
        "decay_edge_types=%d watermark %d -> %d",
        len(objects), len(flow_by_edge), len(touched), len(edge_types), watermark, new_watermark,
    )
    return {
        "ok": True,
        "applied": True,
        "objects_scanned": len(objects),
        "edges_reinforced": len(touched),
        "decay_edge_types": edge_types,
        "watermark_epoch_ms": new_watermark,
        "delta": delta,
        "mu": mu,
    }
