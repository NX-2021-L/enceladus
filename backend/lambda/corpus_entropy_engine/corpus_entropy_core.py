"""corpus_entropy_core — pure-function detection logic for the Corpus Entropy
Engine (CEE) Lambda. ENC-TSK-K41 / B66 Phase-5, per DOC-A3D0CDF91CE9.

Five telemetry-only entropy detectors, each a pure function over already-fetched
governed records (no AWS/HTTP calls in this module — those live in
lambda_function.py so this module stays network-free and unit-testable):

  (a) Lineage-unanchored entropy — tracker records with no parent/plan linkage
      (CloudWatch Category=lineage_unanchored; not Neo4j zero-degree isolation).
  (b) Stagnation Entropy   — open tasks with no worklog entry above threshold.
  (c) Relational Entropy   — declared relational field with no corresponding
                              graph edge.
  (d) Retention Entropy    — Lessons with FSRS-6 stability S < T3 (0.7).
  (e) Compliance/Semantic  — documents with compliance_score below threshold
                              AND maturity_state == "raw".

OGTM: read-only detection. No corpus mutation, no new edge types. GDMP Stage-1
auto-remediation is a separate task (do NOT build remediation here).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# FSRS-6 retrieval-invisible threshold (T3), matching the canonical convention
# already established in graph_query_api/lambda_function.py for Lesson records.
FSRS_T3_THRESHOLD = 0.7

# Relation-id fields that, when declared non-empty on a tracker record, are
# expected to have a corresponding graph edge (tracker_mutation's
# _RELATION_ID_FIELDS convention).
RELATION_ID_FIELDS = ("related_task_ids", "related_issue_ids", "related_feature_ids")

# Document maturity states considered "raw" for the Compliance/Semantic detector.
RAW_MATURITY_STATE = "raw"

DEFAULT_COMPLIANCE_SCORE_THRESHOLD = 70
DEFAULT_STAGNATION_DAYS = 14


# ---------------------------------------------------------------------------
# (a) Lineage-unanchored entropy — no parent/plan linkage in tracker fields
# ---------------------------------------------------------------------------

def detect_orphan_entropy(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag tracker records lacking parent/plan lineage anchors.

    Emitted as EntropyFindingCount Category=lineage_unanchored (ENC-ISS-555).
    This is NOT the GraphHealth IsolatedNodeRatio (Neo4j nodes with zero edges).

    A task/issue/feature is unanchored if it has no `parent_task_id` AND no
    non-empty `related_task_ids`. A wave document is unanchored if it has no
    `plan_anchor_id`. Top-level plans are excluded (no parent by definition).
    """
    findings: List[Dict[str, Any]] = []
    for rec in records:
        record_id = rec.get("record_id") or rec.get("item_id") or ""
        record_type = str(rec.get("record_type") or "").lower()

        if record_type == "plan":
            continue

        if record_type in ("task", "issue", "feature"):
            parent_task_id = rec.get("parent_task_id")
            related = rec.get("related_task_ids") or []
            if not parent_task_id and not related:
                findings.append({
                    "record_id": record_id,
                    "record_type": record_type,
                    "reason": "no_parent_task_id_and_no_related_task_ids",
                })
        elif record_type == "document":
            subtype = str(rec.get("document_subtype") or "").lower()
            if subtype == "wave" and not rec.get("plan_anchor_id"):
                findings.append({
                    "record_id": record_id,
                    "record_type": record_type,
                    "reason": "wave_document_missing_plan_anchor_id",
                })
    return findings


# ---------------------------------------------------------------------------
# (b) Stagnation Entropy — open tasks with no worklog above threshold
# ---------------------------------------------------------------------------

def _last_worklog_timestamp(history: Iterable[Dict[str, Any]]) -> Optional[str]:
    last: Optional[str] = None
    for entry in history or []:
        if str(entry.get("status") or "") == "worklog":
            ts = entry.get("timestamp")
            if ts and (last is None or ts > last):
                last = ts
    return last


def detect_stagnation_entropy(
    records: Iterable[Dict[str, Any]],
    *,
    now_iso: str,
    threshold_days: int = DEFAULT_STAGNATION_DAYS,
) -> List[Dict[str, Any]]:
    """Flag open tasks with no worklog entry newer than `threshold_days`.

    A task with zero worklog entries in `history` at all is flagged using its
    `created_at` as the reference point (never touched since creation). A task
    whose only history is the checkout/creation events but nothing recent also
    qualifies once the newest worklog timestamp is older than the threshold.
    """
    findings: List[Dict[str, Any]] = []
    for rec in records:
        record_type = str(rec.get("record_type") or "").lower()
        status = str(rec.get("status") or "").lower()
        if record_type != "task" or status in ("closed", "merged-main"):
            continue

        record_id = rec.get("record_id") or rec.get("item_id") or ""
        history = rec.get("history") or []
        last_worklog = _last_worklog_timestamp(history)
        reference_ts = last_worklog or rec.get("created_at")
        if not reference_ts:
            continue

        age_days = _days_between(reference_ts, now_iso)
        if age_days is not None and age_days > threshold_days:
            findings.append({
                "record_id": record_id,
                "record_type": record_type,
                "reason": "no_worklog_within_threshold" if last_worklog else "no_worklog_ever",
                "last_worklog_at": last_worklog,
                "age_days": age_days,
            })
    return findings


def _days_between(iso_earlier: str, iso_now: str) -> Optional[float]:
    from datetime import datetime

    def _parse(s: str):
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)

    try:
        earlier = _parse(iso_earlier)
        now = _parse(iso_now)
    except (ValueError, TypeError):
        return None
    delta = now - earlier
    return delta.total_seconds() / 86400.0


# ---------------------------------------------------------------------------
# (c) Relational Entropy — declared relational field, no graph edge
# ---------------------------------------------------------------------------

def detect_relational_entropy(
    records: Iterable[Dict[str, Any]],
    edge_pairs: Iterable[Any],
) -> List[Dict[str, Any]]:
    """Flag declared relational-field targets with no corresponding graph edge.

    `edge_pairs` is an iterable of (source, target) tuples/lists sourced from
    graph_query_api's adjacency export (read-only; this detector introduces no
    new edge types — it only compares declared fields against what already
    exists). Edges are treated as undirected for membership purposes.
    """
    edge_set = set()
    for pair in edge_pairs:
        s, t = pair[0], pair[1]
        edge_set.add((s, t))
        edge_set.add((t, s))

    findings: List[Dict[str, Any]] = []
    for rec in records:
        record_id = rec.get("record_id") or rec.get("item_id") or ""
        for field in RELATION_ID_FIELDS:
            targets = rec.get(field) or []
            for target_id in targets:
                if (record_id, target_id) not in edge_set:
                    findings.append({
                        "record_id": record_id,
                        "field": field,
                        "declared_target_id": target_id,
                        "reason": "declared_relation_missing_graph_edge",
                    })
    return findings


# ---------------------------------------------------------------------------
# (d) Retention Entropy — Lessons with FSRS-6 stability S < T3 (0.7)
# ---------------------------------------------------------------------------

def detect_retention_entropy(
    lessons: Iterable[Dict[str, Any]],
    *,
    threshold: float = FSRS_T3_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Flag Lesson records whose FSRS-6 stability is below T3.

    Canonical field is `stability`; falls back to `resonance_score` for
    pre-FSRS-6 lesson records absent a `stability` value, matching the
    graph_query_api._apply_fsrs_t3_filter precedence convention.
    """
    findings: List[Dict[str, Any]] = []
    for rec in lessons:
        record_id = rec.get("record_id") or rec.get("item_id") or ""
        stability = rec.get("stability")
        source_field = "stability"
        if stability is None:
            stability = rec.get("resonance_score")
            source_field = "resonance_score"
        if stability is None:
            continue
        try:
            stability = float(stability)
        except (TypeError, ValueError):
            continue
        if stability < threshold:
            findings.append({
                "record_id": record_id,
                "stability": stability,
                "source_field": source_field,
                "threshold": threshold,
                "reason": "fsrs6_stability_below_t3",
            })
    return findings


# ---------------------------------------------------------------------------
# (e) Compliance/Semantic Entropy — compliance_score below threshold AND
#     maturity_state == raw
# ---------------------------------------------------------------------------

def detect_compliance_semantic_entropy(
    documents: Iterable[Dict[str, Any]],
    *,
    score_threshold: int = DEFAULT_COMPLIANCE_SCORE_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Flag documents with compliance_score below threshold AND maturity raw.

    Field names per document_api's DynamoDB schema: `compliance_score`
    (numeric) and `document_maturity_state` (string enum including "raw").
    """
    findings: List[Dict[str, Any]] = []
    for rec in documents:
        record_id = rec.get("record_id") or rec.get("document_id") or rec.get("item_id") or ""
        maturity = str(
            rec.get("document_maturity_state") or rec.get("maturity_state") or ""
        ).lower()
        score = rec.get("compliance_score")
        if score is None or maturity != RAW_MATURITY_STATE:
            continue
        try:
            score = float(score)
        except (TypeError, ValueError):
            continue
        if score < score_threshold:
            findings.append({
                "record_id": record_id,
                "compliance_score": score,
                "maturity_state": maturity,
                "threshold": score_threshold,
                "reason": "compliance_score_below_threshold_and_raw",
            })
    return findings


# ---------------------------------------------------------------------------
# Kill switch (ISS-465 cost-preflight companion)
# ---------------------------------------------------------------------------

def is_hard_disabled(env: Dict[str, str]) -> bool:
    """CEE_HARD_DISABLED kill switch — mandatory before first scheduled run.

    Any of "1"/"true"/"yes" (case-insensitive) disables the run. Absent or any
    other value means enabled. Mirrors the UNLEARNING_*/TRAINING_HARD_DISABLED
    convention already used by sibling gamma-only cost-gated Lambdas (K02/K03).
    """
    val = str(env.get("CEE_HARD_DISABLED", "0")).strip().lower()
    return val in ("1", "true", "yes")


def build_category_metric_data(
    counts: Dict[str, int],
    *,
    function_name: str,
    timestamp,
) -> List[Dict[str, Any]]:
    """Build CloudWatch put_metric_data MetricData entries, one per category,
    each dimensioned by FunctionName + Category. Caller batches <=20 per call.
    """
    metric_data = []
    for category, count in counts.items():
        metric_data.append({
            "MetricName": "EntropyFindingCount",
            "Value": float(count),
            "Unit": "Count",
            "Timestamp": timestamp,
            "Dimensions": [
                {"Name": "FunctionName", "Value": function_name},
                {"Name": "Category", "Value": category},
            ],
        })
    return metric_data


def build_scan_duration_metric_data(
    duration_ms: float,
    *,
    function_name: str,
    timestamp,
) -> Dict[str, Any]:
    """Single ScanDurationMs datapoint for cost/perf profiling (ENC-TSK-N49)."""
    return {
        "MetricName": "ScanDurationMs",
        "Value": float(duration_ms),
        "Unit": "Milliseconds",
        "Timestamp": timestamp,
        "Dimensions": [
            {"Name": "FunctionName", "Value": function_name},
        ],
    }
