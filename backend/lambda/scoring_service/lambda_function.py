"""scoring_service/lambda_function.py — Enceladus Scoring Service (B63 Phase 2B / ENC-TSK-H47)

Extracts lesson constitutional SCORING out of the tracker_mutation monolith into a standalone,
SNS-triggered ASYNC Lambda. This is the SECOND of two planned extractions under ENC-TSK-B63
(Phase 2 Gate); the first was the synchronous Lifecycle Service (ENC-TSK-H46). Where the Lifecycle
Service is a direct-invoke validator, the Scoring Service is a fire-and-forget consumer: it owns the
lesson scoring_status: pending -> scored lifecycle.

Flow (when enable_scoring_service_extraction is ON):
  1. tracker_mutation writes a lesson record with scoring_status='pending' and the validated
     pillar_scores, then publishes a {lesson.scoring.requested} message to the lesson-scoring SNS
     topic (skipping the inline pillar_composite / resonance_score computation).
  2. SNS asynchronously delivers the message to this Lambda (at-least-once).
  3. This service computes the constitutional scores (pillar_composite + resonance_score — the SAME
     pure functions previously inline in tracker_mutation, ENC-FTR-054) and writes them back to the
     lesson item, flipping scoring_status -> 'scored'.

Idempotency (SNS is at-least-once): the write-back is a CONDITIONAL UpdateItem gated on
scoring_status='pending'. A duplicate delivery (or a re-drive after a later pillar_scores update has
already re-scored) hits the condition guard and is treated as a no-op success — the score is never
double-applied and a newer score is never clobbered by a stale replay.

Environment variables:
  DYNAMODB_TABLE     default: devops-project-tracker  (lesson records are written here)
  DYNAMODB_REGION    default: us-west-2
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SCORING_SERVICE_VERSION = "1.0.0"  # ENC-TSK-H47

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")

_ddb_client = None


def _ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb_client


# ---------------------------------------------------------------------------
# Constitutional scoring — verbatim parity with tracker_mutation (ENC-FTR-054).
# Canonical source: coordination_api/lambda_function.py:7247-7350. These pure functions are the
# SOLE owner of lesson scoring once the flag is ON; tracker_mutation keeps a copy only for the
# flag-OFF rollback path (ENC-TSK-H47 AC #3). Keep in sync with both call sites.
# ---------------------------------------------------------------------------
_LESSON_PILLAR_WEIGHTS = {
    "efficiency": 0.25,
    "human_protection": 0.30,
    "intention": 0.20,
    "alignment": 0.25,
}

_VIBE_BOARD_ANCHORS = {
    "convergence": 0.12, "will": 0.10, "flow": 0.10, "play": 0.08,
    "surrender": 0.10, "force": 0.08, "balance": 0.12, "love": 0.10,
    "resonance": 0.12, "telemetry": 0.08,
}

_REQUIRED_PILLARS = {"efficiency", "human_protection", "intention", "alignment"}

# ---------------------------------------------------------------------------
# ENC-TSK-K43 (B66 Ph5) — F_governance percentile normalization.
# Math gate: DOC-A3D0CDF91CE9 Q3.1 ("Explicit F_governance Functional",
# ENRICHING -> CORRECTED). F_structural, F_temporal, and F_evidential are not
# directly summable (different units/scales); the corrected composite is a
# percentile-rank sum, bounded [0, 3] where 0 == perfect health across all
# three governance free-energy dimensions:
#
#   F_governance = percentile_rank(F_structural) + percentile_rank(F_temporal)
#                  + percentile_rank(F_evidential)
#
# F_governance = 0 is NOT achievable in practice (Q3.1 sub-question — each
# term is strictly >= 0 / > 0 for an active project), so this module treats
# LOW F_governance (near the achievable minimum) as high compliance and HIGH
# F_governance (near the theoretical max of 3.0) as low compliance, and folds
# that into the Scoring Service's existing resonance anti-pattern-penalty
# mechanism (_compute_resonance_score) as a governance compliance weighting
# term — not a parallel scoring path, per the task's integration contract.
# ---------------------------------------------------------------------------
F_GOVERNANCE_MAX = 3.0  # theoretical ceiling: percentile_rank in [0,1] per term, 3 terms.

# Multiplicative band the governance-compliance weight maps onto in
# _compute_resonance_score, symmetric around 1.0x at weight==0.5 (neutral) so
# a record with no historical distribution (percentile_rank's own neutral
# midpoint) reproduces the exact pre-K43 score. Mirrors the scale of the
# existing anti-pattern penalties immediately below (0.5x-0.8x) rather than a
# wider swing, so F_governance nudges ranking without a single low-compliance
# record ever dominating the vibe-board terms.
_GOVERNANCE_MIN_MULTIPLIER = 0.8   # weight == 0.0 (worst observed governance health)
_GOVERNANCE_MAX_MULTIPLIER = 1.2   # weight == 1.0 (perfect governance health, F_governance == 0)


def percentile_rank(value: float, distribution) -> float:
    """Fraction of ``distribution`` that is <= ``value``, in [0.0, 1.0].

    Pure order-statistic percentile rank (no interpolation) against a
    historical distribution — matches the Q3.1 gate's "percentile ranks
    computed against historical distributions across all project-phases"
    definition. An empty/falsy distribution degrades to the neutral midpoint
    (0.5) rather than raising, since a governance signal with no history yet
    (e.g. a brand-new project-phase) should neither help nor hurt ranking.
    """
    if not distribution:
        return 0.5
    values = sorted(float(v) for v in distribution)
    n = len(values)
    value = float(value)
    count_le = sum(1 for v in values if v <= value)
    return max(0.0, min(1.0, count_le / n))


def compute_f_governance(
    f_structural: float,
    f_temporal: float,
    f_evidential: float,
    *,
    structural_distribution=None,
    temporal_distribution=None,
    evidential_distribution=None,
) -> float:
    """DOC-A3D0CDF91CE9 Q3.1 corrected composite: sum of percentile ranks.

    Each raw F_* value is converted to a percentile rank against its own
    historical distribution (commensurability fix — the three free-energy
    terms have different units and are not directly summable), then summed.
    Bounded [0.0, 3.0]; 0.0 == perfect health on all three dimensions.
    """
    ps = percentile_rank(f_structural, structural_distribution)
    pt = percentile_rank(f_temporal, temporal_distribution)
    pe = percentile_rank(f_evidential, evidential_distribution)
    return round(ps + pt + pe, 4)


def governance_compliance_weight(f_governance: float) -> float:
    """Map F_governance in [0, F_GOVERNANCE_MAX] to a compliance weight in
    [0.0, 1.0], where 0.0 == worst-observed governance health and 1.0 ==
    perfect health (F_governance == 0, per Q3.1). Linear inverse mapping —
    simplest monotonic transform consistent with "lower F_governance is
    better" and adequate for a first-order compliance weighting term (no
    claim of a more elaborate curve; DOC-A3D0CDF91CE9 does not specify one).
    """
    clamped = max(0.0, min(F_GOVERNANCE_MAX, float(f_governance)))
    return round(1.0 - (clamped / F_GOVERNANCE_MAX), 4)


def _compute_lesson_pillar_composite(pillar_scores) -> float:
    """Weighted pillar composite: 0.25*eff + 0.30*hp + 0.20*int + 0.25*aln."""
    composite = 0.0
    for pillar, weight in _LESSON_PILLAR_WEIGHTS.items():
        composite += weight * max(0.0, min(1.0, float(pillar_scores.get(pillar, 0.0))))
    return round(composite, 4)


def _compute_resonance_score(pillar_scores, anchor_alignments=None, f_governance: Optional[float] = None) -> float:
    """Vibe board resonance with anti-pattern penalties. Returns [0.0, 1.0].

    ``f_governance`` (ENC-TSK-K43 / B66 Ph5, additive keyword-only so the
    verbatim-parity call sites in tracker_mutation / coordination_api that do
    not pass it are unaffected) is the optional DOC-A3D0CDF91CE9 Q3.1
    composite (percentile_rank(F_structural) + percentile_rank(F_temporal) +
    percentile_rank(F_evidential), bounded [0, 3], 0 == perfect governance
    health) for the record/project this score is being computed for. When
    supplied, it is converted via governance_compliance_weight into a
    multiplicative governance-compliance term applied the SAME way the
    existing anti-pattern checks below apply their penalties — a bounded
    multiplicative factor on ``raw`` — rather than a separate additive score
    or a parallel ranking path. Below-median compliance (weight < 0.5, i.e.
    F_governance above its own achievable-minimum band) dampens resonance;
    above-median compliance (weight > 0.5) gives a mild boost, symmetric
    around a neutral 1.0x at weight==0.5 (matches percentile_rank's own
    neutral-midpoint convention for an unseeded distribution).
    """
    if anchor_alignments:
        raw = sum(w * max(0.0, min(1.0, float(anchor_alignments.get(word, 0.0))))
                  for word, w in _VIBE_BOARD_ANCHORS.items())
    else:
        eff = float(pillar_scores.get("efficiency", 0.0))
        hp = float(pillar_scores.get("human_protection", 0.0))
        intent = float(pillar_scores.get("intention", 0.0))
        align = float(pillar_scores.get("alignment", 0.0))
        anchor_alignments = {
            "convergence": (eff + align) / 2, "will": intent,
            "flow": (eff + intent) / 2, "play": align * 0.8,
            "surrender": hp * 0.9, "force": eff * 0.7,
            "balance": (eff + hp + intent + align) / 4, "love": hp,
            "resonance": align, "telemetry": (intent + eff) / 2,
        }
        raw = sum(w * max(0.0, min(1.0, anchor_alignments.get(word, 0.0)))
                  for word, w in _VIBE_BOARD_ANCHORS.items())

    # Anti-pattern penalties
    if float(anchor_alignments.get("force", 0)) > 0.7 and float(anchor_alignments.get("surrender", 0)) < 0.3:
        raw *= 0.5
    if float(anchor_alignments.get("will", 0)) > 0.7 and float(anchor_alignments.get("flow", 0)) < 0.3:
        raw *= 0.7
    if float(pillar_scores.get("efficiency", 0)) > 0.8 and float(anchor_alignments.get("love", 0)) < 0.2:
        raw *= 0.6
    if float(anchor_alignments.get("convergence", 0)) > 0.8 and float(anchor_alignments.get("play", 0)) < 0.2:
        raw *= 0.8

    # ENC-TSK-K43: F_governance percentile-normalized compliance weighting.
    # weight in [0,1], 0.5 neutral -> multiplier in [GOVERNANCE_MIN_MULTIPLIER, GOVERNANCE_MAX_MULTIPLIER].
    if f_governance is not None:
        weight = governance_compliance_weight(f_governance)
        multiplier = (
            _GOVERNANCE_MIN_MULTIPLIER
            + (weight * (_GOVERNANCE_MAX_MULTIPLIER - _GOVERNANCE_MIN_MULTIPLIER))
        )
        raw *= multiplier

    return round(max(0.0, min(1.0, raw)), 4)


def _coerce_pillar_scores(raw) -> Optional[Dict[str, float]]:
    """Coerce the message's pillar_scores into a {pillar: float} dict, or None if unusable.

    The publisher (tracker_mutation) has already validated the scores at lesson-create time, so this
    is a defensive parse for the async boundary: all four pillars must be present and numeric."""
    if not isinstance(raw, dict):
        return None
    parsed: Dict[str, float] = {}
    for pillar in _REQUIRED_PILLARS:
        if pillar not in raw:
            return None
        try:
            parsed[pillar] = float(raw[pillar])
        except (TypeError, ValueError):
            return None
    return parsed


# ---------------------------------------------------------------------------
# DynamoDB write-back — idempotent scoring_status: pending -> scored.
# ---------------------------------------------------------------------------
def _apply_scores(project_id: str, record_id: str, pillar_composite: float, resonance_score: float) -> str:
    """Write the computed scores onto the lesson item and flip scoring_status -> 'scored'.

    Idempotent against SNS at-least-once delivery: the update is conditional on
    scoring_status='pending', so a duplicate or stale replay is a no-op. Returns one of
    'scored' | 'noop' | 'error' for caller logging."""
    now = _now_z()
    try:
        _ddb().update_item(
            TableName=DYNAMODB_TABLE,
            Key={"project_id": {"S": project_id}, "record_id": {"S": record_id}},
            UpdateExpression=(
                "SET pillar_composite = :pc, resonance_score = :rs, "
                "scoring_status = :scored, scoring_completed_at = :now"
            ),
            ConditionExpression=(
                "attribute_exists(record_id) AND scoring_status = :pending"
            ),
            ExpressionAttributeValues={
                ":pc": {"N": str(pillar_composite)},
                ":rs": {"N": str(resonance_score)},
                ":scored": {"S": "scored"},
                ":pending": {"S": "pending"},
                ":now": {"S": now},
            },
        )
        return "scored"
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Already scored (duplicate delivery), already re-scored by a newer write, or the item
            # is no longer pending. At-least-once delivery makes this an expected no-op, not a failure.
            logger.info(
                "[H47] %s not in scoring_status=pending (already scored or superseded); idempotent no-op",
                record_id,
            )
            return "noop"
        logger.error("[H47] scoring write-back failed for %s: %s", record_id, exc)
        return "error"


def _now_z() -> str:
    import datetime as dt
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Message handling
# ---------------------------------------------------------------------------
def score_lesson(message: dict) -> Tuple[str, dict]:
    """Score a single lesson from a decoded {lesson.scoring.requested} message.

    Returns (outcome, detail) where outcome is one of
    'scored' | 'noop' | 'skipped' | 'error' for handler-level aggregation."""
    project_id = (message.get("project_id") or "").strip()
    record_id = (message.get("record_id") or "").strip()
    if not project_id or not record_id:
        logger.error("[H47] message missing project_id/record_id; skipping: %r", message)
        return "skipped", {"outcome": "skipped", "reason": "missing_keys"}

    pillar_scores = _coerce_pillar_scores(message.get("pillar_scores"))
    if pillar_scores is None:
        logger.error("[H47] message for %s has missing/invalid pillar_scores; skipping", record_id)
        return "skipped", {"outcome": "skipped", "reason": "invalid_pillar_scores", "record_id": record_id}

    # ENC-TSK-K43 (B66 Ph5): optional F_governance composite carried on the
    # {lesson.scoring.requested} message (publisher-computed, e.g. by
    # tracker_mutation from the record's own F_structural/F_temporal/
    # F_evidential percentile ranks per DOC-A3D0CDF91CE9 Q3.1). Absent on
    # messages from a publisher that hasn't wired governance signals in yet —
    # _compute_resonance_score treats None as "no governance weighting term",
    # so this degrades to the pre-K43 score rather than erroring.
    f_governance = message.get("f_governance")
    if f_governance is not None:
        try:
            f_governance = float(f_governance)
        except (TypeError, ValueError):
            logger.warning("[K43] message for %s has non-numeric f_governance=%r; ignoring", record_id, f_governance)
            f_governance = None

    pillar_composite = _compute_lesson_pillar_composite(pillar_scores)
    resonance_score = _compute_resonance_score(pillar_scores, f_governance=f_governance)
    outcome = _apply_scores(project_id, record_id, pillar_composite, resonance_score)
    detail = {
        "record_id": record_id,
        "pillar_composite": pillar_composite,
        "resonance_score": resonance_score,
        "outcome": outcome,
    }
    if f_governance is not None:
        detail["f_governance"] = f_governance
    if outcome == "scored":
        logger.info(
            "[H47] scored %s pillar_composite=%s resonance_score=%s",
            record_id, pillar_composite, resonance_score,
        )
    return outcome, detail


def _decode_message(record: dict) -> Optional[dict]:
    """Extract and JSON-decode the SNS Message body from a Lambda SNS event record.

    Lambda-protocol SNS subscriptions cannot use raw message delivery (AWS rejects
    RawMessageDelivery=true for protocol=lambda), so the event arrives as an SNS Notification whose
    Message attribute is the JSON string the publisher passed to sns.publish(Message=...)."""
    sns_env = record.get("Sns") or record.get("sns")
    if not isinstance(sns_env, dict):
        return None
    raw = sns_env.get("Message", "")
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        logger.error("[H47] SNS Message is not valid JSON; skipping record")
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def lambda_handler(event, context):  # noqa: ANN001
    """SNS-triggered entrypoint. event = {"Records": [{"Sns": {"Message": "<json>"}}, ...]}.

    Processes every record best-effort: a single bad record never blocks the rest. A real write
    failure ('error') is collected and, if any occurred, re-raised at the end so Lambda's async
    retry / DLQ machinery can re-drive — the conditional write-back keeps that retry idempotent.
    Direct-invoke {"action": "health"} and a bare message dict are also accepted for probing.
    """
    # Health probe / direct-invoke convenience (gamma pre-probe per ENC-LSN-039).
    if isinstance(event, dict) and event.get("action") == "health":
        return {"ok": True, "service": "scoring_service", "version": SCORING_SERVICE_VERSION}

    records: List[dict] = []
    if isinstance(event, dict) and "Records" in event:
        records = event.get("Records") or []
    elif isinstance(event, dict) and event.get("event_type") == "lesson.scoring.requested":
        # Direct-invoke with a bare message (no SNS envelope) — useful for gamma functional probes.
        outcome, detail = score_lesson(event)
        return {"processed": 1, "results": [detail]}

    results: List[dict] = []
    errors = 0
    for record in records:
        message = _decode_message(record)
        if message is None:
            results.append({"outcome": "skipped", "reason": "undecodable"})
            continue
        outcome, detail = score_lesson(message)
        results.append(detail)
        if outcome == "error":
            errors += 1

    summary = {"processed": len(results), "errors": errors, "results": results}
    if errors:
        # Surface to Lambda's async retry/DLQ path. Idempotent write-back makes re-drive safe.
        raise RuntimeError(f"scoring_service: {errors} record(s) failed write-back: {json.dumps(summary)}")
    return summary
