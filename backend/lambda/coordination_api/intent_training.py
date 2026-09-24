"""intent_training.py — FTR-084 Ph2 intent-classifier training loop (ENC-TSK-K02).

Per-invocation EventBridge-triggered weight mutation for the session-init intent
classifier. Training updates per-record score boosts (multiplicative on nearest-
neighbor ranks) from labeled session outcomes stored on S3.

COST-PREFLIGHT (blocking AC, pre-merge):
  Cadence: weekly EventBridge cron (4 runs/month).
  Per run (gamma): coordination_api Lambda 512MB × ≤120s + ≤100 Titan embed
  calls for holdout evaluation ≈ $0.01/run.
  Weight storage: S3 JSON snapshots under intent-training/weights/ (<1 MB) ≈ $0.00.
  Projected monthly total: ~$0.04 (Lambda + Bedrock + S3).
  Headroom alarm: IntentTrainingMonthlyCostAlarm at $5 USD (50× projected).
  Kill switch: TRAINING_HARD_DISABLED=1 (default ON) — must be cleared by io
  before any mutation runs; installed at deploy, not after first invoice.

Rollback: invoke coordination_api with
  {"action": "intent_classifier_training_rollback"}
or pass {"version_id": "<prior>"} to pin a specific snapshot.

No new Neo4j edge types; boosts are opaque scoring-path state only.
"""

from __future__ import annotations

import json
import logging
import os
import random
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# ISS-465 pattern: default hard-disabled until io explicitly enables training.
TRAINING_HARD_DISABLED = os.environ.get("TRAINING_HARD_DISABLED", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

INTENT_TRAINING_BUCKET = os.environ.get("INTENT_TRAINING_BUCKET", "").strip()
INTENT_TRAINING_PREFIX = os.environ.get(
    "INTENT_TRAINING_PREFIX", "intent-training"
).strip().strip("/")

try:
    TRAINING_LEARNING_RATE = float(os.environ.get("TRAINING_LEARNING_RATE", "0.05"))
except (TypeError, ValueError):
    TRAINING_LEARNING_RATE = 0.05

try:
    TRAINING_BOOST_MIN = float(os.environ.get("TRAINING_BOOST_MIN", "0.5"))
except (TypeError, ValueError):
    TRAINING_BOOST_MIN = 0.5

try:
    TRAINING_BOOST_MAX = float(os.environ.get("TRAINING_BOOST_MAX", "2.0"))
except (TypeError, ValueError):
    TRAINING_BOOST_MAX = 2.0

try:
    TRAINING_DEGRADATION_THRESHOLD = float(
        os.environ.get("TRAINING_DEGRADATION_THRESHOLD", "0.10")
    )
except (TypeError, ValueError):
    TRAINING_DEGRADATION_THRESHOLD = 0.10

HOLDOUT_FRACTION = 0.2
COST_PREFLIGHT_MONTHLY_USD = 0.04

ACTIVE_POINTER_SUFFIX = "weights/active.json"
VERSIONS_SUFFIX = "weights/versions"
LABELS_SUFFIX = "labels/session_outcomes.jsonl"


def _prefix_key(suffix: str) -> str:
    base = INTENT_TRAINING_PREFIX or "intent-training"
    return f"{base}/{suffix}"


def is_training_hard_disabled() -> bool:
    return TRAINING_HARD_DISABLED


def parse_labels_jsonl(raw: str) -> List[Dict[str, Any]]:
    """Parse newline-delimited labeled session outcomes."""
    labels: List[Dict[str, Any]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        ids = row.get("label_node_ids") or row.get("node_ids") or []
        if isinstance(ids, str):
            ids = [ids]
        if not isinstance(ids, list):
            continue
        label_ids = [str(x).strip() for x in ids if str(x).strip()]
        if not label_ids:
            continue
        text = str(row.get("first_turn_text") or row.get("request_text") or "").strip()
        embedding = row.get("embedding")
        labels.append(
            {
                "first_turn_text": text,
                "label_node_ids": label_ids,
                "embedding": embedding if isinstance(embedding, list) else None,
            }
        )
    return labels


def clamp_boost(value: float) -> float:
    if value < TRAINING_BOOST_MIN:
        return TRAINING_BOOST_MIN
    if value > TRAINING_BOOST_MAX:
        return TRAINING_BOOST_MAX
    return value


def apply_boost_updates(
    boosts: Dict[str, float],
    label_node_ids: Sequence[str],
    predicted_top_id: Optional[str],
) -> Dict[str, float]:
    """Bounded multiplicative boost update for one labeled outcome."""
    out = dict(boosts)
    for rid in label_node_ids:
        out[rid] = clamp_boost(out.get(rid, 1.0) + TRAINING_LEARNING_RATE)
    if predicted_top_id and predicted_top_id not in label_node_ids:
        out[predicted_top_id] = clamp_boost(
            out.get(predicted_top_id, 1.0) - (TRAINING_LEARNING_RATE / 2.0)
        )
    return out


def apply_record_boosts_to_neighbors(
    neighbors: Sequence[Dict[str, Any]],
    record_boosts: Optional[Dict[str, float]],
) -> List[Dict[str, Any]]:
    """Multiply neighbor scores by trained record boosts and re-sort descending."""
    if not neighbors or not record_boosts:
        return list(neighbors or [])
    boosted: List[Dict[str, Any]] = []
    for n in neighbors:
        if not isinstance(n, dict):
            continue
        rid = str(n.get("record_id") or "").strip()
        try:
            score = float(n.get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        mult = float(record_boosts.get(rid, 1.0)) if rid else 1.0
        boosted.append({**n, "record_id": rid, "score": max(0.0, min(1.0, score * mult))})
    boosted.sort(key=lambda d: d.get("score", 0.0), reverse=True)
    return boosted


def _split_holdout(
    labels: Sequence[Dict[str, Any]],
    *,
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    items = list(labels)
    if len(items) < 2:
        return items, []
    rng = random.Random(seed)
    rng.shuffle(items)
    holdout_n = max(1, int(len(items) * HOLDOUT_FRACTION))
    holdout = items[:holdout_n]
    train = items[holdout_n:]
    return train, holdout


def measure_top1_accuracy(
    labels: Sequence[Dict[str, Any]],
    record_boosts: Dict[str, float],
    *,
    rank_fn: Callable[[Dict[str, Any]], List[str]],
) -> float:
    """Fraction of labels where top-1 predicted id is in label_node_ids."""
    if not labels:
        return 1.0
    hits = 0
    for row in labels:
        ranked = rank_fn({**row, "record_boosts": record_boosts})
        if not ranked:
            continue
        if ranked[0] in row.get("label_node_ids", []):
            hits += 1
    return hits / len(labels)


def train_record_boosts(
    labels: Sequence[Dict[str, Any]],
    current_boosts: Optional[Dict[str, float]] = None,
    *,
    rank_fn: Callable[[Dict[str, Any]], List[str]],
    seed: int = 42,
) -> Dict[str, Any]:
    """Run one training epoch; validate holdout; auto-disable on >10% degradation."""
    boosts = dict(current_boosts or {})
    train, holdout = _split_holdout(labels, seed=seed)
    if not train:
        return {
            "trained": False,
            "reason": "insufficient_labels",
            "record_boosts": boosts,
            "training_disabled": False,
        }

    baseline_acc = measure_top1_accuracy(holdout, boosts, rank_fn=rank_fn) if holdout else 1.0

    for row in train:
        ranked = rank_fn({**row, "record_boosts": boosts})
        top = ranked[0] if ranked else None
        boosts = apply_boost_updates(boosts, row.get("label_node_ids", []), top)

    new_acc = measure_top1_accuracy(holdout, boosts, rank_fn=rank_fn) if holdout else 1.0
    floor = baseline_acc * (1.0 - TRAINING_DEGRADATION_THRESHOLD)
    degraded = holdout and new_acc < floor

    if degraded:
        logger.warning(
            "intent_training: holdout degraded baseline=%.3f new=%.3f floor=%.3f — kill switch",
            baseline_acc,
            new_acc,
            floor,
        )
        return {
            "trained": False,
            "reason": "holdout_degradation",
            "baseline_accuracy": baseline_acc,
            "new_accuracy": new_acc,
            "record_boosts": dict(current_boosts or {}),
            "training_disabled": True,
        }

    return {
        "trained": True,
        "reason": "ok",
        "baseline_accuracy": baseline_acc,
        "new_accuracy": new_acc,
        "record_boosts": boosts,
        "training_disabled": False,
        "train_count": len(train),
        "holdout_count": len(holdout),
    }


def build_weight_snapshot(
    record_boosts: Dict[str, float],
    *,
    previous_version_id: Optional[str] = None,
    accuracy_holdout: Optional[float] = None,
    training_disabled: bool = False,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    ts = now or datetime.now(timezone.utc)
    version_id = ts.strftime("%Y%m%dT%H%M%SZ")
    return {
        "version_id": version_id,
        "record_boosts": record_boosts,
        "previous_version_id": previous_version_id,
        "accuracy_holdout": accuracy_holdout,
        "training_disabled": training_disabled,
        "cost_preflight_monthly_usd": COST_PREFLIGHT_MONTHLY_USD,
        "created_at": ts.isoformat().replace("+00:00", "Z"),
    }


def resolve_rollback_version(
    active: Optional[Dict[str, Any]],
    *,
    requested_version_id: Optional[str] = None,
) -> Optional[str]:
    if requested_version_id:
        return str(requested_version_id).strip() or None
    if not active:
        return None
    prev = active.get("previous_version_id")
    return str(prev).strip() if prev else None


def load_active_weights_from_store(
    get_object: Callable[[str], str],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Return (active_pointer_doc, resolved_version_doc)."""
    pointer_raw = get_object(_prefix_key(ACTIVE_POINTER_SUFFIX))
    pointer = json.loads(pointer_raw)
    version_id = str(pointer.get("version_id") or "").strip()
    if not version_id:
        return pointer, None
    version_raw = get_object(_prefix_key(f"{VERSIONS_SUFFIX}/{version_id}.json"))
    return pointer, json.loads(version_raw)


def persist_weight_snapshot(
    snapshot: Dict[str, Any],
    put_object: Callable[[str, str], None],
) -> Dict[str, Any]:
    version_id = snapshot["version_id"]
    version_key = _prefix_key(f"{VERSIONS_SUFFIX}/{version_id}.json")
    put_object(version_key, json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
    pointer = {
        "version_id": version_id,
        "updated_at": snapshot.get("created_at"),
        "training_disabled": snapshot.get("training_disabled", False),
    }
    put_object(
        _prefix_key(ACTIVE_POINTER_SUFFIX),
        json.dumps(pointer, separators=(",", ":"), sort_keys=True),
    )
    return {"version_id": version_id, "pointer_key": _prefix_key(ACTIVE_POINTER_SUFFIX)}


def run_training_cycle(
    *,
    get_object: Callable[[str], str],
    put_object: Callable[[str, str], None],
    rank_fn: Callable[[Dict[str, Any]], List[str]],
    dry_run: bool = False,
    labels: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Full training job: load labels, train, version, persist (or dry-run)."""
    if is_training_hard_disabled():
        return {
            "enabled": False,
            "reason": "TRAINING_HARD_DISABLED",
            "cost_preflight_monthly_usd": COST_PREFLIGHT_MONTHLY_USD,
        }

    if labels is None:
        try:
            labels_raw = get_object(_prefix_key(LABELS_SUFFIX))
        except Exception as exc:  # noqa: BLE001
            logger.warning("intent_training: labels load failed: %s", exc)
            return {"enabled": True, "trained": False, "reason": "labels_unavailable"}
        labels = parse_labels_jsonl(labels_raw)

    label_list = list(labels or [])
    if not label_list:
        return {"enabled": True, "trained": False, "reason": "no_labels"}

    current_boosts: Dict[str, float] = {}
    previous_version_id: Optional[str] = None
    try:
        _pointer, active_version = load_active_weights_from_store(get_object)
        if active_version and not active_version.get("training_disabled"):
            boosts = active_version.get("record_boosts")
            if isinstance(boosts, dict):
                current_boosts = {str(k): float(v) for k, v in boosts.items()}
            previous_version_id = str(active_version.get("version_id") or "") or None
    except Exception:  # noqa: BLE001 — cold start with no weights yet
        pass

    result = train_record_boosts(label_list, current_boosts, rank_fn=rank_fn)
    if not result.get("trained"):
        if result.get("training_disabled"):
            snap = build_weight_snapshot(
                dict(current_boosts),
                previous_version_id=previous_version_id,
                accuracy_holdout=result.get("new_accuracy"),
                training_disabled=True,
            )
            if not dry_run:
                persist_weight_snapshot(snap, put_object)
        return {
            "enabled": True,
            "trained": False,
            "reason": result.get("reason"),
            "training_disabled": result.get("training_disabled", False),
            "baseline_accuracy": result.get("baseline_accuracy"),
            "new_accuracy": result.get("new_accuracy"),
            "cost_preflight_monthly_usd": COST_PREFLIGHT_MONTHLY_USD,
        }

    snap = build_weight_snapshot(
        result["record_boosts"],
        previous_version_id=previous_version_id,
        accuracy_holdout=result.get("new_accuracy"),
        training_disabled=False,
    )
    persisted = None
    if not dry_run:
        persisted = persist_weight_snapshot(snap, put_object)

    return {
        "enabled": True,
        "trained": True,
        "version_id": snap["version_id"],
        "persisted": persisted,
        "baseline_accuracy": result.get("baseline_accuracy"),
        "new_accuracy": result.get("new_accuracy"),
        "train_count": result.get("train_count"),
        "holdout_count": result.get("holdout_count"),
        "cost_preflight_monthly_usd": COST_PREFLIGHT_MONTHLY_USD,
    }


def run_rollback(
    *,
    get_object: Callable[[str], str],
    put_object: Callable[[str, str], None],
    requested_version_id: Optional[str] = None,
) -> Dict[str, Any]:
    """One-call rollback: repoint active.json to previous (or explicit) version."""
    try:
        pointer, active_version = load_active_weights_from_store(get_object)
    except Exception as exc:  # noqa: BLE001
        return {"rolled_back": False, "reason": "no_active_weights", "error": str(exc)[:200]}

    target = resolve_rollback_version(active_version or pointer, requested_version_id=requested_version_id)
    if not target:
        return {"rolled_back": False, "reason": "no_previous_version"}

    version_raw = get_object(_prefix_key(f"{VERSIONS_SUFFIX}/{target}.json"))
    version_doc = json.loads(version_raw)
    pointer_out = {
        "version_id": target,
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "training_disabled": version_doc.get("training_disabled", False),
        "rolled_back_from": (active_version or {}).get("version_id"),
    }
    put_object(
        _prefix_key(ACTIVE_POINTER_SUFFIX),
        json.dumps(pointer_out, separators=(",", ":"), sort_keys=True),
    )
    return {"rolled_back": True, "version_id": target, "pointer": pointer_out}


def load_inference_record_boosts(
    get_object: Optional[Callable[[str], str]] = None,
) -> Dict[str, float]:
    """Read-only load of active boosts for inference; {} on disable or miss."""
    if is_training_hard_disabled():
        return {}
    if not INTENT_TRAINING_BUCKET:
        return {}
    getter = get_object
    if getter is None:
        try:
            import boto3

            s3 = boto3.client("s3")

            def _default_get(key: str) -> str:
                resp = s3.get_object(Bucket=INTENT_TRAINING_BUCKET, Key=key)
                return resp["Body"].read().decode("utf-8")

            getter = _default_get
        except Exception:  # noqa: BLE001
            return {}
    try:
        _pointer, active_version = load_active_weights_from_store(getter)
        if not active_version or active_version.get("training_disabled"):
            return {}
        boosts = active_version.get("record_boosts")
        if not isinstance(boosts, dict):
            return {}
        return {str(k): float(v) for k, v in boosts.items()}
    except Exception:  # noqa: BLE001
        return {}
