"""Enceladus/Rhythm CloudWatch metrics (ENC-TSK-K81)."""

from __future__ import annotations

import logging
from typing import Dict, Optional

import boto3

from config import CLOUDWATCH_NAMESPACE, PROJECT_ID

logger = logging.getLogger(__name__)
_cw = boto3.client("cloudwatch")


def publish_beat_metrics(
    tier: str,
    *,
    duration_ms: float,
    cost_estimate: float,
    artifact_bytes: int,
    backlog_delta: Optional[int] = None,
    extra: Optional[Dict[str, float]] = None,
) -> None:
    dims = [{"Name": "Tier", "Value": tier}, {"Name": "ProjectId", "Value": PROJECT_ID}]
    metrics = [
        {"MetricName": "beat_duration_ms", "Value": duration_ms, "Unit": "Milliseconds"},
        {"MetricName": "beat_cost_estimate", "Value": cost_estimate, "Unit": "None"},
        {"MetricName": "artifact_bytes", "Value": float(artifact_bytes), "Unit": "Bytes"},
    ]
    if backlog_delta is not None:
        metrics.append(
            {"MetricName": "backlog_delta", "Value": float(backlog_delta), "Unit": "Count"}
        )
    if extra:
        for name, value in extra.items():
            metrics.append({"MetricName": name, "Value": float(value), "Unit": "Count"})

    try:
        _cw.put_metric_data(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricData=[{**m, "Dimensions": dims} for m in metrics],
        )
    except Exception as exc:
        logger.warning("put_metric_data failed: %s", exc)


def publish_lyapunov(open_leaves: int, delta: int, grooming: bool = False) -> None:
    dims = [
        {"Name": "Tier", "Value": "decide"},
        {"Name": "ProjectId", "Value": PROJECT_ID},
        {"Name": "Grooming", "Value": "true" if grooming else "false"},
    ]
    try:
        _cw.put_metric_data(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricData=[
                {
                    "MetricName": "backlog_open_leaves",
                    "Dimensions": dims,
                    "Value": float(open_leaves),
                    "Unit": "Count",
                },
                {
                    "MetricName": "backlog_open_leaves_delta",
                    "Dimensions": dims,
                    "Value": float(delta),
                    "Unit": "Count",
                },
            ],
        )
    except Exception as exc:
        logger.warning("lyapunov metrics failed: %s", exc)
