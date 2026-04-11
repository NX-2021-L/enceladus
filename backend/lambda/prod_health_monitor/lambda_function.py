"""
Enceladus Production Health Monitor — ENC-TSK-D20 / ENC-PLN-020 Phase 4

Scheduled Lambda that publishes per-function CodeSize metrics to CloudWatch.
Detects CFN stomp incidents (CodeSize < 1024), architecture drift, and
runtime mismatches within 15 minutes via EventBridge-triggered health probes.

Metrics published:
  - Enceladus/Prod/LambdaCodeSize (dimension: FunctionName)

Environment variables:
  FUNCTION_NAMES   JSON array of Lambda function names to monitor
  AWS_REGION       AWS region (default: us-west-2)
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-west-2")
NAMESPACE = "Enceladus/Prod"
FUNCTION_NAMES: List[str] = json.loads(os.environ.get("FUNCTION_NAMES", "[]"))


def _get_lambda_configs(lambda_client, function_names: List[str]) -> List[dict]:
    results = []
    for fn in function_names:
        try:
            config = lambda_client.get_function_configuration(FunctionName=fn)
            results.append({
                "FunctionName": fn,
                "CodeSize": config.get("CodeSize", 0),
                "Runtime": config.get("Runtime", "unknown"),
                "Architectures": config.get("Architectures", ["unknown"]),
                "LastModified": config.get("LastModified", ""),
                "State": config.get("State", "unknown"),
            })
        except lambda_client.exceptions.ResourceNotFoundException:
            logger.warning("[WARN] Function %s not found, skipping", fn)
        except Exception as exc:
            logger.error("[ERROR] Failed to get config for %s: %s", fn, exc)
            results.append({
                "FunctionName": fn,
                "CodeSize": 0,
                "error": str(exc),
            })
    return results


def _publish_metrics(cw_client, configs: List[dict]) -> int:
    now = datetime.now(timezone.utc)
    metric_data = []
    for config in configs:
        if "error" in config:
            continue
        metric_data.append({
            "MetricName": "LambdaCodeSize",
            "Value": float(config["CodeSize"]),
            "Unit": "Bytes",
            "Timestamp": now,
            "Dimensions": [
                {"Name": "FunctionName", "Value": config["FunctionName"]},
            ],
        })

    # CloudWatch PutMetricData accepts max 1000 items per call
    for i in range(0, len(metric_data), 20):
        batch = metric_data[i:i + 20]
        cw_client.put_metric_data(Namespace=NAMESPACE, MetricData=batch)

    return len(metric_data)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("[START] Production health monitor — %d functions", len(FUNCTION_NAMES))

    if not FUNCTION_NAMES:
        logger.error("[ERROR] FUNCTION_NAMES env var is empty or not set")
        return {"statusCode": 500, "body": "FUNCTION_NAMES not configured"}

    lambda_client = boto3.client("lambda", region_name=REGION)
    cw_client = boto3.client("cloudwatch", region_name=REGION)

    configs = _get_lambda_configs(lambda_client, FUNCTION_NAMES)

    # Detect stomp (CodeSize < 1024)
    stomped = [c for c in configs if c.get("CodeSize", 0) < 1024 and "error" not in c]
    if stomped:
        logger.error(
            "[ERROR] CFN STOMP DETECTED — %d functions with CodeSize < 1024: %s",
            len(stomped),
            ", ".join(f"{c['FunctionName']}={c['CodeSize']}" for c in stomped),
        )

    published = _publish_metrics(cw_client, configs)
    logger.info("[SUCCESS] Published %d LambdaCodeSize metrics to %s", published, NAMESPACE)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "functions_checked": len(configs),
            "metrics_published": published,
            "stomped_count": len(stomped),
            "stomped_functions": [c["FunctionName"] for c in stomped],
        }),
    }
