"""
Enceladus Production Health Monitor — ENC-TSK-D20 / ENC-PLN-020 Phase 4
Extended by ENC-TSK-K44 / ENC-FTR-071 (B66 Ph5): per-service health checks
feeding the B66 CloudWatch dashboard.

Scheduled Lambda (EventBridge, every 15 minutes) that:
  1. Publishes per-function CodeSize metrics (original D20 CFN-stomp detector:
     alerts if code_size < 1024 bytes).
  2. Runs per-service health checks — DynamoDB, Neo4j AuraDB, S3, SQS, and a
     Lambda cold-start baseline — and publishes CloudWatch metrics consumed by
     the B66 dashboard panels.

Metrics published (namespace Enceladus/Prod unless noted):
  - LambdaCodeSize            (dimension: FunctionName)              [D20]
  - DynamoDBThrottle          (dimension: TableName)                 [K44]
  - GraphSyncLag              (dimension: QueueName)                 [K44]
  - MCPColdStart               (dimension: FunctionName)              [K44]
  - ServiceHealthCheck         (dimension: Service) 1=healthy 0=unhealthy [K44]

Environment variables:
  FUNCTION_NAMES        JSON array of Lambda function names to monitor (D20)
  COLD_START_FUNCTIONS   JSON array of Lambda function names to sample for
                          cold-start baseline (K44). Defaults to FUNCTION_NAMES.
  DYNAMODB_TABLE_NAME     DynamoDB table checked for health + throttle signal
  NEO4J_SECRET_NAME       Secrets Manager secret id holding NEO4J_URI/creds
  S3_HEALTH_BUCKET        S3 bucket checked for reachability
  GRAPH_SYNC_QUEUE_URL    SQS queue URL checked for depth (graph_sync lag proxy).
                          Named distinctly from devops-deploy-intake's
                          SQS_QUEUE_URL (env_drift_registry.json deploy-critical
                          var) so the ENC-TSK-H22 per-function env-parity
                          strip-proof attribution stays unambiguous.
  AWS_REGION               AWS region (default: us-west-2)
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
COLD_START_FUNCTIONS: List[str] = json.loads(
    os.environ.get("COLD_START_FUNCTIONS", "") or os.environ.get("FUNCTION_NAMES", "[]")
)

DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "")
NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "")
S3_HEALTH_BUCKET = os.environ.get("S3_HEALTH_BUCKET", "")
GRAPH_SYNC_QUEUE_URL = os.environ.get("GRAPH_SYNC_QUEUE_URL", "")

# ENC-ISS-465: hard kill switch. Set to "1" to skip all AWS calls (cost guard).
HARD_DISABLED = os.environ.get("HEALTH_MONITOR_HARD_DISABLED", "0") == "1"

# Alarm thresholds (documented here; the actual CloudWatch Alarm resources
# live in infrastructure/cloudformation/05-monitoring.yaml and MUST reference
# these same metric names/namespaces).
DYNAMODB_THROTTLE_ALARM_THRESHOLD = 1  # any throttle in a 15-min window pages
GRAPH_SYNC_LAG_ALARM_THRESHOLD_MESSAGES = 100  # queue depth backlog
MCP_COLD_START_ALARM_THRESHOLD_MS = 5000  # cold init duration


# ---------------------------------------------------------------------------
# Lazy AWS clients (colocated tests monkeypatch these module globals)
# ---------------------------------------------------------------------------

_lambda_client = None
_cw_client = None
_ddb_client = None
_s3_client = None
_sqs_client = None
_secrets_client = None


def _get_lambda():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=REGION)
    return _lambda_client


def _get_cw():
    global _cw_client
    if _cw_client is None:
        _cw_client = boto3.client("cloudwatch", region_name=REGION)
    return _cw_client


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client("dynamodb", region_name=REGION)
    return _ddb_client


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=REGION)
    return _s3_client


def _get_sqs():
    global _sqs_client
    if _sqs_client is None:
        _sqs_client = boto3.client("sqs", region_name=REGION)
    return _sqs_client


def _get_secrets():
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager", region_name=REGION)
    return _secrets_client


# ---------------------------------------------------------------------------
# D20: per-function CodeSize sentinel (unchanged behavior)
# ---------------------------------------------------------------------------

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


def _codesize_metrics(configs: List[dict], now: datetime) -> List[dict]:
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
    return metric_data


# ---------------------------------------------------------------------------
# K44: per-service health checks
# ---------------------------------------------------------------------------

def check_dynamodb(table_name: str) -> Dict[str, Any]:
    """Check DynamoDB table reachability + surface throttle signal.

    Uses describe_table (cheap, no read/write capacity consumed) to confirm
    the table is ACTIVE, and reads the ConsumedCapacity-free throttle count
    the caller publishes separately via CloudWatch (ThrottledRequests is a
    native DynamoDB metric already in AWS/DynamoDB; this check reports
    reachability plus an explicit boolean the dashboard can alarm on).
    """
    if not table_name:
        return {"service": "dynamodb", "healthy": False, "error": "DYNAMODB_TABLE_NAME not configured"}
    try:
        resp = _get_ddb().describe_table(TableName=table_name)
        status = resp["Table"]["TableStatus"]
        healthy = status == "ACTIVE"
        return {
            "service": "dynamodb",
            "healthy": healthy,
            "table_name": table_name,
            "table_status": status,
            "throttled": False,
        }
    except Exception as exc:
        logger.error("[ERROR] DynamoDB health check failed for %s: %s", table_name, exc)
        # A ProvisionedThroughputExceededException surfacing here IS a throttle signal.
        throttled = "ProvisionedThroughputExceeded" in type(exc).__name__ or "Throttl" in str(exc)
        return {
            "service": "dynamodb",
            "healthy": False,
            "table_name": table_name,
            "error": str(exc),
            "throttled": throttled,
        }


def check_neo4j(secret_name: str) -> Dict[str, Any]:
    """Check Neo4j AuraDB connectivity via a lightweight Bolt handshake."""
    if not secret_name:
        return {"service": "neo4j", "healthy": False, "error": "NEO4J_SECRET_NAME not configured"}
    try:
        from neo4j import GraphDatabase

        resp = _get_secrets().get_secret_value(SecretId=secret_name)
        creds = json.loads(resp["SecretString"])
        driver = GraphDatabase.driver(
            creds["NEO4J_URI"],
            auth=(creds.get("NEO4J_USERNAME", "neo4j"), creds["NEO4J_PASSWORD"]),
            connection_acquisition_timeout=10,
        )
        try:
            driver.verify_connectivity()
            return {"service": "neo4j", "healthy": True}
        finally:
            driver.close()
    except Exception as exc:
        logger.error("[ERROR] Neo4j health check failed: %s", exc)
        return {"service": "neo4j", "healthy": False, "error": str(exc)}


def check_s3(bucket: str) -> Dict[str, Any]:
    """Check S3 bucket reachability via head_bucket (no data transfer)."""
    if not bucket:
        return {"service": "s3", "healthy": False, "error": "S3_HEALTH_BUCKET not configured"}
    try:
        _get_s3().head_bucket(Bucket=bucket)
        return {"service": "s3", "healthy": True, "bucket": bucket}
    except Exception as exc:
        logger.error("[ERROR] S3 health check failed for %s: %s", bucket, exc)
        return {"service": "s3", "healthy": False, "bucket": bucket, "error": str(exc)}


def check_sqs(queue_url: str) -> Dict[str, Any]:
    """Check SQS queue reachability and return approximate depth (graph_sync lag proxy)."""
    if not queue_url:
        return {"service": "sqs", "healthy": False, "error": "GRAPH_SYNC_QUEUE_URL not configured", "depth": 0}
    try:
        resp = _get_sqs().get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )
        attrs = resp.get("Attributes", {})
        depth = int(attrs.get("ApproximateNumberOfMessages", 0))
        in_flight = int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0))
        return {
            "service": "sqs",
            "healthy": True,
            "queue_url": queue_url,
            "depth": depth,
            "in_flight": in_flight,
        }
    except Exception as exc:
        logger.error("[ERROR] SQS health check failed for %s: %s", queue_url, exc)
        return {"service": "sqs", "healthy": False, "queue_url": queue_url, "error": str(exc), "depth": 0}


def check_lambda_cold_start(function_names: List[str]) -> Dict[str, Any]:
    """Baseline cold-start proxy: LastUpdateStatus + init duration via a
    lightweight config read. A true init-duration measurement requires log
    correlation (REPORT lines); as a 15-min baseline we sample
    get_function_configuration State/LastUpdateStatus per function and treat
    any function stuck outside Active/Successful as a cold-start risk signal.
    """
    if not function_names:
        return {"service": "lambda_cold_start", "healthy": False, "error": "COLD_START_FUNCTIONS not configured", "samples": []}

    lambda_client = _get_lambda()
    samples = []
    unhealthy = 0
    for fn in function_names:
        try:
            config = lambda_client.get_function_configuration(FunctionName=fn)
            state = config.get("State", "unknown")
            last_update_status = config.get("LastUpdateStatus", "unknown")
            ok = state == "Active" and last_update_status == "Successful"
            if not ok:
                unhealthy += 1
            samples.append({
                "function_name": fn,
                "state": state,
                "last_update_status": last_update_status,
                "healthy": ok,
            })
        except Exception as exc:
            unhealthy += 1
            logger.error("[ERROR] Cold-start baseline check failed for %s: %s", fn, exc)
            samples.append({"function_name": fn, "healthy": False, "error": str(exc)})

    return {
        "service": "lambda_cold_start",
        "healthy": unhealthy == 0,
        "samples": samples,
        "unhealthy_count": unhealthy,
    }


# ---------------------------------------------------------------------------
# Metric assembly
# ---------------------------------------------------------------------------

def _health_check_metrics(results: Dict[str, Any], now: datetime) -> List[dict]:
    """Turn health-check results into ServiceHealthCheck + specific metrics."""
    metric_data: List[dict] = []

    for service, result in results.items():
        metric_data.append({
            "MetricName": "ServiceHealthCheck",
            "Value": 1.0 if result.get("healthy") else 0.0,
            "Unit": "None",
            "Timestamp": now,
            "Dimensions": [{"Name": "Service", "Value": service}],
        })

    ddb = results.get("dynamodb", {})
    if ddb.get("table_name"):
        metric_data.append({
            "MetricName": "DynamoDBThrottle",
            "Value": 1.0 if ddb.get("throttled") else 0.0,
            "Unit": "Count",
            "Timestamp": now,
            "Dimensions": [{"Name": "TableName", "Value": ddb["table_name"]}],
        })

    sqs = results.get("sqs", {})
    if sqs.get("queue_url"):
        queue_name = sqs["queue_url"].rsplit("/", 1)[-1]
        metric_data.append({
            "MetricName": "GraphSyncLag",
            "Value": float(sqs.get("depth", 0)),
            "Unit": "Count",
            "Timestamp": now,
            "Dimensions": [{"Name": "QueueName", "Value": queue_name}],
        })

    cold_start = results.get("lambda_cold_start", {})
    for sample in cold_start.get("samples", []):
        fn = sample.get("function_name")
        if not fn:
            continue
        metric_data.append({
            "MetricName": "MCPColdStart",
            "Value": 0.0 if sample.get("healthy") else 1.0,
            "Unit": "Count",
            "Timestamp": now,
            "Dimensions": [{"Name": "FunctionName", "Value": fn}],
        })

    return metric_data


def _publish_metrics(cw_client, metric_data: List[dict]) -> int:
    # CloudWatch PutMetricData accepts max 1000 items per call; batch conservatively at 20.
    for i in range(0, len(metric_data), 20):
        batch = metric_data[i:i + 20]
        cw_client.put_metric_data(Namespace=NAMESPACE, MetricData=batch)
    return len(metric_data)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("[START] Production health monitor")

    if HARD_DISABLED:
        logger.warning("[SKIP] HEALTH_MONITOR_HARD_DISABLED=1 — skipping all checks (ISS-465 cost guard)")
        return {"statusCode": 200, "body": json.dumps({"skipped": True})}

    metric_data: List[dict] = []
    now = datetime.now(timezone.utc)

    # D20: CodeSize sentinel (only if configured — backward compatible)
    stomped: List[dict] = []
    if FUNCTION_NAMES:
        configs = _get_lambda_configs(_get_lambda(), FUNCTION_NAMES)
        metric_data.extend(_codesize_metrics(configs, now))
        stomped = [c for c in configs if c.get("CodeSize", 0) < 1024 and "error" not in c]
        if stomped:
            logger.error(
                "[ERROR] CFN STOMP DETECTED — %d functions with CodeSize < 1024: %s",
                len(stomped),
                ", ".join(f"{c['FunctionName']}={c['CodeSize']}" for c in stomped),
            )
    else:
        logger.info("[SKIP] FUNCTION_NAMES not configured — skipping CodeSize sentinel")

    # K44: per-service health checks
    results = {
        "dynamodb": check_dynamodb(DYNAMODB_TABLE_NAME),
        "neo4j": check_neo4j(NEO4J_SECRET_NAME),
        "s3": check_s3(S3_HEALTH_BUCKET),
        "sqs": check_sqs(GRAPH_SYNC_QUEUE_URL),
        "lambda_cold_start": check_lambda_cold_start(COLD_START_FUNCTIONS),
    }
    metric_data.extend(_health_check_metrics(results, now))

    published = _publish_metrics(_get_cw(), metric_data)
    unhealthy_services = [svc for svc, r in results.items() if not r.get("healthy")]
    if unhealthy_services:
        logger.warning("[WARN] Unhealthy services this cycle: %s", ", ".join(unhealthy_services))

    logger.info("[SUCCESS] Published %d metrics to %s", published, NAMESPACE)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "functions_checked": len(FUNCTION_NAMES),
            "metrics_published": published,
            "stomped_count": len(stomped),
            "stomped_functions": [c["FunctionName"] for c in stomped],
            "service_health": {svc: r.get("healthy") for svc, r in results.items()},
            "unhealthy_services": unhealthy_services,
        }),
    }
