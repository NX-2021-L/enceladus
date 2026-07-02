"""Tests for prod_health_monitor Lambda — ENC-TSK-D20 (CodeSize sentinel) +
ENC-TSK-K44 / ENC-FTR-071 (per-service health checks: DynamoDB, Neo4j AuraDB,
S3, SQS, Lambda cold-start baseline).

Covers:
  - D20 CodeSize sentinel behavior is preserved (stomp detection, metric shape)
  - Each K44 health check reports healthy/unhealthy correctly with fake clients
  - DynamoDBThrottle / GraphSyncLag / MCPColdStart metrics are shaped correctly
  - ServiceHealthCheck emits one metric per service with the Service dimension
  - handler() batches PutMetricData calls (<=20 per call) and never raises on
    a single service failure (fail-open per service, still publishes others)
  - HEALTH_MONITOR_HARD_DISABLED short-circuits all AWS calls (ISS-465 guard)
"""

import json

import lambda_function as mod


# ---------------------------------------------------------------------------
# Fake AWS clients
# ---------------------------------------------------------------------------

class FakeLambdaClient:
    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self, configs=None, fail_functions=None):
        self._configs = configs or {}
        self._fail_functions = fail_functions or set()

    def get_function_configuration(self, FunctionName):
        if FunctionName in self._fail_functions:
            raise RuntimeError("boom")
        if FunctionName not in self._configs:
            raise self.exceptions.ResourceNotFoundException(FunctionName)
        return self._configs[FunctionName]


class FakeCloudWatchClient:
    def __init__(self):
        self.calls = []

    def put_metric_data(self, Namespace, MetricData):
        self.calls.append({"Namespace": Namespace, "MetricData": MetricData})


class FakeDynamoDBClient:
    def __init__(self, status="ACTIVE", error=None):
        self._status = status
        self._error = error

    def describe_table(self, TableName):
        if self._error:
            raise self._error
        return {"Table": {"TableStatus": self._status}}


class FakeS3Client:
    def __init__(self, error=None):
        self._error = error

    def head_bucket(self, Bucket):
        if self._error:
            raise self._error
        return {}


class FakeSQSClient:
    def __init__(self, depth=0, in_flight=0, error=None):
        self._depth = depth
        self._in_flight = in_flight
        self._error = error

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        if self._error:
            raise self._error
        return {
            "Attributes": {
                "ApproximateNumberOfMessages": str(self._depth),
                "ApproximateNumberOfMessagesNotVisible": str(self._in_flight),
            }
        }


# ---------------------------------------------------------------------------
# D20: CodeSize sentinel (preserved behavior)
# ---------------------------------------------------------------------------

def test_codesize_metrics_shape():
    now = mod.datetime.now(mod.timezone.utc)
    configs = [{"FunctionName": "fn-a", "CodeSize": 2048}]
    metrics = mod._codesize_metrics(configs, now)
    assert metrics == [{
        "MetricName": "LambdaCodeSize",
        "Value": 2048.0,
        "Unit": "Bytes",
        "Timestamp": now,
        "Dimensions": [{"Name": "FunctionName", "Value": "fn-a"}],
    }]


def test_get_lambda_configs_detects_stomp(monkeypatch):
    client = FakeLambdaClient(configs={
        "fn-a": {"CodeSize": 512, "Runtime": "python3.12", "Architectures": ["arm64"], "State": "Active"},
        "fn-b": {"CodeSize": 4096, "Runtime": "python3.12", "Architectures": ["arm64"], "State": "Active"},
    })
    configs = mod._get_lambda_configs(client, ["fn-a", "fn-b"])
    stomped = [c for c in configs if c["CodeSize"] < 1024]
    assert len(stomped) == 1
    assert stomped[0]["FunctionName"] == "fn-a"


def test_get_lambda_configs_skips_missing_function():
    client = FakeLambdaClient(configs={})
    configs = mod._get_lambda_configs(client, ["ghost-fn"])
    assert configs == []


def test_get_lambda_configs_records_error():
    client = FakeLambdaClient(configs={}, fail_functions={"broken-fn"})
    configs = mod._get_lambda_configs(client, ["broken-fn"])
    assert configs[0]["error"] == "boom"
    assert configs[0]["CodeSize"] == 0


# ---------------------------------------------------------------------------
# K44: DynamoDB health check
# ---------------------------------------------------------------------------

def test_check_dynamodb_healthy(monkeypatch):
    monkeypatch.setattr(mod, "_get_ddb", lambda: FakeDynamoDBClient(status="ACTIVE"))
    result = mod.check_dynamodb("devops-project-tracker")
    assert result["healthy"] is True
    assert result["table_status"] == "ACTIVE"
    assert result["throttled"] is False


def test_check_dynamodb_unhealthy_status(monkeypatch):
    monkeypatch.setattr(mod, "_get_ddb", lambda: FakeDynamoDBClient(status="UPDATING"))
    result = mod.check_dynamodb("devops-project-tracker")
    assert result["healthy"] is False
    assert result["table_status"] == "UPDATING"


def test_check_dynamodb_throttle_signal(monkeypatch):
    class ThrottleError(Exception):
        pass
    ThrottleError.__name__ = "ProvisionedThroughputExceededException"
    monkeypatch.setattr(mod, "_get_ddb", lambda: FakeDynamoDBClient(error=ThrottleError("throttled")))
    result = mod.check_dynamodb("devops-project-tracker")
    assert result["healthy"] is False
    assert result["throttled"] is True


def test_check_dynamodb_not_configured():
    result = mod.check_dynamodb("")
    assert result["healthy"] is False
    assert "not configured" in result["error"]


# ---------------------------------------------------------------------------
# K44: Neo4j health check
# ---------------------------------------------------------------------------

def test_check_neo4j_not_configured():
    result = mod.check_neo4j("")
    assert result["healthy"] is False
    assert "not configured" in result["error"]


def test_check_neo4j_healthy(monkeypatch):
    class FakeDriver:
        def verify_connectivity(self):
            return None

        def close(self):
            pass

    class FakeGraphDatabase:
        @staticmethod
        def driver(uri, auth, connection_acquisition_timeout=10):
            return FakeDriver()

    class FakeSecretsClient:
        def get_secret_value(self, SecretId):
            return {"SecretString": json.dumps({
                "NEO4J_URI": "bolt://example.com:7687",
                "NEO4J_USERNAME": "neo4j",
                "NEO4J_PASSWORD": "secret",
            })}

    import sys
    import types
    fake_neo4j_module = types.ModuleType("neo4j")
    fake_neo4j_module.GraphDatabase = FakeGraphDatabase
    monkeypatch.setitem(sys.modules, "neo4j", fake_neo4j_module)
    monkeypatch.setattr(mod, "_get_secrets", lambda: FakeSecretsClient())

    result = mod.check_neo4j("enceladus/neo4j/auradb-credentials")
    assert result["healthy"] is True


def test_check_neo4j_connectivity_failure(monkeypatch):
    class FakeDriver:
        def verify_connectivity(self):
            raise RuntimeError("connection refused")

        def close(self):
            pass

    class FakeGraphDatabase:
        @staticmethod
        def driver(uri, auth, connection_acquisition_timeout=10):
            return FakeDriver()

    class FakeSecretsClient:
        def get_secret_value(self, SecretId):
            return {"SecretString": json.dumps({
                "NEO4J_URI": "bolt://example.com:7687",
                "NEO4J_PASSWORD": "secret",
            })}

    import sys
    import types
    fake_neo4j_module = types.ModuleType("neo4j")
    fake_neo4j_module.GraphDatabase = FakeGraphDatabase
    monkeypatch.setitem(sys.modules, "neo4j", fake_neo4j_module)
    monkeypatch.setattr(mod, "_get_secrets", lambda: FakeSecretsClient())

    result = mod.check_neo4j("enceladus/neo4j/auradb-credentials")
    assert result["healthy"] is False
    assert "connection refused" in result["error"]


# ---------------------------------------------------------------------------
# K44: S3 health check
# ---------------------------------------------------------------------------

def test_check_s3_healthy(monkeypatch):
    monkeypatch.setattr(mod, "_get_s3", lambda: FakeS3Client())
    result = mod.check_s3("jreese-net")
    assert result["healthy"] is True


def test_check_s3_unhealthy(monkeypatch):
    monkeypatch.setattr(mod, "_get_s3", lambda: FakeS3Client(error=RuntimeError("access denied")))
    result = mod.check_s3("jreese-net")
    assert result["healthy"] is False
    assert "access denied" in result["error"]


def test_check_s3_not_configured():
    result = mod.check_s3("")
    assert result["healthy"] is False


# ---------------------------------------------------------------------------
# K44: SQS health check (graph_sync lag proxy)
# ---------------------------------------------------------------------------

def test_check_sqs_healthy_with_depth(monkeypatch):
    monkeypatch.setattr(mod, "_get_sqs", lambda: FakeSQSClient(depth=42, in_flight=3))
    result = mod.check_sqs("https://sqs.us-west-2.amazonaws.com/123/devops-graph-sync-queue.fifo")
    assert result["healthy"] is True
    assert result["depth"] == 42
    assert result["in_flight"] == 3


def test_check_sqs_unhealthy(monkeypatch):
    monkeypatch.setattr(mod, "_get_sqs", lambda: FakeSQSClient(error=RuntimeError("queue not found")))
    result = mod.check_sqs("https://sqs.us-west-2.amazonaws.com/123/missing-queue")
    assert result["healthy"] is False
    assert result["depth"] == 0


# ---------------------------------------------------------------------------
# K44: Lambda cold-start baseline
# ---------------------------------------------------------------------------

def test_check_lambda_cold_start_all_healthy(monkeypatch):
    client = FakeLambdaClient(configs={
        "devops-coordination-api": {"State": "Active", "LastUpdateStatus": "Successful"},
    })
    monkeypatch.setattr(mod, "_get_lambda", lambda: client)
    result = mod.check_lambda_cold_start(["devops-coordination-api"])
    assert result["healthy"] is True
    assert result["unhealthy_count"] == 0


def test_check_lambda_cold_start_detects_unhealthy(monkeypatch):
    client = FakeLambdaClient(configs={
        "devops-coordination-api": {"State": "Pending", "LastUpdateStatus": "InProgress"},
    })
    monkeypatch.setattr(mod, "_get_lambda", lambda: client)
    result = mod.check_lambda_cold_start(["devops-coordination-api"])
    assert result["healthy"] is False
    assert result["unhealthy_count"] == 1


def test_check_lambda_cold_start_not_configured():
    result = mod.check_lambda_cold_start([])
    assert result["healthy"] is False


# ---------------------------------------------------------------------------
# K44: metric assembly
# ---------------------------------------------------------------------------

def test_health_check_metrics_service_health_dimension():
    now = mod.datetime.now(mod.timezone.utc)
    results = {
        "dynamodb": {"healthy": True, "table_name": "t1", "throttled": False},
        "neo4j": {"healthy": False},
    }
    metrics = mod._health_check_metrics(results, now)
    service_metrics = [m for m in metrics if m["MetricName"] == "ServiceHealthCheck"]
    assert len(service_metrics) == 2
    values_by_service = {
        m["Dimensions"][0]["Value"]: m["Value"] for m in service_metrics
    }
    assert values_by_service["dynamodb"] == 1.0
    assert values_by_service["neo4j"] == 0.0


def test_health_check_metrics_dynamodb_throttle():
    now = mod.datetime.now(mod.timezone.utc)
    results = {"dynamodb": {"healthy": False, "table_name": "devops-project-tracker", "throttled": True}}
    metrics = mod._health_check_metrics(results, now)
    throttle_metrics = [m for m in metrics if m["MetricName"] == "DynamoDBThrottle"]
    assert len(throttle_metrics) == 1
    assert throttle_metrics[0]["Value"] == 1.0
    assert throttle_metrics[0]["Dimensions"] == [{"Name": "TableName", "Value": "devops-project-tracker"}]


def test_health_check_metrics_graph_sync_lag():
    now = mod.datetime.now(mod.timezone.utc)
    results = {"sqs": {
        "healthy": True,
        "queue_url": "https://sqs.us-west-2.amazonaws.com/123/devops-graph-sync-queue.fifo",
        "depth": 17,
    }}
    metrics = mod._health_check_metrics(results, now)
    lag_metrics = [m for m in metrics if m["MetricName"] == "GraphSyncLag"]
    assert len(lag_metrics) == 1
    assert lag_metrics[0]["Value"] == 17.0
    assert lag_metrics[0]["Dimensions"] == [{"Name": "QueueName", "Value": "devops-graph-sync-queue.fifo"}]


def test_health_check_metrics_mcp_cold_start():
    now = mod.datetime.now(mod.timezone.utc)
    results = {"lambda_cold_start": {
        "healthy": False,
        "samples": [
            {"function_name": "enceladus-mcp-code", "healthy": False},
            {"function_name": "enceladus-mcp-streamable", "healthy": True},
        ],
    }}
    metrics = mod._health_check_metrics(results, now)
    cold_start_metrics = {
        m["Dimensions"][0]["Value"]: m["Value"]
        for m in metrics if m["MetricName"] == "MCPColdStart"
    }
    assert cold_start_metrics["enceladus-mcp-code"] == 1.0
    assert cold_start_metrics["enceladus-mcp-streamable"] == 0.0


# ---------------------------------------------------------------------------
# K44: publish batching
# ---------------------------------------------------------------------------

def test_publish_metrics_batches_at_20():
    cw = FakeCloudWatchClient()
    metric_data = [{"MetricName": f"m{i}", "Value": 1.0} for i in range(45)]
    published = mod._publish_metrics(cw, metric_data)
    assert published == 45
    assert len(cw.calls) == 3  # 20 + 20 + 5
    assert all(len(c["MetricData"]) <= 20 for c in cw.calls)


# ---------------------------------------------------------------------------
# Handler integration
# ---------------------------------------------------------------------------

def _patch_all_healthy(monkeypatch):
    monkeypatch.setattr(mod, "check_dynamodb", lambda t: {"service": "dynamodb", "healthy": True, "table_name": t, "throttled": False})
    monkeypatch.setattr(mod, "check_neo4j", lambda s: {"service": "neo4j", "healthy": True})
    monkeypatch.setattr(mod, "check_s3", lambda b: {"service": "s3", "healthy": True, "bucket": b})
    monkeypatch.setattr(mod, "check_sqs", lambda q: {"service": "sqs", "healthy": True, "queue_url": q, "depth": 0})
    monkeypatch.setattr(mod, "check_lambda_cold_start", lambda fns: {"service": "lambda_cold_start", "healthy": True, "samples": []})


def test_handler_publishes_and_reports_healthy(monkeypatch):
    _patch_all_healthy(monkeypatch)
    cw = FakeCloudWatchClient()
    monkeypatch.setattr(mod, "_get_cw", lambda: cw)
    monkeypatch.setattr(mod, "FUNCTION_NAMES", [])

    result = mod.handler({}, None)

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["unhealthy_services"] == []
    assert all(body["service_health"].values())
    assert len(cw.calls) >= 1


def test_handler_reports_unhealthy_service(monkeypatch):
    _patch_all_healthy(monkeypatch)
    monkeypatch.setattr(mod, "check_neo4j", lambda s: {"service": "neo4j", "healthy": False, "error": "timeout"})
    cw = FakeCloudWatchClient()
    monkeypatch.setattr(mod, "_get_cw", lambda: cw)
    monkeypatch.setattr(mod, "FUNCTION_NAMES", [])

    result = mod.handler({}, None)

    body = json.loads(result["body"])
    assert "neo4j" in body["unhealthy_services"]
    assert body["service_health"]["neo4j"] is False


def test_handler_still_publishes_codesize_when_configured(monkeypatch):
    _patch_all_healthy(monkeypatch)
    cw = FakeCloudWatchClient()
    monkeypatch.setattr(mod, "_get_cw", lambda: cw)
    monkeypatch.setattr(mod, "FUNCTION_NAMES", ["fn-a"])
    lambda_client = FakeLambdaClient(configs={"fn-a": {"CodeSize": 4096, "State": "Active"}})
    monkeypatch.setattr(mod, "_get_lambda", lambda: lambda_client)

    result = mod.handler({}, None)

    body = json.loads(result["body"])
    assert body["functions_checked"] == 1
    assert body["stomped_count"] == 0


def test_handler_detects_stomp_and_still_runs_health_checks(monkeypatch):
    _patch_all_healthy(monkeypatch)
    cw = FakeCloudWatchClient()
    monkeypatch.setattr(mod, "_get_cw", lambda: cw)
    monkeypatch.setattr(mod, "FUNCTION_NAMES", ["fn-a"])
    lambda_client = FakeLambdaClient(configs={"fn-a": {"CodeSize": 200, "State": "Active"}})
    monkeypatch.setattr(mod, "_get_lambda", lambda: lambda_client)

    result = mod.handler({}, None)

    body = json.loads(result["body"])
    assert body["stomped_count"] == 1
    assert body["stomped_functions"] == ["fn-a"]
    # Health checks still ran despite the stomp detection.
    assert body["unhealthy_services"] == []


def test_handler_hard_disabled_short_circuits(monkeypatch):
    monkeypatch.setattr(mod, "HARD_DISABLED", True)

    def _boom(*args, **kwargs):
        raise AssertionError("should not call AWS when hard-disabled")

    monkeypatch.setattr(mod, "_get_cw", _boom)
    monkeypatch.setattr(mod, "_get_lambda", _boom)
    monkeypatch.setattr(mod, "_get_ddb", _boom)
    monkeypatch.setattr(mod, "_get_s3", _boom)
    monkeypatch.setattr(mod, "_get_sqs", _boom)
    monkeypatch.setattr(mod, "_get_secrets", _boom)

    result = mod.handler({}, None)

    assert result["statusCode"] == 200
    assert json.loads(result["body"])["skipped"] is True
