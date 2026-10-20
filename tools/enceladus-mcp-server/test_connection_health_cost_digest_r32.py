"""ENC-TSK-R32 (C2.8): connection_health surfaces a compact cost_digest read from
s3://jreese-net/governance/cost-digest/latest.json (us-west-1), cached per Lambda
container for 1h, never raises, and never calls Cost Explorer.
"""
import io
import json
from unittest.mock import patch

from test_code_mode import _load_server, _run


class _ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _StubS3:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error
        self.calls = []

    def get_object(self, Bucket, Key):
        self.calls.append((Bucket, Key))
        if self.error is not None:
            raise self.error
        body = self.payload if isinstance(self.payload, (bytes, str)) else json.dumps(self.payload)
        return {"Body": io.BytesIO(body.encode("utf-8") if isinstance(body, str) else body)}


_DIGEST = {
    "date": "2026-10-18",
    "prior_day_spend": 12.34,
    "median_7d": 10.0,
    "regression": 1,
    "top_deltas": [{"service": f"svc{i}", "delta": i} for i in range(8)],
    "feed_publisher_invocations": 1234,
    "invalidation_paths_mtd": 56,
    "raw_ce_response": {"huge": "ignored"},
}


def _server():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    server._cost_digest_cache.update(value=None, fetched_at=0.0, ttl=0.0)
    return server


def _health(server, stub):
    with patch.object(server, "_health_api_request", return_value={"dynamodb": "ok", "s3": "ok"}), \
            patch.object(server, "_graph_health_check", return_value={"status": "ok"}), \
            patch.object(server, "_get_cost_digest_s3", return_value=stub):
        return json.loads(_run(server._connection_health({}))[0].text)


def test_digest_hit_is_compact_and_reads_expected_object():
    server = _server()
    stub = _StubS3(_DIGEST)
    payload = _health(server, stub)

    assert stub.calls == [("jreese-net", "governance/cost-digest/latest.json")]
    digest = payload["cost_digest"]
    assert digest["status"] == "ok"
    assert digest["date"] == "2026-10-18"
    assert digest["prior_day_spend"] == 12.34
    assert digest["median_7d"] == 10.0
    assert digest["regression"] is True
    assert len(digest["top_deltas"]) == 5
    assert digest["feed_publisher_invocations"] == 1234
    assert digest["invalidation_paths_mtd"] == 56
    assert "raw_ce_response" not in digest
    assert server.COST_DIGEST_REGION == "us-west-1"


def test_cache_reuse_within_ttl_and_refresh_after_ttl():
    server = _server()
    stub = _StubS3(_DIGEST)
    clock = {"t": 1000.0}
    with patch.object(server.time, "monotonic", side_effect=lambda: clock["t"]):
        _health(server, stub)
        clock["t"] += 3599
        _health(server, stub)
        assert len(stub.calls) == 1  # reused within the 1h TTL

        clock["t"] += 2  # now past 3600s
        stub.payload = dict(_DIGEST, prior_day_spend=99.0)
        payload = _health(server, stub)
    assert len(stub.calls) == 2
    assert payload["cost_digest"]["prior_day_spend"] == 99.0


def test_missing_object_is_unavailable_and_connection_health_succeeds():
    server = _server()
    payload = _health(server, _StubS3(error=_ClientError("NoSuchKey")))

    assert payload["dynamodb"] == "ok"
    assert payload["cost_digest"] == {"status": "unavailable", "reason": "not_found"}


def test_unreadable_object_never_raises():
    server = _server()
    assert _health(server, _StubS3(error=_ClientError("AccessDenied")))["cost_digest"] == {
        "status": "unavailable", "reason": "read_error:AccessDenied",
    }
    server = _server()
    assert _health(server, _StubS3(payload="{not json"))["cost_digest"]["reason"] == "invalid_json"
    server = _server()
    assert _health(server, _StubS3(payload=[1, 2]))["cost_digest"]["reason"] == "invalid_digest_shape"


def test_unavailable_is_retried_after_short_ttl_not_cached_for_an_hour():
    server = _server()
    stub = _StubS3(error=_ClientError("NoSuchKey"))
    clock = {"t": 5000.0}
    with patch.object(server.time, "monotonic", side_effect=lambda: clock["t"]):
        _health(server, stub)
        clock["t"] += 30
        _health(server, stub)
        assert len(stub.calls) == 1
        clock["t"] += 31
        stub.error, stub.payload = None, _DIGEST
        payload = _health(server, stub)
    assert len(stub.calls) == 2
    assert payload["cost_digest"]["status"] == "ok"


def test_no_cost_explorer_on_mcp_path():
    source = open(_load_server(ENCELADUS_MCP_INTERFACE_MODE="code").__file__, encoding="utf-8").read()
    assert 'client("ce"' not in source and "get_cost_and_usage" not in source
