"""Unit tests for ENC-TSK-K43 (B66 Ph5) real Fiedler lambda2 wiring in
graph_health_metrics.

Prior to K43, FiedlerAlgebraicConnectivity was a placeholder aliased to
GraphEdgeDensity (documented in the ENC-TSK-C10 module docstring as a stopgap
while GDS was unavailable). K43 replaces it with the REAL Fiedler lambda2 via
a cross-Lambda invoke into devops-graph-query-api's action='publish_graph_health'
entrypoint (the FTR-088 CSR/Fiedler path, ISS-465-compliant -- no GDS
projection).

ENC-ISS-554: the GraphEdgeDensity-proxy fallback on invoke failure was
removed -- a different metric's value silently relabeled as lambda2 is a
confident-lie pattern in its own right. FiedlerAlgebraicConnectivity is now
simply omitted from the published batch on any failure (invoke error, or the
estimator's own explicit rejection of a degenerate lambda2).

Covers:
  - _fetch_real_fiedler_value: successful invoke parses the nested
    publish_graph_health response and extracts lambda2 for the right
    project_id; a FunctionError, malformed payload, or no matching
    project_id result all degrade to {"ok": False, ...} rather than raising.
  - _compute_metrics: FiedlerAlgebraicConnectivity carries the REAL lambda2
    on a successful invoke (and is NOT equal to the GraphEdgeDensity proxy
    when the two values differ), and is omitted entirely (not a proxy
    substitute) when the invoke fails or the estimator rejects a degenerate
    value -- never blocks GraphNodeCount/GraphEdgeDensity/OrphanNodeRatio.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# dedup_convergence is packaged in via .build_extras at deploy time; for local
# tests resolve it from its canonical owner (graph_query_api), appended LAST so
# it never shadows this dir's lambda_function.
sys.path.append(str(_HERE.parent / "graph_query_api"))
sys.path.insert(0, str(_HERE))

import lambda_function as lf  # noqa: E402


class _FakePayload:
    def __init__(self, body: dict):
        self._raw = json.dumps(body).encode("utf-8")

    def read(self):
        return self._raw


class _FakeLambdaClient:
    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise_exc = raise_exc
        self.invoke_calls = []

    def invoke(self, **kwargs):
        self.invoke_calls.append(kwargs)
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._response


def _publish_graph_health_response(lambda2: float, project_id: str = "enceladus", ok: bool = True):
    body = {
        "ok": ok,
        "published": 1 if ok else 0,
        "namespace": "Enceladus/GraphHealth",
        "results": [{"ok": ok, "lambda2": lambda2, "project_id": project_id}],
    }
    return {"Payload": _FakePayload(body)}


class FetchRealFiedlerValueTests(unittest.TestCase):
    def setUp(self):
        lf._lambda_client = None  # reset lazy singleton between tests

    def test_successful_invoke_extracts_lambda2(self):
        lf._get_lambda_client = lambda: _FakeLambdaClient(_publish_graph_health_response(0.42))
        result = lf._fetch_real_fiedler_value()
        self.assertEqual(result, {"ok": True, "lambda2": 0.42})

    def test_invoke_payload_shape(self):
        fake = _FakeLambdaClient(_publish_graph_health_response(0.1))
        lf._get_lambda_client = lambda: fake
        lf._fetch_real_fiedler_value()
        self.assertEqual(len(fake.invoke_calls), 1)
        call = fake.invoke_calls[0]
        self.assertEqual(call["FunctionName"], lf.GRAPH_QUERY_API_LAMBDA_NAME)
        self.assertEqual(call["InvocationType"], "RequestResponse")
        payload = json.loads(call["Payload"].decode("utf-8"))
        self.assertEqual(payload["action"], "publish_graph_health")
        self.assertEqual(payload["project_id"], lf.PROJECT_ID)

    def test_function_error_degrades_gracefully(self):
        response = _publish_graph_health_response(0.5)
        response["FunctionError"] = "Unhandled"
        lf._get_lambda_client = lambda: _FakeLambdaClient(response)
        result = lf._fetch_real_fiedler_value()
        self.assertFalse(result["ok"])
        self.assertIn("FunctionError", result["error"])

    def test_no_matching_project_result_degrades_gracefully(self):
        lf._get_lambda_client = lambda: _FakeLambdaClient(
            _publish_graph_health_response(0.3, project_id="other-project")
        )
        result = lf._fetch_real_fiedler_value()
        self.assertFalse(result["ok"])

    def test_all_projects_failed_degrades_gracefully(self):
        lf._get_lambda_client = lambda: _FakeLambdaClient(
            _publish_graph_health_response(0.3, ok=False)
        )
        result = lf._fetch_real_fiedler_value()
        self.assertFalse(result["ok"])

    def test_exception_during_invoke_degrades_gracefully(self):
        lf._get_lambda_client = lambda: _FakeLambdaClient(raise_exc=RuntimeError("network unreachable"))
        result = lf._fetch_real_fiedler_value()
        self.assertFalse(result["ok"])
        self.assertIn("network unreachable", result["error"])

    def test_malformed_payload_degrades_gracefully(self):
        class _BadPayload:
            def read(self):
                return b"{not-json"

        lf._get_lambda_client = lambda: _FakeLambdaClient({"Payload": _BadPayload()})
        result = lf._fetch_real_fiedler_value()
        self.assertFalse(result["ok"])


class _Sess:
    def __init__(self, driver):
        self._d = driver

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        if "orphans" in cypher:
            return _Single({"orphans": self._d.orphan_count})
        if "count(n)" in cypher:
            return _Single({"total": self._d.node_count})
        if "count(r)" in cypher:
            return _Single({"total": self._d.edge_count})
        return _Single({})


class _Single:
    def __init__(self, d):
        self._d = d

    def single(self):
        return self._d


class _Driver:
    def __init__(self, node_count=10, edge_count=20, orphan_count=1):
        self.node_count = node_count
        self.edge_count = edge_count
        self.orphan_count = orphan_count

    def session(self):
        return _Sess(self)


class ComputeMetricsTests(unittest.TestCase):
    def setUp(self):
        lf._lambda_client = None

    def test_fiedler_algebraic_connectivity_uses_real_value_on_success(self):
        driver = _Driver(node_count=10, edge_count=20, orphan_count=1)  # GraphEdgeDensity = 2.0
        lf._fetch_real_fiedler_value = lambda: {"ok": True, "lambda2": 0.37}
        metrics = lf._compute_metrics(driver)
        self.assertEqual(metrics["FiedlerAlgebraicConnectivity"], 0.37)
        self.assertEqual(metrics["GraphEdgeDensity"], 2.0)
        # The real value must differ from (not silently equal) the old proxy,
        # proving this is no longer the GraphEdgeDensity alias.
        self.assertNotEqual(metrics["FiedlerAlgebraicConnectivity"], metrics["GraphEdgeDensity"])

    def test_fiedler_algebraic_connectivity_omitted_on_failure(self):
        # ENC-ISS-554: no more silent GraphEdgeDensity-under-Fiedler-name
        # substitution -- a failed/degenerate real-lambda2 fetch means the
        # metric is simply absent from this interval's batch (silence beats
        # a confident-but-mislabeled reading), and the other metrics are
        # still published normally.
        driver = _Driver(node_count=10, edge_count=20, orphan_count=1)  # GraphEdgeDensity = 2.0
        lf._fetch_real_fiedler_value = lambda: {"ok": False, "error": "graph_query_api unavailable"}
        metrics = lf._compute_metrics(driver)
        self.assertNotIn("FiedlerAlgebraicConnectivity", metrics)
        self.assertEqual(metrics["GraphEdgeDensity"], 2.0)

    def test_fiedler_algebraic_connectivity_omitted_on_estimator_rejected_degenerate_value(self):
        # The estimator itself (graph_query_api.compute_fiedler_value) now
        # rejects a degenerate lambda2 as ok=False with an invalid_reason
        # rather than ok=True/lambda2=0.0 -- confirm that flows through here
        # as an omission too, not a published zero.
        driver = _Driver(node_count=10, edge_count=20, orphan_count=1)
        lf._fetch_real_fiedler_value = lambda: {
            "ok": False,
            "error": "lambda2=0.0 is degenerate for an induced subgraph capped at n=500 vertices (limit=500)",
            "invalid_reason": "sample_capped_degenerate",
        }
        metrics = lf._compute_metrics(driver)
        self.assertNotIn("FiedlerAlgebraicConnectivity", metrics)

    def test_other_metrics_unaffected_by_fiedler_fetch(self):
        driver = _Driver(node_count=50, edge_count=75, orphan_count=3)
        lf._fetch_real_fiedler_value = lambda: {"ok": True, "lambda2": 0.15}
        metrics = lf._compute_metrics(driver)
        self.assertEqual(metrics["GraphNodeCount"], 50.0)
        self.assertEqual(metrics["GraphEdgeDensity"], 1.5)
        self.assertEqual(metrics["OrphanNodeRatio"], 0.06)


if __name__ == "__main__":
    unittest.main()
