"""Unit tests for ENC-TSK-K43 (B66 Ph5) Fiedler lambda-2 GraphHealth metric.

Exercises graph_health_metric.py in isolation (no real AWS, no live AuraDB):
the FTR-088 _query_laplacian dependency is dependency-injected as a plain
function, so these tests never import lambda_function.py (no Neo4j driver /
scipy / boto3 required for the fake-driver-free tests) and reuse the same
fake-eigenvalue-result-injection pattern for the handler-level tests.

Covers:
  - AC-1: lambda2 == eigenvalues[1] resolved from a _query_laplacian-shaped
    result and assembled into a well-formed CloudWatch MetricDatum in the
    Enceladus/GraphHealth namespace.
  - AC-2: ISS-465 GDS cost-kill -- compute_fiedler_value only ever calls the
    injected query_laplacian_fn (the FTR-088 CSR/Fiedler path); it never
    imports or references gds.graph.project / an AGA session / any standing
    projection helper.
  - Batching: publish_metric_data batches at <= 20 MetricDatum per
    put_metric_data call.
  - Degradation: a <2-eigenvalue or error result from query_laplacian_fn
    yields {"ok": False, ...} rather than raising, and a failed project is
    excluded from metric_data (no partial datapoint published) while other
    projects still succeed.
  - handle_publish_graph_health: action-dispatch entrypoint contract (driver
    unavailable -> ok=False without touching cloudwatch; happy path calls
    put_metric_data exactly once for a single default project).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import graph_health_metric as ghm  # noqa: E402


def _laplacian_result(eigenvalues, *, n=10, edge_count=9, eig_method="eigsh_SA", normalization="combinatorial"):
    return {
        "eigenvalues": eigenvalues,
        "laplacian": {
            "n": n,
            "edge_count": edge_count,
            "eig_method": eig_method,
            "normalization": normalization,
        },
    }


def _fake_query_laplacian_fn(eigenvalues_by_project, calls_log=None):
    """Build a query_laplacian_fn stand-in keyed by project_id. Records
    (driver, project_id, params) tuples into calls_log when supplied, so
    tests can assert exactly what compute_fiedler_value passed through."""
    def _fn(driver, project_id, params):
        if calls_log is not None:
            calls_log.append((driver, project_id, dict(params)))
        spec = eigenvalues_by_project.get(project_id)
        if spec is None:
            return {"error": f"no fixture for project_id={project_id}"}
        if isinstance(spec, dict) and "error" in spec:
            return spec
        return _laplacian_result(spec)
    return _fn


class TestComputeFiedlerValue(unittest.TestCase):
    def test_lambda2_is_eigenvalues_index_1_ac1(self):
        calls = []
        fn = _fake_query_laplacian_fn({"enceladus": [0.0, 0.42, 1.1]}, calls_log=calls)
        result = ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=fn)
        self.assertTrue(result["ok"])
        self.assertEqual(result["lambda2"], 0.42)
        self.assertEqual(result["lambda0"], 0.0)
        self.assertEqual(result["project_id"], "enceladus")
        self.assertEqual(result["n"], 10)
        self.assertEqual(result["eig_method"], "eigsh_SA")
        # AC-2 / ISS-465: only the injected FTR-088 path was called -- one call,
        # requesting k>=2 (so the Fiedler index-1 eigenpair is always resolvable).
        self.assertEqual(len(calls), 1)
        _driver, _pid, params = calls[0]
        self.assertGreaterEqual(params["k"], 2)
        self.assertEqual(params["normalization"], "combinatorial")

    def test_k_is_floored_at_2_even_when_caller_requests_1(self):
        calls = []
        fn = _fake_query_laplacian_fn({"enceladus": [0.0, 0.1]}, calls_log=calls)
        ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=fn, k=1)
        self.assertEqual(calls[0][2]["k"], 2)

    def test_propagates_query_laplacian_error(self):
        fn = _fake_query_laplacian_fn({"enceladus": {"error": "Laplacian requires at least 2 vertices"}})
        result = ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=fn)
        self.assertFalse(result["ok"])
        self.assertIn("at least 2 vertices", result["error"])

    def test_degrades_on_too_few_eigenvalues(self):
        # A pathological/degenerate response with only the trivial eigenpair.
        fn = _fake_query_laplacian_fn({"enceladus": [0.0]})
        result = ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=fn)
        self.assertFalse(result["ok"])
        self.assertIn("lambda2", result["error"])

    def test_degenerate_lambda2_at_capped_sample_size_is_rejected_ac2(self):
        # ENC-ISS-554: eigenvalues[1] == 0.0 with n == limit means the
        # LAPLACIAN_MAX_VERTICES cap was hit -- the sample is very likely a
        # non-representative induced-subgraph artifact, not a genuine
        # full-graph disconnection reading. Must be ok=False, never a
        # confident zero.
        # Use a raw fn (not the shared fixture helper) so laplacian.n can be
        # pinned to the requested limit, exercising the "capped" branch.
        def _fn(driver, project_id, params):
            return {
                "eigenvalues": [0.0, 0.0, 0.1],
                "laplacian": {"n": params["limit"], "edge_count": 3, "eig_method": "eigsh_SA", "normalization": "combinatorial"},
            }
        result = ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=_fn, limit=500)
        self.assertFalse(result["ok"])
        self.assertEqual(result["invalid_reason"], "sample_capped_degenerate")
        self.assertEqual(result["lambda2_raw"], 0.0)
        self.assertNotIn("lambda2", result)  # never publishable as a reading

    def test_degenerate_lambda2_below_cap_flags_genuine_disconnection_ac2(self):
        # n < limit means the full vertex set was captured (no truncation);
        # a degenerate lambda2 here is a real disconnection signal, still
        # never published as ok=True, but distinguishable in the reason.
        def _fn(driver, project_id, params):
            return {
                "eigenvalues": [0.0, 0.0, 0.2],
                "laplacian": {"n": 12, "edge_count": 10, "eig_method": "dense_eigh", "normalization": "combinatorial"},
            }
        result = ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=_fn, limit=500)
        self.assertFalse(result["ok"])
        self.assertEqual(result["invalid_reason"], "genuine_disconnection_suspected")

    def test_positive_lambda2_still_succeeds_ac2(self):
        # Sanity check: the epsilon gate does not reject legitimate positive
        # readings.
        fn = _fake_query_laplacian_fn({"enceladus": [0.0, 0.42, 1.1]})
        result = ghm.compute_fiedler_value(object(), "enceladus", query_laplacian_fn=fn)
        self.assertTrue(result["ok"])
        self.assertEqual(result["lambda2"], 0.42)

    def test_never_touches_gds_projection_helpers(self):
        # AC-2 hard gate: the module's *code* (not its explanatory docstrings/
        # comments) must never invoke a GDS/AGA symbol -- only the injected
        # FTR-088 query_laplacian_fn. Strip comments/docstring-only lines so
        # this checks executable statements, not prose that documents the
        # deliberate absence of those calls.
        import ast
        import inspect
        src = inspect.getsource(ghm)
        tree = ast.parse(src)
        # Collect every Attribute/Call dotted-name actually used in code (not
        # string literals/docstrings, which ast.walk over Constant nodes would
        # also catch and produce false positives against this module's prose).
        used_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                parts = []
                cur = node
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(cur.id)
                used_names.add(".".join(reversed(parts)))
            elif isinstance(node, ast.Name):
                used_names.add(node.id)
        forbidden_substrings = ("gds", "AGA", "_refresh_standing_projection", "standing_projection")
        for name in used_names:
            lowered = name.lower()
            for forbidden in forbidden_substrings:
                self.assertNotIn(
                    forbidden.lower(), lowered,
                    f"graph_health_metric.py code references {name!r} containing forbidden {forbidden!r} (ISS-465)",
                )


class TestMetricAssemblyAndPublish(unittest.TestCase):
    def test_build_fiedler_metric_datum_shape(self):
        fiedler = {"ok": True, "lambda2": 0.37, "project_id": "enceladus"}
        datum = ghm.build_fiedler_metric_datum(fiedler)
        self.assertEqual(datum["MetricName"], ghm.FIEDLER_METRIC_NAME)
        self.assertEqual(datum["Value"], 0.37)
        self.assertEqual(datum["Dimensions"], [{"Name": "ProjectId", "Value": "enceladus"}])
        self.assertIn("Timestamp", datum)

    def test_publish_metric_data_batches_at_20(self):
        calls = []

        class _FakeCW:
            def put_metric_data(self, **kwargs):
                calls.append(kwargs)

        metric_data = [{"MetricName": "x", "Value": float(i)} for i in range(45)]
        published = ghm.publish_metric_data(_FakeCW(), metric_data)
        self.assertEqual(published, 45)
        self.assertEqual(len(calls), 3)  # 20 + 20 + 5
        self.assertEqual(len(calls[0]["MetricData"]), 20)
        self.assertEqual(len(calls[1]["MetricData"]), 20)
        self.assertEqual(len(calls[2]["MetricData"]), 5)
        for call in calls:
            self.assertEqual(call["Namespace"], ghm.GRAPH_HEALTH_NAMESPACE)

    def test_publish_metric_data_empty_is_noop(self):
        class _FakeCW:
            def put_metric_data(self, **kwargs):
                raise AssertionError("must not call put_metric_data for empty input")

        self.assertEqual(ghm.publish_metric_data(_FakeCW(), []), 0)


class TestRunPublishGraphHealth(unittest.TestCase):
    def test_single_project_happy_path(self):
        class _FakeCW:
            def __init__(self):
                self.calls = []

            def put_metric_data(self, **kwargs):
                self.calls.append(kwargs)

        cw = _FakeCW()
        fn = _fake_query_laplacian_fn({"enceladus": [0.0, 0.55, 1.2]})
        out = ghm.run_publish_graph_health(object(), cw, query_laplacian_fn=fn, project_ids=["enceladus"])
        self.assertTrue(out["ok"])
        self.assertEqual(out["published"], 1)
        self.assertEqual(out["namespace"], ghm.GRAPH_HEALTH_NAMESPACE)
        self.assertEqual(len(cw.calls), 1)
        self.assertEqual(cw.calls[0]["MetricData"][0]["Value"], 0.55)

    def test_partial_failure_publishes_only_successful_projects(self):
        class _FakeCW:
            def __init__(self):
                self.calls = []

            def put_metric_data(self, **kwargs):
                self.calls.append(kwargs)

        cw = _FakeCW()
        fn = _fake_query_laplacian_fn({
            "enceladus": [0.0, 0.3, 0.9],
            "broken-project": {"error": "boom"},
        })
        out = ghm.run_publish_graph_health(
            object(), cw, query_laplacian_fn=fn, project_ids=["enceladus", "broken-project"],
        )
        self.assertTrue(out["ok"])  # at least one datapoint published
        self.assertEqual(out["published"], 1)
        self.assertEqual(len(out["results"]), 2)
        ok_flags = sorted(r["ok"] for r in out["results"])
        self.assertEqual(ok_flags, [False, True])

    def test_all_projects_fail_yields_ok_false_zero_published(self):
        class _FakeCW:
            def put_metric_data(self, **kwargs):
                raise AssertionError("must not publish when nothing succeeded")

        fn = _fake_query_laplacian_fn({"enceladus": {"error": "boom"}})
        out = ghm.run_publish_graph_health(object(), _FakeCW(), query_laplacian_fn=fn, project_ids=["enceladus"])
        self.assertFalse(out["ok"])
        self.assertEqual(out["published"], 0)


class TestHandlePublishGraphHealth(unittest.TestCase):
    def test_driver_unavailable_short_circuits_before_cloudwatch(self):
        cw_called = []

        def _get_cw():
            cw_called.append(True)
            return object()

        out = ghm.handle_publish_graph_health(
            {"action": "publish_graph_health"},
            get_driver_fn=lambda: None,
            get_cloudwatch_fn=_get_cw,
            query_laplacian_fn=lambda *a, **k: {"error": "unreachable"},
        )
        self.assertFalse(out["ok"])
        self.assertIn("driver", out["error"])
        self.assertEqual(cw_called, [])  # never even fetched a CloudWatch client

    def test_happy_path_single_default_project(self):
        class _FakeCW:
            def __init__(self):
                self.calls = []

            def put_metric_data(self, **kwargs):
                self.calls.append(kwargs)

        cw = _FakeCW()
        fn = _fake_query_laplacian_fn({ghm.DEFAULT_PROJECT_ID: [0.0, 0.61, 1.4]})
        out = ghm.handle_publish_graph_health(
            {"action": "publish_graph_health"},
            get_driver_fn=lambda: object(),
            get_cloudwatch_fn=lambda: cw,
            query_laplacian_fn=fn,
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out["published"], 1)
        self.assertEqual(len(cw.calls), 1)

    def test_explicit_project_id_override(self):
        calls = []
        fn = _fake_query_laplacian_fn({"other-project": [0.0, 0.2]}, calls_log=calls)

        class _FakeCW:
            def put_metric_data(self, **kwargs):
                pass

        ghm.handle_publish_graph_health(
            {"action": "publish_graph_health", "project_id": "other-project"},
            get_driver_fn=lambda: object(),
            get_cloudwatch_fn=lambda: _FakeCW(),
            query_laplacian_fn=fn,
        )
        self.assertEqual(calls[0][1], "other-project")


if __name__ == "__main__":
    unittest.main()
