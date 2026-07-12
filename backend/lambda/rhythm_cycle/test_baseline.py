"""Unit tests for baseline.py (ENC-TSK-N26).

Network-free / AWS-free: boto3 (dynamodb) and http_client.get_json are always
mocked. Exercises the happy path for each of the four artifact classes plus
the honest-degradation path when a dependency is unreachable or unconfigured.
"""

from __future__ import annotations

import os
import sys
import unittest
from decimal import Decimal
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import baseline  # noqa: E402
import config  # noqa: E402
import lambda_function  # noqa: E402


class PercolationExportTests(unittest.TestCase):
    def test_exports_latest_row_and_cleans_decimals(self):
        rows = [
            {"pk": "date#2026-07-10", "computed_at": "2026-07-10T00:00:00Z", "mean_degree": Decimal("4.5")},
            {"pk": "date#2026-07-11", "computed_at": "2026-07-11T00:00:00Z", "mean_degree": Decimal("4.75"), "edge_count": Decimal("120")},
        ]
        mock_table = mock.Mock()
        mock_table.scan.return_value = {"Items": rows}
        mock_resource = mock.Mock()
        mock_resource.Table.return_value = mock_table

        with mock.patch.object(baseline.boto3, "resource", return_value=mock_resource):
            result = baseline.capture_percolation_export()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["row_pk"], "date#2026-07-11")
        self.assertIsInstance(result["exported_row"]["mean_degree"], float)
        self.assertIsInstance(result["exported_row"]["edge_count"], int)

    def test_no_rows_is_unavailable_not_a_failure(self):
        mock_table = mock.Mock()
        mock_table.scan.return_value = {"Items": []}
        mock_resource = mock.Mock()
        mock_resource.Table.return_value = mock_table

        with mock.patch.object(baseline.boto3, "resource", return_value=mock_resource):
            result = baseline.capture_percolation_export()

        self.assertEqual(result["status"], "unavailable")
        self.assertIn("reason", result)

    def test_ddb_error_is_captured_not_raised(self):
        with mock.patch.object(baseline.boto3, "resource", side_effect=RuntimeError("access denied")):
            result = baseline.capture_percolation_export()

        self.assertEqual(result["status"], "unavailable")
        self.assertIn("access denied", result["reason"])


class RetrievalQualityTests(unittest.TestCase):
    def test_unconfigured_tracker_base_is_unavailable(self):
        with mock.patch.object(baseline, "TRACKER_API_BASE", ""):
            result = baseline.capture_retrieval_quality()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["query_count"], 0)

    def test_runs_fixed_query_set_and_records_latency(self):
        def fake_get_json(url, params=None):
            if params is None:
                # record_id lookup
                return {"success": True, "record": {"item_id": "ENC-TSK-N26"}}
            return {"success": True, "records": [{"item_id": "ENC-TSK-N08", "title": "baseline capture tooling", "description": ""}]}

        with mock.patch.object(baseline, "TRACKER_API_BASE", "https://example.invalid/api/v1/tracker"):
            with mock.patch.object(baseline, "get_json", side_effect=fake_get_json):
                result = baseline.capture_retrieval_quality()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["query_count"], len(baseline.FIXED_QUERY_SET))
        self.assertTrue(all("latency_ms" in q for q in result["queries"]))

    def test_query_error_is_captured_per_query(self):
        with mock.patch.object(baseline, "TRACKER_API_BASE", "https://example.invalid/api/v1/tracker"):
            with mock.patch.object(baseline, "get_json", side_effect=RuntimeError("HTTP 500")):
                result = baseline.capture_retrieval_quality()

        self.assertEqual(result["status"], "ok")  # surface reachable; individual queries degrade
        self.assertTrue(all(q["found"] is False for q in result["queries"]))
        self.assertTrue(all("error" in q for q in result["queries"]))


class LessonCitationRateTests(unittest.TestCase):
    def test_unconfigured_is_unavailable(self):
        with mock.patch.object(baseline, "TRACKER_API_BASE", ""):
            result = baseline.capture_lesson_citation_rate()
        self.assertEqual(result["status"], "unavailable")

    def test_computes_proxy_rate_and_formula(self):
        lessons = [
            {"item_id": "ENC-LSN-001", "related_task_ids": ["ENC-TSK-1"]},
            {"item_id": "ENC-LSN-002", "related_task_ids": [], "related_issue_ids": []},
        ]
        with mock.patch.object(baseline, "TRACKER_API_BASE", "https://example.invalid/api/v1/tracker"):
            with mock.patch.object(baseline, "get_json", return_value={"success": True, "records": lessons}):
                result = baseline.capture_lesson_citation_rate()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["lesson_count"], 2)
        self.assertEqual(result["lessons_with_outbound_refs"], 1)
        self.assertAlmostEqual(result["proxy_citation_rate"], 0.5)
        self.assertIn("formula", result)

    def test_zero_lessons_no_division_by_zero(self):
        with mock.patch.object(baseline, "TRACKER_API_BASE", "https://example.invalid/api/v1/tracker"):
            with mock.patch.object(baseline, "get_json", return_value={"success": True, "records": []}):
                result = baseline.capture_lesson_citation_rate()

        self.assertEqual(result["lesson_count"], 0)
        self.assertEqual(result["proxy_citation_rate"], 0.0)


class CorpusInvariantsTests(unittest.TestCase):
    def test_reuses_percolation_export_for_graph_metrics(self):
        percolation_export = {
            "status": "ok",
            "row_pk": "date#2026-07-11",
            "exported_row": {"edge_count": 500, "mean_degree": 3.2, "mean_degree_sq": 12.4, "node_count": 300},
        }
        with mock.patch.object(baseline, "TRACKER_API_BASE", ""):
            invariants = baseline.capture_corpus_invariants(percolation_export)

        self.assertEqual(invariants["M_edges"], 500)
        self.assertEqual(invariants["mean_degree"], 3.2)
        self.assertEqual(invariants["second_moment_mean_degree_sq"], 12.4)
        self.assertIsNone(invariants["modularity_Q"])
        self.assertIsNone(invariants["hot_tier_fraction"])
        self.assertIn("not computable", invariants["modularity_Q_note"])
        self.assertIn("not computable", invariants["hot_tier_fraction_note"])

    def test_marks_graph_metrics_unavailable_when_percolation_export_failed(self):
        percolation_export = {"status": "unavailable", "reason": "no rows found"}
        with mock.patch.object(baseline, "TRACKER_API_BASE", ""):
            invariants = baseline.capture_corpus_invariants(percolation_export)

        self.assertIsNone(invariants["M_edges"])
        self.assertIn("no rows found", invariants["graph_metrics_source"])

    def test_n_lower_bound_flags_capped_types(self):
        percolation_export = {"status": "unavailable", "reason": "n/a"}
        capped_records = [{"item_id": f"ENC-TSK-{i}"} for i in range(baseline._LIST_PAGE_SIZE)]

        with mock.patch.object(baseline, "TRACKER_API_BASE", "https://example.invalid/api/v1/tracker"):
            with mock.patch.object(baseline, "get_json", return_value={"success": True, "records": capped_records}):
                invariants = baseline.capture_corpus_invariants(percolation_export)

        self.assertEqual(invariants["N_lower_bound_by_type"]["task"], baseline._LIST_PAGE_SIZE)
        self.assertIn("task", invariants["N_note"])


class RunBaselineCaptureTests(unittest.TestCase):
    @mock.patch("baseline.write_artifact")
    @mock.patch("baseline.capture_corpus_invariants")
    @mock.patch("baseline.capture_lesson_citation_rate")
    @mock.patch("baseline.capture_retrieval_quality")
    @mock.patch("baseline.capture_percolation_export")
    def test_writes_single_artifact_with_all_four_classes(
        self, perc, retrieval, lessons, invariants, write_artifact
    ):
        perc.return_value = {"status": "ok"}
        retrieval.return_value = {"status": "ok"}
        lessons.return_value = {"status": "ok"}
        invariants.return_value = {"modularity_Q": None}
        write_artifact.return_value = {"timestamped_key": "k1", "latest_key": "baseline/latest.json", "bytes": "42"}

        snapshot = baseline.run_baseline_capture()

        write_artifact.assert_called_once()
        self.assertEqual(write_artifact.call_args[0][0], "baseline")
        self.assertEqual(snapshot["artifact_classes_ok"], 3)
        self.assertEqual(snapshot["latest_key"], "baseline/latest.json")
        self.assertIn("corpus_invariants", snapshot)

    @mock.patch("baseline.write_artifact")
    @mock.patch("baseline.capture_corpus_invariants")
    @mock.patch("baseline.capture_lesson_citation_rate")
    @mock.patch("baseline.capture_retrieval_quality")
    @mock.patch("baseline.capture_percolation_export")
    def test_partial_capture_counts_only_ok_classes(
        self, perc, retrieval, lessons, invariants, write_artifact
    ):
        perc.return_value = {"status": "unavailable", "reason": "no rows"}
        retrieval.return_value = {"status": "ok"}
        lessons.return_value = {"status": "unavailable", "reason": "TRACKER_API_BASE not configured"}
        invariants.return_value = {}
        write_artifact.return_value = {"timestamped_key": "k1", "latest_key": "baseline/latest.json", "bytes": "10"}

        snapshot = baseline.run_baseline_capture()

        self.assertEqual(snapshot["artifact_classes_ok"], 1)


class LambdaRoutingTests(unittest.TestCase):
    def test_baseline_capture_tier_is_registered(self):
        self.assertIn("baseline_capture", lambda_function.TIER_HANDLERS)
        self.assertIs(lambda_function.TIER_HANDLERS["baseline_capture"], baseline.run_baseline_capture)

    def test_baseline_capture_has_no_predecessor(self):
        # Not part of the scheduled harmonic chain -- no predecessor artifact read.
        self.assertNotIn("baseline_capture", config.TIER_PREDECESSOR)

    def test_handler_routes_baseline_capture_tier(self):
        fake_handler = mock.Mock(return_value={"artifact_classes_ok": 3})
        with mock.patch.dict(lambda_function.TIER_HANDLERS, {"baseline_capture": fake_handler}):
            resp = lambda_function.lambda_handler({"tier": "baseline_capture"}, None)
        self.assertEqual(resp["statusCode"], 200)
        fake_handler.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
