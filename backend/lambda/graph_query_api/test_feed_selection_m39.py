"""Unit tests for ENC-TSK-M39 — feed_selection out-of-band action.

feed_query is not VPC-attached to the OpenSearch domain, so it invokes
graph_query_api directly (action='feed_selection') as a selection-tier proxy
instead. These tests exercise `_handle_feed_selection` and its dispatch entry
in `lambda_handler`, matching the direct-invoke action conventions in
test_close_wave_j90.py.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


class TestHandleFeedSelection(unittest.TestCase):
    def test_missing_project_ids_returns_error(self):
        result = lf._handle_feed_selection({"caps": {"task": 10}})
        self.assertFalse(result["ok"])
        self.assertIn("project_ids", result["error"])

    def test_missing_caps_returns_error(self):
        result = lf._handle_feed_selection({"project_ids": ["enceladus"]})
        self.assertFalse(result["ok"])
        self.assertIn("caps", result["error"])

    def test_delegates_to_opensearch_keyword_and_returns_selection(self):
        with mock.patch.object(
            lf.opensearch_keyword,
            "feed_selection_msearch",
            return_value=({"enceladus#task": ["ENC-TSK-001"]}, None),
        ) as fn:
            result = lf._handle_feed_selection({
                "project_ids": ["enceladus"],
                "caps": {"task": 100},
            })
        fn.assert_called_once_with(["enceladus"], {"task": 100})
        self.assertTrue(result["ok"])
        self.assertEqual(result["selection"], {"enceladus#task": ["ENC-TSK-001"]})

    def test_propagates_error_from_opensearch_keyword(self):
        with mock.patch.object(
            lf.opensearch_keyword,
            "feed_selection_msearch",
            return_value=({}, "opensearch_not_configured"),
        ):
            result = lf._handle_feed_selection({
                "project_ids": ["enceladus"],
                "caps": {"task": 100},
            })
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "opensearch_not_configured")


class TestDispatch(unittest.TestCase):
    def test_feed_selection_action_routes_to_handler(self):
        with mock.patch.object(lf, "_handle_feed_selection", return_value={"ok": True}) as h:
            result = lf.lambda_handler(
                {"action": "feed_selection", "project_ids": ["enceladus"], "caps": {"task": 10}}, None
            )
        h.assert_called_once()
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
