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
        fn.assert_called_once_with(["enceladus"], {"task": 100}, page_size=None, before=None)
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


class TestFeedSelectionPageCapM76(unittest.TestCase):
    """ENC-TSK-M76: upstream page-cap mode threads page_size + before into the
    selection tier and returns ranked {id, updated_at} dicts so feed_query can
    hydrate only the page."""

    def test_handler_passes_page_size_and_before_through(self):
        with mock.patch.object(
            lf.opensearch_keyword,
            "feed_selection_msearch",
            return_value=({"enceladus#task": [{"id": "ENC-TSK-001", "updated_at": "2026-07-10T00:00:00Z"}]}, None),
        ) as fn:
            result = lf._handle_feed_selection({
                "project_ids": ["enceladus"],
                "caps": {"task": 100},
                "page_size": 75,
                "before": "2026-07-11T00:00:00Z",
            })
        fn.assert_called_once_with(
            ["enceladus"], {"task": 100}, page_size=75, before="2026-07-11T00:00:00Z"
        )
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["selection"],
            {"enceladus#task": [{"id": "ENC-TSK-001", "updated_at": "2026-07-10T00:00:00Z"}]},
        )

    def test_handler_ignores_non_positive_page_size(self):
        with mock.patch.object(
            lf.opensearch_keyword, "feed_selection_msearch", return_value=({}, None)
        ) as fn:
            lf._handle_feed_selection({"project_ids": ["enceladus"], "caps": {"task": 5}, "page_size": 0})
        # page_size<=0 falls back to legacy mode (None).
        fn.assert_called_once_with(["enceladus"], {"task": 5}, page_size=None, before=None)


class TestFeedSelectionMsearchPageCapM76(unittest.TestCase):
    """The msearch builder itself in page-cap mode."""

    def _fake_responses(self, per_pair):
        # one sub-response per (project,type) pair; per_pair maps rtype -> [(id, updated_at)]
        import opensearch_keyword as ok
        return per_pair, ok

    def test_page_mode_fetches_page_size_plus_one_with_updated_at_and_range(self):
        import opensearch_keyword as ok
        captured = {}

        def fake_request(method, path, body=None):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body
            # Respond with one hit per pair (single project, single type here).
            return 200, {"responses": [
                {"hits": {"hits": [
                    {"_id": "enceladus#task#ENC-TSK-001", "_source": {"updated_at": "2026-07-10T09:00:00Z"}},
                ]}},
            ]}

        with mock.patch.object(ok, "opensearch_configured", return_value=True), \
             mock.patch.object(ok, "opensearch_request", side_effect=fake_request):
            selection, error = ok.feed_selection_msearch(
                ["enceladus"], {"task": 100}, page_size=75, before="2026-07-11T00:00:00Z"
            )
        self.assertIsNone(error)
        # ranked dict shape, not a bare id list
        self.assertEqual(
            selection, {"enceladus#task": [{"id": "ENC-TSK-001", "updated_at": "2026-07-10T09:00:00Z"}]}
        )
        # query header requested page_size+1, _source updated_at, and the range bound
        body = captured["body"]
        self.assertIn('"size": 76', body)
        self.assertIn('"_source": ["updated_at"]', body)
        self.assertIn('"lte": "2026-07-11T00:00:00Z"', body)

    def test_legacy_mode_unchanged_bare_id_lists(self):
        import opensearch_keyword as ok

        def fake_request(method, path, body=None):
            b = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body
            # legacy header must NOT carry a range bound or _source updated_at
            assert '"_source": false' in b.lower()
            return 200, {"responses": [
                {"hits": {"hits": [{"_id": "enceladus#task#ENC-TSK-001"}]}},
            ]}

        with mock.patch.object(ok, "opensearch_configured", return_value=True), \
             mock.patch.object(ok, "opensearch_request", side_effect=fake_request):
            selection, error = ok.feed_selection_msearch(["enceladus"], {"task": 10})
        self.assertIsNone(error)
        self.assertEqual(selection, {"enceladus#task": ["ENC-TSK-001"]})
