"""Unit tests for ENC-TSK-L43 OpenSearch keyword arm helpers."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import opensearch_keyword as okw  # noqa: E402


class TestOpensearchRequestBodyEncoding(unittest.TestCase):
    """ENC-TSK-M39 regression: opensearch_request must not re-serialize a
    pre-encoded body. A real (unmocked) exercise of opensearch_request itself
    -- mocking opensearch_request away (as the rest of this file does) would
    never have caught the double-encoding bug this guards against."""

    class _FakeResp:
        def __init__(self, body: bytes):
            self._body = body
            self.status = 200

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def test_bytes_body_passed_through_unmodified(self):
        captured = {}

        def fake_urlopen(req, context=None, timeout=None):
            captured["data"] = req.data
            return self._FakeResp(b"{}")

        ndjson_body = b'{"index": "records_read"}\n{"size": 5}\n'
        with mock.patch.object(okw, "OPENSEARCH_ENDPOINT", "https://os.example"), mock.patch.object(
            okw, "_get_credentials", return_value=("user", "pass")
        ), mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            okw.opensearch_request("POST", "/_msearch", ndjson_body)

        self.assertEqual(captured["data"], ndjson_body)

    def test_dict_body_still_json_encoded(self):
        captured = {}

        def fake_urlopen(req, context=None, timeout=None):
            captured["data"] = req.data
            return self._FakeResp(b"{}")

        with mock.patch.object(okw, "OPENSEARCH_ENDPOINT", "https://os.example"), mock.patch.object(
            okw, "_get_credentials", return_value=("user", "pass")
        ), mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            okw.opensearch_request("POST", "/_search", {"size": 5})

        self.assertEqual(json.loads(captured["data"]), {"size": 5})


class TestRecordIdFromHit(unittest.TestCase):
    def test_parses_stable_doc_id(self):
        hit = {"_id": "enceladus#task#ENC-TSK-001", "_source": {}}
        self.assertEqual(okw.record_id_from_hit(hit), "ENC-TSK-001")


class TestFacetParsing(unittest.TestCase):
    def test_parse_facet_aggs(self):
        aggs = {
            "record_type": {"buckets": [{"key": "task", "doc_count": 3}]},
            "status": {"buckets": [{"key": "open", "doc_count": 2}]},
            "priority": {"buckets": []},
            "project_id": {"buckets": [{"key": "enceladus", "doc_count": 3}]},
        }
        facets = okw._parse_facet_aggs(aggs)
        self.assertEqual(facets["record_type"]["task"], 3)
        self.assertEqual(facets["status"]["open"], 2)
        self.assertEqual(facets["project_id"]["enceladus"], 3)


class TestHybridKeywordRanks(unittest.TestCase):
    def test_returns_ranks_and_facets_on_success(self):
        search_resp = {
            "hits": {
                "hits": [
                    {"_id": "enceladus#task#ENC-TSK-001", "_score": 4.2},
                    {"_id": "enceladus#issue#ENC-ISS-002", "_score": 2.1},
                ]
            },
            "aggregations": {
                "project_id": {"buckets": [{"key": "enceladus", "doc_count": 2}]},
                "record_type": {"buckets": [{"key": "task", "doc_count": 1}, {"key": "issue", "doc_count": 1}]},
                "status": {"buckets": []},
                "priority": {"buckets": []},
            },
        }
        with mock.patch.object(okw, "opensearch_configured", return_value=True), mock.patch.object(
            okw, "opensearch_request", return_value=(200, search_resp)
        ):
            ranks, facets, err = okw.hybrid_keyword_ranks("enceladus", "search test", 10)
        self.assertIsNone(err)
        self.assertEqual(len(ranks), 2)
        self.assertEqual(ranks[0]["record_id"], "ENC-TSK-001")
        self.assertEqual(ranks[0]["rank"], 1)
        self.assertEqual(facets["record_type"]["task"], 1)

    def test_returns_error_when_opensearch_fails(self):
        with mock.patch.object(okw, "opensearch_configured", return_value=True), mock.patch.object(
            okw, "opensearch_request", side_effect=RuntimeError("connection refused")
        ):
            ranks, facets, err = okw.hybrid_keyword_ranks("enceladus", "query", 5)
        self.assertEqual(ranks, [])
        self.assertEqual(facets, {})
        self.assertIn("connection refused", err or "")


class TestFeedSelectionMsearch(unittest.TestCase):
    """ENC-TSK-M39: feed_query's OpenSearch-tier selection proxy query."""

    def test_returns_ids_per_project_and_type(self):
        msearch_resp = {
            "responses": [
                {"hits": {"hits": [
                    {"_id": "enceladus#task#ENC-TSK-001"},
                    {"_id": "enceladus#task#ENC-TSK-002"},
                ]}},
                {"hits": {"hits": [{"_id": "enceladus#issue#ENC-ISS-010"}]}},
            ]
        }
        with mock.patch.object(okw, "opensearch_configured", return_value=True), mock.patch.object(
            okw, "opensearch_request", return_value=(200, msearch_resp)
        ):
            selection, err = okw.feed_selection_msearch(
                ["enceladus"], {"task": 100, "issue": 10}
            )
        self.assertIsNone(err)
        self.assertEqual(selection["enceladus#task"], ["ENC-TSK-001", "ENC-TSK-002"])
        self.assertEqual(selection["enceladus#issue"], ["ENC-ISS-010"])

    def test_builds_one_msearch_line_pair_per_project_type_pair(self):
        msearch_resp = {"responses": [{"hits": {"hits": []}}, {"hits": {"hits": []}}, {"hits": {"hits": []}}, {"hits": {"hits": []}}]}
        captured = {}

        def fake_request(method, path, body):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            return 200, msearch_resp

        with mock.patch.object(okw, "opensearch_configured", return_value=True), mock.patch.object(
            okw, "opensearch_request", side_effect=fake_request
        ):
            okw.feed_selection_msearch(["enceladus", "other-proj"], {"task": 5, "issue": 3})

        self.assertEqual(captured["path"], "/_msearch")
        lines = captured["body"].decode("utf-8").strip().split("\n")
        # 2 projects x 2 record types x (1 header + 1 query) = 8 lines
        self.assertEqual(len(lines), 8)
        header = json.loads(lines[0])
        self.assertEqual(header, {"index": okw.READ_ALIAS})
        query = json.loads(lines[1])
        self.assertEqual(query["size"], 5)
        self.assertEqual(query["sort"], [{"updated_at": "desc"}])

    def test_returns_error_on_transport_failure(self):
        with mock.patch.object(okw, "opensearch_configured", return_value=True), mock.patch.object(
            okw, "opensearch_request", side_effect=RuntimeError("timeout")
        ):
            selection, err = okw.feed_selection_msearch(["enceladus"], {"task": 10})
        self.assertEqual(selection, {})
        self.assertIn("timeout", err or "")

    def test_returns_error_when_not_configured(self):
        with mock.patch.object(okw, "opensearch_configured", return_value=False):
            selection, err = okw.feed_selection_msearch(["enceladus"], {"task": 10})
        self.assertEqual(selection, {})
        self.assertEqual(err, "opensearch_not_configured")

    def test_empty_input_short_circuits(self):
        with mock.patch.object(okw, "opensearch_configured", return_value=True):
            selection, err = okw.feed_selection_msearch([], {"task": 10})
        self.assertEqual(selection, {})
        self.assertEqual(err, "no_input")

    def test_skips_pair_with_sub_query_error_but_keeps_others(self):
        msearch_resp = {
            "responses": [
                {"error": {"type": "search_phase_execution_exception"}},
                {"hits": {"hits": [{"_id": "enceladus#issue#ENC-ISS-010"}]}},
            ]
        }
        with mock.patch.object(okw, "opensearch_configured", return_value=True), mock.patch.object(
            okw, "opensearch_request", return_value=(200, msearch_resp)
        ):
            selection, err = okw.feed_selection_msearch(["enceladus"], {"task": 100, "issue": 10})
        self.assertIsNone(err)
        self.assertNotIn("enceladus#task", selection)
        self.assertEqual(selection["enceladus#issue"], ["ENC-ISS-010"])


class TestFeedCorpusFacetFallback(unittest.TestCase):
    def test_parses_feed_corpus_facets(self):
        payload = {
            "facets": {
                "record_type": {"task": 5},
                "status": {"open": 4},
                "priority": {"P1": 2},
                "project_id": {"enceladus": 5},
            }
        }
        body = json.dumps(payload).encode("utf-8")

        class FakeResp:
            def read(self):
                return body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch.object(okw, "COORDINATION_INTERNAL_API_KEY", "test-key"), mock.patch(
            "urllib.request.urlopen", return_value=FakeResp()
        ):
            facets, err = okw.fetch_feed_corpus_facets(project_id="enceladus", query_text="foo")
        self.assertIsNone(err)
        self.assertEqual(facets["record_type"]["task"], 5)


if __name__ == "__main__":
    unittest.main()
