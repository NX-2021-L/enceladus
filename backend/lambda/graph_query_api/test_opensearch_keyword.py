"""Unit tests for ENC-TSK-L43 OpenSearch keyword arm helpers."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import opensearch_keyword as okw  # noqa: E402


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
