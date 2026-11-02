"""ENC-TSK-S12 (N5c): Lucene field boosts over governed_record_text_ft, fallback chain, escaping."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lambda_function as lf  # noqa: E402


class _Session:
    def __init__(self, calls, bad_indexes):
        self.calls, self.bad = calls, bad_indexes

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **kw):
        self.calls.append((cypher, kw))
        if "db.index.fulltext.queryNodes" in cypher:
            if kw["index_name"] in self.bad:
                raise RuntimeError("There is no such fulltext schema index: " + kw["index_name"])
            return [{"rid": "ENC-TSK-1", "score": 2.0}]
        return [{"rid": "ENC-TSK-9", "score": 3.0}]


class _Driver:
    def __init__(self, bad_indexes=()):
        self.calls, self.bad = [], set(bad_indexes)

    def session(self):
        return _Session(self.calls, self.bad)


class KeywordBoostTests(unittest.TestCase):
    def test_lucene_string_carries_boosts(self):
        d = _Driver()
        out = lf._hybrid_keyword_ranks(d, "enceladus", "Graph Search", 5)
        self.assertEqual([r["record_id"] for r in out], ["ENC-TSK-1"])
        _, kw = d.calls[0]
        self.assertEqual(kw["index_name"], "governed_record_text_ft")
        self.assertEqual(
            kw["ft_query"],
            "title:(graph OR search)^3 OR intent:(graph OR search)^2 OR description:(graph OR search)^1",
        )
        self.assertEqual(len(d.calls), 1)

    def test_bad_index_name_falls_back_to_title_index_with_plain_query(self):
        with mock.patch.object(lf, "KEYWORD_FULLTEXT_INDEX", "no_such_index"):
            d = _Driver(bad_indexes={"no_such_index"})
            out = lf._hybrid_keyword_ranks(d, "enceladus", "graph search", 5)
        self.assertEqual([r["record_id"] for r in out], ["ENC-TSK-1"])
        self.assertEqual([c[1]["index_name"] for c in d.calls], ["no_such_index", "governed_record_title_ft"])
        self.assertEqual(d.calls[1][1]["ft_query"], "graph OR search")

    def test_both_indexes_missing_falls_back_to_contains(self):
        d = _Driver(bad_indexes={"governed_record_text_ft", "governed_record_title_ft"})
        out = lf._hybrid_keyword_ranks(d, "enceladus", "graph search", 5)
        self.assertEqual([r["record_id"] for r in out], ["ENC-TSK-9"])
        self.assertEqual(len(d.calls), 3)
        self.assertIn("CONTAINS", d.calls[2][0])

    def test_title_index_env_uses_plain_query_once(self):
        with mock.patch.object(lf, "KEYWORD_FULLTEXT_INDEX", "governed_record_title_ft"):
            d = _Driver()
            lf._hybrid_keyword_ranks(d, "enceladus", "graph", 5)
        self.assertEqual(len(d.calls), 1)
        self.assertEqual(d.calls[0][1]["ft_query"], "graph")

    def test_escaping_still_holds_inside_boosted_query(self):
        d = _Driver()
        lf._hybrid_keyword_ranks(d, "enceladus", 'a:b* AND "x" (y)', 5)
        q = d.calls[0][1]["ft_query"]
        self.assertIn("title:(a\\:b\\* OR and OR \\\"x\\\" OR \\(y\\))^3", q)
        self.assertEqual(lf._lucene_escape("NOT"), "not")
        self.assertEqual(lf._lucene_escape("a:b*"), "a\\:b\\*")


if __name__ == "__main__":
    unittest.main()
