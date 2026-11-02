"""ENC-TSK-R81-0E: keyword signal uses the title-only fulltext index with CONTAINS fallback."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lambda_function as lf  # noqa: E402


class _Session:
    def __init__(self, calls, fail_fulltext):
        self.calls, self.fail_fulltext = calls, fail_fulltext

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **kw):
        self.calls.append((cypher, kw))
        if "db.index.fulltext.queryNodes" in cypher:
            if self.fail_fulltext:
                raise RuntimeError("There is no such fulltext schema index")
            return [{"rid": "ENC-TSK-1", "score": 2.5}, {"rid": "ENC-TSK-2", "score": 1.0}]
        return [{"rid": "ENC-TSK-9", "score": 3.0}]


class _Driver:
    def __init__(self, fail_fulltext=False):
        self.calls, self.fail_fulltext = [], fail_fulltext

    def session(self):
        return _Session(self.calls, self.fail_fulltext)


class KeywordFulltextTests(unittest.TestCase):
    def test_uses_fulltext_index_and_title_only(self):
        d = _Driver()
        out = lf._hybrid_keyword_ranks(d, "enceladus", "graph search (fast)", 5, "task")
        self.assertEqual([r["record_id"] for r in out], ["ENC-TSK-1", "ENC-TSK-2"])
        self.assertEqual([r["rank"] for r in out], [1, 2])
        cypher, kw = d.calls[0]
        self.assertIn("db.index.fulltext.queryNodes", cypher)
        self.assertEqual(kw["index_name"], "governed_record_title_ft")
        self.assertEqual(kw["label"], "Task")
        self.assertEqual(kw["ft_query"], "graph OR search OR \\(fast\\)")
        self.assertEqual(len(d.calls), 1)

    def test_falls_back_to_title_contains_without_intent_description(self):
        d = _Driver(fail_fulltext=True)
        out = lf._hybrid_keyword_ranks(d, "enceladus", "graph search", 5)
        self.assertEqual([r["record_id"] for r in out], ["ENC-TSK-9"])
        cypher, _ = d.calls[1]
        self.assertIn("CONTAINS", cypher)
        self.assertNotIn("intent", cypher)
        self.assertNotIn("description", cypher)

    def test_operators_neutralised(self):
        self.assertEqual(lf._lucene_escape("AND"), "and")
        self.assertEqual(lf._lucene_escape("a:b*"), "a\\:b\\*")


if __name__ == "__main__":
    unittest.main()
