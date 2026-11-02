"""ENC-TSK-S05 (N5a): intent/description projected onto governed nodes; embedding text untouched."""
import unittest
from unittest.mock import MagicMock


def _props(lf, record):
    tx = MagicMock()
    lf._upsert_node(tx, record)
    return tx.run.call_args.kwargs["props"]


class TestTextProjection(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        import embedding
        self.lf = lf
        self.embedding = embedding

    def test_projects_intent_and_description(self):
        props = _props(self.lf, {"record_id": "ENC-TSK-ZZ1", "record_type": "task", "title": "t",
                                 "intent": "why", "description": "what"})
        self.assertEqual(props["intent"], "why")
        self.assertEqual(props["description"], "what")
        self.assertEqual(props["title"], "t")

    def test_caps_applied(self):
        props = _props(self.lf, {"record_id": "ENC-ISS-ZZ1", "record_type": "issue", "title": "t",
                                 "intent": "i" * 1500, "description": "d" * 2500})
        self.assertEqual(len(props["intent"]), 1000)
        self.assertEqual(len(props["description"]), 2000)

    def test_absent_empty_or_non_string_omitted(self):
        for rec in (
            {},
            {"intent": "", "description": "   "},
            {"intent": None, "description": None},
            {"intent": ["x"], "description": {"a": 1}},
        ):
            base = {"record_id": "ENC-TSK-ZZ2", "record_type": "task", "title": "t"}
            base.update(rec)
            props = _props(self.lf, base)
            self.assertNotIn("intent", props)
            self.assertNotIn("description", props)
            self.assertEqual(props["title"], "t")

    def test_all_governed_types_project(self):
        for rtype, rid in (("feature", "ENC-FTR-ZZ1"), ("plan", "ENC-PLN-ZZ1"), ("lesson", "ENC-LSN-ZZ1")):
            props = _props(self.lf, {"record_id": rid, "record_type": rtype, "title": "t", "intent": "i"})
            self.assertEqual(props["intent"], "i", rtype)

    def test_embedding_text_and_hash_unchanged(self):
        long_rec = {"title": "t", "intent": "i" * 1500, "description": "d" * 2500}
        before_text = self.embedding.build_embedding_text(long_rec)
        before_hash = self.embedding.hash_embedding_text(before_text)
        _props(self.lf, {"record_id": "ENC-TSK-ZZ3", "record_type": "task", **long_rec})
        after_text = self.embedding.build_embedding_text(long_rec)
        # uncapped text still feeds the embedding (cap applies to node props only)
        self.assertIn("i" * 1500, after_text)
        self.assertEqual(before_text, after_text)
        self.assertEqual(before_hash, self.embedding.hash_embedding_text(after_text))
        self.assertNotIn("intent", self.lf.NODE_PROPERTIES)


if __name__ == "__main__":
    unittest.main()
