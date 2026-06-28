"""Tests for ENC-TSK-C08: graph_sync HCE provenance edge projection.

AC-4 (OGTM): the candidate Document's consolidated_from / proposed_by fields
project to CONSOLIDATED_FROM / PROPOSED_BY edges (plus inverses), and the typed
relationship-record path is registered in RELATIONSHIP_TYPE_TO_EDGE_LABEL.
"""
import unittest
from unittest.mock import MagicMock


class TestRelationshipTypeMappingC08(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.mapping = lf.RELATIONSHIP_TYPE_TO_EDGE_LABEL

    def test_consolidated_from(self):
        self.assertEqual(self.mapping["consolidated-from"], "CONSOLIDATED_FROM")

    def test_consolidates(self):
        self.assertEqual(self.mapping["consolidates"], "CONSOLIDATES")

    def test_proposed_by(self):
        self.assertEqual(self.mapping["proposed-by"], "PROPOSED_BY")

    def test_proposes(self):
        self.assertEqual(self.mapping["proposes"], "PROPOSES")


class TestCandidateEdgeProjectionC08(unittest.TestCase):
    def _reconcile(self, record):
        import lambda_function as lf
        tx = MagicMock()
        lf._reconcile_edges(tx, record)
        return [str(c) for c in tx.run.call_args_list]

    def test_consolidated_from_projects_edge(self):
        record = {
            "record_type": "document",
            "record_id": "DOC-CAND01",
            "project_id": "enceladus",
            "document_subtype": "doc",
            "consolidated_from": ["DOC-SRC01", "DOC-SRC02"],
        }
        calls = self._reconcile(record)
        self.assertTrue(any("CONSOLIDATED_FROM" in c for c in calls),
                        f"no CONSOLIDATED_FROM edge; calls={calls}")
        self.assertTrue(any("CONSOLIDATES" in c for c in calls))

    def test_proposed_by_projects_edge(self):
        record = {
            "record_type": "document",
            "record_id": "DOC-CAND02",
            "project_id": "enceladus",
            "document_subtype": "doc",
            "proposed_by": "ENC-FTR-064",
        }
        calls = self._reconcile(record)
        self.assertTrue(any("PROPOSED_BY" in c for c in calls),
                        f"no PROPOSED_BY edge; calls={calls}")
        self.assertTrue(any("PROPOSES" in c for c in calls))

    def test_no_provenance_fields_no_edges(self):
        record = {
            "record_type": "document",
            "record_id": "DOC-PLAIN",
            "project_id": "enceladus",
            "document_subtype": "doc",
        }
        calls = self._reconcile(record)
        self.assertFalse(any("CONSOLIDATED_FROM" in c for c in calls))
        self.assertFalse(any("PROPOSED_BY" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
