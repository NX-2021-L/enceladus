"""Tests for ENC-TSK-C08: graph_query_api _ALLOWED_EDGE_TYPES OGTM registration.

AC-4: the HCE-introduced edge types CONSOLIDATED_FROM and PROPOSED_BY (plus their
inverses) must be queryable via tracker.graphsearch, which gates on this allowlist.
"""
import unittest


class TestAllowedEdgeTypesC08(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.allowed = lf._ALLOWED_EDGE_TYPES

    def test_consolidated_from_in_allowlist(self):
        self.assertIn("CONSOLIDATED_FROM", self.allowed)

    def test_consolidates_inverse_in_allowlist(self):
        self.assertIn("CONSOLIDATES", self.allowed)

    def test_proposed_by_in_allowlist(self):
        self.assertIn("PROPOSED_BY", self.allowed)

    def test_proposes_inverse_in_allowlist(self):
        self.assertIn("PROPOSES", self.allowed)

    def test_existing_edge_types_preserved(self):
        for edge in ("CONSOLIDATED_FROM", "INFORMED_BY", "HANDS_OFF", "RELATED_TO",
                     "PATHWAY_TRAVERSED", "LEARNED_FROM"):
            with self.subTest(edge=edge):
                self.assertIn(edge, self.allowed)


if __name__ == "__main__":
    unittest.main()
