"""Tests for ENC-TSK-F45: graph_query_api _ALLOWED_EDGE_TYPES OGTM registration."""
import unittest


class TestAllowedEdgeTypesF45(unittest.TestCase):
    """ENC-TSK-F45 OGTM-a/b/c: all 6 new edge labels registered in _ALLOWED_EDGE_TYPES."""

    def setUp(self):
        import lambda_function as lf
        self.allowed = lf._ALLOWED_EDGE_TYPES

    def test_DESIGNS_in_allowlist(self):
        self.assertIn("DESIGNS", self.allowed)

    def test_DESIGNED_BY_in_allowlist(self):
        self.assertIn("DESIGNED_BY", self.allowed)

    def test_IMPLEMENTS_in_allowlist(self):
        # IMPLEMENTS was already present; verify still there
        self.assertIn("IMPLEMENTS", self.allowed)

    def test_IMPLEMENTED_BY_in_allowlist(self):
        self.assertIn("IMPLEMENTED_BY", self.allowed)

    def test_DEPLOYS_in_allowlist(self):
        self.assertIn("DEPLOYS", self.allowed)

    def test_DEPLOYED_BY_in_allowlist(self):
        self.assertIn("DEPLOYED_BY", self.allowed)

    def test_existing_edge_types_preserved(self):
        for edge in ("CHILD_OF", "RELATED_TO", "BELONGS_TO", "ADDRESSES", "BLOCKS",
                     "PLAN_CONTAINS", "LEARNED_FROM", "HANDS_OFF"):
            with self.subTest(edge=edge):
                self.assertIn(edge, self.allowed)


if __name__ == "__main__":
    unittest.main()
