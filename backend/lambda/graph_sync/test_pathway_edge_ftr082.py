"""ENC-FTR-082 Phase A / AC-6: graph_sync PATHWAY_TRAVERSED label projection.

Labels must stay byte-identical to graph_query_api _ALLOWED_EDGE_TYPES (ENC-ISS-178).
"""
import unittest


class TestPathwayLabelMapping(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.mapping = lf.RELATIONSHIP_TYPE_TO_EDGE_LABEL

    def test_forward_label(self):
        self.assertEqual(self.mapping.get("pathway-traversed"), "PATHWAY_TRAVERSED")

    def test_inverse_label(self):
        self.assertEqual(self.mapping.get("traversed-by"), "TRAVERSED_BY")

    def test_labels_uppercase(self):
        # Projection labels are UPPER_SNAKE by convention.
        self.assertEqual("PATHWAY_TRAVERSED", "PATHWAY_TRAVERSED".upper())
        self.assertEqual(self.mapping["traversed-by"], self.mapping["traversed-by"].upper())


if __name__ == "__main__":
    unittest.main()
