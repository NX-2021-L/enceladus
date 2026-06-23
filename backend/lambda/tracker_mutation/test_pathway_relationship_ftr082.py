"""ENC-FTR-082 Phase A / AC-6: tracker_mutation pathway-traversed registration.

Covers all four relationship registries so create-relationship(pathway-traversed)
validates and auto-creates the traversed-by inverse without KeyError/Unknown-type.
"""
import unittest


class TestPathwayRelationshipRegistries(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_in_relationship_types(self):
        self.assertIn("pathway-traversed", self.lf._RELATIONSHIP_TYPES)
        self.assertIn("traversed-by", self.lf._RELATIONSHIP_TYPES)

    def test_inverse_pairs_both_directions(self):
        # Guards the unguarded _INVERSE_PAIRS[...] index in _handle_create_relationship.
        self.assertEqual(self.lf._INVERSE_PAIRS["pathway-traversed"], "traversed-by")
        self.assertEqual(self.lf._INVERSE_PAIRS["traversed-by"], "pathway-traversed")

    def test_owl_characteristics(self):
        c = self.lf._OWL_CHARACTERISTICS["pathway-traversed"]
        self.assertTrue(c["asymmetric"])
        self.assertTrue(c["irreflexive"])
        self.assertFalse(c["transitive"])

    def test_domain_range_present(self):
        # Present => _validate_rel_domain_range does NOT return "Unknown relationship type".
        self.assertIn("pathway-traversed", self.lf._DOMAIN_RANGE_CONSTRAINTS)
        self.assertIn("traversed-by", self.lf._DOMAIN_RANGE_CONSTRAINTS)

    def test_domain_range_validates_any_endpoints(self):
        self.assertIsNone(
            self.lf._validate_rel_domain_range("pathway-traversed", "feature", "feature"))
        self.assertIsNone(
            self.lf._validate_rel_domain_range("traversed-by", "task", "lesson"))

    def test_not_transitive(self):
        self.assertNotIn("pathway-traversed", self.lf._TRANSITIVE_TYPES)


if __name__ == "__main__":
    unittest.main()
