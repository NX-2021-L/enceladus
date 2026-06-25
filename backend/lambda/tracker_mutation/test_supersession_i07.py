"""ENC-TSK-I07 (Dedup P3): supersession primitive unit tests.

Pure-logic coverage in the established tracker_mutation house style (no DDB
round-trip): the supersedes/superseded-by domain/range generalization to
{lesson, issue, task}, the supersede precheck guards that short-circuit BEFORE
any DynamoDB read (non-supersedable type, cross-type), the evidence-count helper
backing the evidence-orphan guard, and presence/wiring of the operation helpers.

See DOC-DF651F07D5C2 §7. The full supersede -> edge-migration -> evidence-freeze
-> reversible un-supersession round trip is validated end-to-end on gamma as the
OGTM criterion #4 live traversal, tracked as the I07 follow-on (it requires the
live DynamoDB + Neo4j projection, not exercised by these pure unit tests).
"""
import unittest


class TestSupersessionRegistries(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_supersedable_types(self):
        self.assertEqual(self.lf._SUPERSEDABLE_TYPES, frozenset({"issue", "task"}))
        self.assertNotIn("lesson", self.lf._SUPERSEDABLE_TYPES)
        self.assertNotIn("feature", self.lf._SUPERSEDABLE_TYPES)

    def test_domain_range_generalized_to_issue_and_task(self):
        # ENC-TSK-I07: superseded-by/supersedes are now valid for issue/issue and
        # task/task, while still valid for the original lesson/lesson (ENC-FTR-052).
        for rt in ("superseded-by", "supersedes"):
            self.assertIsNone(self.lf._validate_rel_domain_range(rt, "issue", "issue"), rt)
            self.assertIsNone(self.lf._validate_rel_domain_range(rt, "task", "task"), rt)
            self.assertIsNone(self.lf._validate_rel_domain_range(rt, "lesson", "lesson"), rt)

    def test_domain_range_rejects_feature_endpoint(self):
        # feature is intentionally NOT in the generalized domain/range set.
        self.assertIsNotNone(
            self.lf._validate_rel_domain_range("superseded-by", "feature", "feature"))

    def test_inverse_and_owl_unchanged(self):
        self.assertEqual(self.lf._INVERSE_PAIRS["superseded-by"], "supersedes")
        self.assertEqual(self.lf._INVERSE_PAIRS["supersedes"], "superseded-by")
        c = self.lf._OWL_CHARACTERISTICS["superseded-by"]
        self.assertTrue(c["asymmetric"])
        self.assertTrue(c["irreflexive"])
        self.assertTrue(c["transitive"])


class TestAcceptedEvidenceCount(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_counts_only_accepted_structured_criteria(self):
        item = {"acceptance_criteria": [
            {"description": "a", "evidence_acceptance": True},
            {"description": "b", "evidence_acceptance": False},
            {"description": "c", "evidence_acceptance": True},
            "legacy-string-criterion",  # plain-string criteria never count as accepted
        ]}
        self.assertEqual(self.lf._accepted_evidence_count(item), 2)

    def test_empty_or_missing(self):
        self.assertEqual(self.lf._accepted_evidence_count({}), 0)
        self.assertEqual(self.lf._accepted_evidence_count({"acceptance_criteria": []}), 0)


class TestSupersedePrecheckEarlyGuards(unittest.TestCase):
    """Guards that short-circuit BEFORE any DynamoDB read — exercised with no mock.

    _supersede_precheck validates record types from the IDs and rejects ineligible
    pairs prior to calling _get_record_raw, so these paths are pure.
    """
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_rejects_non_supersedable_type(self):
        r = self.lf._supersede_precheck("enceladus", "ENC-FTR-1", "ENC-FTR-2")
        self.assertIn("error", r)
        self.assertEqual(r.get("status"), 400)

    def test_rejects_cross_type_category_error(self):
        # issue superseded-by task: both supersedable, but cross-type collapse is a
        # category error (DOC-DF651F07D5C2 §4.0) — rejected before any DDB read.
        r = self.lf._supersede_precheck("enceladus", "ENC-ISS-1", "ENC-TSK-2")
        self.assertEqual(r.get("status"), 400)
        self.assertIn("same record_type", r["error"])


class TestSupersessionHelpersWired(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_operation_helpers_present_and_callable(self):
        for name in ("_supersede_precheck", "_apply_supersession", "_revert_supersession",
                     "_migrate_typed_edges", "_unarchive_relationship_edge",
                     "_put_relationship_pair_idempotent", "_accepted_evidence_count"):
            self.assertTrue(callable(getattr(self.lf, name, None)), name)


if __name__ == "__main__":
    unittest.main()
