"""Tests for ENC-TSK-F45: graph_sync edge projection for DESIGNS/IMPLEMENTS/DEPLOYS pairs."""
import unittest
from unittest.mock import MagicMock, call, patch


class TestInferLabelFromIdComponentPrefix(unittest.TestCase):
    """ENC-TSK-F45 OGTM-d: comp- prefix maps to :Component label."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_comp_prefix_returns_component(self):
        self.assertEqual(self.lf._infer_label_from_id("comp-graph-sync"), "Component")

    def test_comp_coordination_api(self):
        self.assertEqual(self.lf._infer_label_from_id("comp-coordination-api"), "Component")

    def test_comp_graph_query_api(self):
        self.assertEqual(self.lf._infer_label_from_id("comp-graph-query-api"), "Component")

    def test_task_prefix_unchanged(self):
        self.assertEqual(self.lf._infer_label_from_id("ENC-TSK-F45"), "Task")

    def test_feature_prefix_unchanged(self):
        self.assertEqual(self.lf._infer_label_from_id("ENC-FTR-076"), "Feature")

    def test_doc_prefix_unchanged(self):
        self.assertEqual(self.lf._infer_label_from_id("DOC-ABCDEF"), "Document")

    def test_unknown_prefix_returns_empty(self):
        self.assertEqual(self.lf._infer_label_from_id("XYZ-UNKNOWN"), "")


class TestRelationshipTypeToEdgeLabelF45(unittest.TestCase):
    """ENC-TSK-F45: RELATIONSHIP_TYPE_TO_EDGE_LABEL has all 6 new mappings."""

    def setUp(self):
        import lambda_function as lf
        self.mapping = lf.RELATIONSHIP_TYPE_TO_EDGE_LABEL

    def test_designs_maps_to_DESIGNS(self):
        self.assertEqual(self.mapping["designs"], "DESIGNS")

    def test_designed_by_maps_to_DESIGNED_BY(self):
        self.assertEqual(self.mapping["designed-by"], "DESIGNED_BY")

    def test_implements_maps_to_IMPLEMENTS(self):
        self.assertEqual(self.mapping["implements"], "IMPLEMENTS")

    def test_implemented_by_maps_to_IMPLEMENTED_BY(self):
        self.assertEqual(self.mapping["implemented-by"], "IMPLEMENTED_BY")

    def test_deploys_maps_to_DEPLOYS(self):
        self.assertEqual(self.mapping["deploys"], "DEPLOYS")

    def test_deployed_by_maps_to_DEPLOYED_BY(self):
        self.assertEqual(self.mapping["deployed-by"], "DEPLOYED_BY")


class TestUpsertRelationshipEdgePlaceholder(unittest.TestCase):
    """ENC-TSK-F45 / ENC-TSK-E01: _upsert_relationship_edge creates placeholder nodes."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _run(self, rel_type, source_id, target_id):
        tx = MagicMock()
        record = {
            "relationship_type": rel_type,
            "source_id": source_id,
            "target_id": target_id,
        }
        self.lf._upsert_relationship_edge(tx, record)
        return tx

    def test_designs_creates_component_placeholder(self):
        tx = self._run("designs", "comp-graph-sync", "ENC-TSK-F45")
        # Should have MERGE calls for placeholder nodes + edge
        cypher_calls = [str(c) for c in tx.run.call_args_list]
        # At least one call should contain MERGE with Component label
        self.assertTrue(
            any("Component" in c for c in cypher_calls),
            f"Expected Component placeholder MERGE; calls were: {cypher_calls}",
        )
        # At least one call should contain MERGE with Task label
        self.assertTrue(
            any("Task" in c for c in cypher_calls),
            f"Expected Task placeholder MERGE; calls were: {cypher_calls}",
        )
        # At least one call should contain DESIGNS edge label
        self.assertTrue(
            any("DESIGNS" in c for c in cypher_calls),
            f"Expected DESIGNS edge MERGE; calls were: {cypher_calls}",
        )

    def test_deploys_creates_placeholder_and_edge(self):
        tx = self._run("deploys", "comp-coordination-api", "ENC-TSK-F40")
        cypher_calls = [str(c) for c in tx.run.call_args_list]
        self.assertTrue(any("DEPLOYS" in c for c in cypher_calls))

    def test_implemented_by_creates_placeholder_and_edge(self):
        tx = self._run("implemented-by", "ENC-TSK-F41", "comp-graph-query-api")
        cypher_calls = [str(c) for c in tx.run.call_args_list]
        self.assertTrue(any("IMPLEMENTED_BY" in c for c in cypher_calls))

    def test_unknown_rel_type_returns_early(self):
        tx = self._run("unknown-edge-type", "comp-x", "ENC-TSK-001")
        tx.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
