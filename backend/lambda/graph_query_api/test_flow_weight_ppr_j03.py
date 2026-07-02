"""ENC-TSK-J03 — flow_weight PPR read path + entropy metric tests."""
from __future__ import annotations

import math
import unittest
from unittest.mock import MagicMock, patch

import flow_weight_entropy as fwe


class TestShannonEntropy(unittest.TestCase):
    def test_diverse_weights_higher_entropy_than_degenerate(self):
        diverse = fwe.shannon_entropy([1.0, 2.0, 3.0, 4.0])
        degenerate = fwe.shannon_entropy([5.0, 5.0, 5.0, 5.0])
        self.assertGreater(diverse, degenerate)

    def test_single_weight_zero_entropy(self):
        self.assertEqual(fwe.shannon_entropy([5.0, 5.0, 5.0]), 0.0)

    def test_empty_is_zero(self):
        self.assertEqual(fwe.shannon_entropy([]), 0.0)


class TestCypherFallbackFlowWeight(unittest.TestCase):
    def test_cypher_includes_flow_weight_multiplier(self):
        import lambda_function as lf

        cypher_frag = (
            f"coalesce(rel.{lf._GDS_FLOW_WEIGHT_PROPERTY}, 1.0)"
        )
        # Inspect source by calling with a mock driver that captures the query.
        driver = MagicMock()
        session = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        session.run.return_value = []

        lf._hybrid_graph_ranks_cypher_fallback(
            driver, "enceladus", "ENC-PLN-006", 5,
        )
        query = session.run.call_args[0][0]
        self.assertIn(cypher_frag, query)


class TestPprWeightProperty(unittest.TestCase):
    def test_default_ppr_weight_is_flow_weight(self):
        import lambda_function as lf

        self.assertEqual(lf._GDS_PPR_WEIGHT_PROPERTY, lf._GDS_FLOW_WEIGHT_PROPERTY)


if __name__ == "__main__":
    unittest.main()
