"""ENC-TSK-J52 / FTR-104 Ph3 — tuned lambda weights + optional energy response."""

from __future__ import annotations

import unittest

import energy_function as ef


class J52TunedWeightTests(unittest.TestCase):
    def test_defaults_match_i99_tuned_values(self):
        self.assertEqual(ef.DEFAULT_LAMBDA_GRAPH, 1.0)
        self.assertEqual(ef.DEFAULT_LAMBDA_KW, 0.1)

    def test_tuned_weights_favor_graph_corroboration_over_uniform(self):
        """Graph-heavy candidate energy drops more under I99-tuned lambdas."""
        kwargs = dict(
            vector_score=0.55,
            graph_score=0.9,
            keyword_score=0.2,
            max_graph_score=0.9,
            max_keyword_score=0.5,
            graph_algorithm="cypher_fallback",
        )
        tuned = ef.compute_retrieval_energy(**kwargs, lambda_graph=1.0, lambda_kw=0.1)
        uniform = ef.compute_retrieval_energy(**kwargs, lambda_graph=0.5, lambda_kw=0.25)
        self.assertLess(tuned["retrieval_energy"], uniform["retrieval_energy"])
        self.assertEqual(tuned["lambda_graph"], 1.0)
        self.assertEqual(tuned["lambda_kw"], 0.1)


if __name__ == "__main__":
    unittest.main()
