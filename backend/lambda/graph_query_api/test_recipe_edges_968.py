"""DVP-TSK-968 part D: graph_query_api registers the Recipe / RecipeRun edges and record_type labels."""
import unittest
from unittest.mock import MagicMock

EDGES = ["RECIPE_USES_TOOL", "TOOL_USED_BY_RECIPE", "RECIPE_SERVES_PROJECT", "PROJECT_SERVED_BY_RECIPE",
         "RECIPE_IMPLEMENTS_FEATURE", "IMPLEMENTED_BY_RECIPE", "RUN_INSTANCE_OF_RECIPE", "RECIPE_HAS_RUN",
         "RUN_OPENED_ESCALATION", "ESCALATION_OPENED_BY_RUN"]


class TestRecipeEdges(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_edge_types_allowed(self):
        for edge in EDGES:
            self.assertIn(edge, self.lf._ALLOWED_EDGE_TYPES)

    def test_keyword_search_accepts_recipe_record_types(self):
        for rtype, label in (("recipe", "Recipe"), ("recipe_run", "RecipeRun")):
            driver = MagicMock()
            session = driver.session.return_value.__enter__.return_value
            session.run.return_value = []
            result = self.lf._query_keyword(driver, "devops", {"query": "ship", "record_type": rtype, "limit": 5})
            self.assertNotIn("Invalid record_type", str(result))
            self.assertIn(f"(n:{label})", session.run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
