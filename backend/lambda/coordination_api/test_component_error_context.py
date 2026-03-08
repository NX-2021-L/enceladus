import importlib.util
import json
import os
import sys
import unittest


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)


class CoordinationComponentErrorContextTests(unittest.TestCase):
    def test_component_create_invalid_transition_type_includes_strictness_rank(self):
        response = coordination_lambda._handle_components_create(
            {
                "body": json.dumps(
                    {
                        "component_name": "Checkout Service",
                        "project_id": "enceladus",
                        "category": "lambda",
                        "transition_type": "manual",
                    }
                )
            },
            {"auth_mode": "internal-key"},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["field"], "transition_type")
        self.assertIn("github_pr_deploy", details["allowed_values"])
        rank_table = {entry["transition_type"]: entry["rank"] for entry in details["strictness_rank"]}
        self.assertEqual(rank_table["github_pr_deploy"], 0)
        self.assertEqual(rank_table["lambda_deploy"], 1)


if __name__ == "__main__":
    unittest.main()
