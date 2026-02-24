import importlib.util
import pathlib
import sys
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("bedrock_agent_actions_lambda", MODULE_PATH)
bedrock_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = bedrock_lambda
SPEC.loader.exec_module(bedrock_lambda)


class _FakeDdb:
    def __init__(self):
        self.put_calls = []

    def get_item(self, TableName, Key):  # noqa: N803
        if TableName == bedrock_lambda.PROJECTS_TABLE:
            return {
                "Item": {
                    "project_id": {"S": "devops"},
                    "prefix": {"S": "DVP"},
                }
            }
        return {}

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)


def test_handle_tracker_create_requires_acceptance_criteria_for_task():
    with patch.object(bedrock_lambda, "_get_ddb") as mock_get_ddb:
        result = bedrock_lambda._handle_tracker_create(
            {
                "project_id": "devops",
                "record_type": "task",
                "title": "Missing criteria",
            }
        )

    assert "error" in result
    assert "acceptance_criteria" in result["error"]
    mock_get_ddb.assert_not_called()


def test_handle_tracker_create_stores_acceptance_criteria():
    fake_ddb = _FakeDdb()
    with patch.object(bedrock_lambda, "_get_ddb", return_value=fake_ddb):
        result = bedrock_lambda._handle_tracker_create(
            {
                "project_id": "devops",
                "record_type": "task",
                "title": "Valid criteria",
                "acceptance_criteria": ["  first  ", "", "second"],
            }
        )

    assert result.get("success") is True
    assert fake_ddb.put_calls
    item = fake_ddb.put_calls[0]["Item"]
    assert "acceptance_criteria" in item
    criteria = [entry["S"] for entry in item["acceptance_criteria"]["L"]]
    assert criteria == ["first", "second"]
