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
        if TableName == bedrock_lambda.GOVERNANCE_POLICIES_TABLE:
            return {
                "Item": {
                    "policy_id": {"S": bedrock_lambda.DOCUMENT_STORAGE_POLICY_ID},
                    "status": {"S": "active"},
                    "enforcement_mode": {"S": "enforce"},
                    "allowed_targets": {"L": [{"S": "docstore_api"}, {"S": "governance_s3"}]},
                }
            }
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


# ENC-TSK-T04 (ENC-ISS-911): POST /tracker/create no longer writes. It used to mint a
# record id from three digits of a random UUID and then put_item it unconditionally, so
# a collision silently overwrote a live governed record. The two tests that used to
# assert its acceptance_criteria validation and storage now assert the refusal: there is
# no create behaviour left to validate, and record-id allocation belongs to the server.
# Full fail-closed coverage lives in test_tracker_write_fail_closed_t04.py.
def test_handle_tracker_create_is_refused_without_touching_dynamodb():
    with patch.object(bedrock_lambda, "_get_ddb") as mock_get_ddb:
        result = bedrock_lambda._handle_tracker_create(
            {
                "project_id": "devops",
                "record_type": "task",
                "title": "Missing criteria",
            }
        )

    assert "error" in result
    assert "Refused" in result["error"]
    assert result["refused_operation"] == "tracker.create"
    assert "tracker.create" in result["governed_path"]
    assert result["governance_reference"] == "ENC-ISS-911"
    mock_get_ddb.assert_not_called()


def test_handle_tracker_create_refuses_even_with_valid_acceptance_criteria():
    """A well-formed request is refused too -- the path is closed, not validated."""
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

    assert result.get("success") is None
    assert "Refused" in result["error"]
    assert not fake_ddb.put_calls, "a refused create must not write"
    assert "item_id" not in result, "a refused create must not mint an id"


def test_check_document_policy_denies_local_path():
    fake_ddb = _FakeDdb()
    with patch.object(bedrock_lambda, "_get_ddb", return_value=fake_ddb):
        result = bedrock_lambda._handle_check_document_policy(
            [
                {"name": "operation", "value": "documents_put"},
                {"name": "storageTarget", "value": "docstore_api"},
                {"name": "fileName", "value": "/tmp/local.md"},
                {"name": "projectId", "value": "enceladus"},
            ]
        )

    assert result["allowed"] is False
    assert result["decision"] == "denied"
    assert fake_ddb.put_calls


def test_check_document_policy_allows_docstore_basename():
    fake_ddb = _FakeDdb()
    with patch.object(bedrock_lambda, "_get_ddb", return_value=fake_ddb):
        result = bedrock_lambda._handle_check_document_policy(
            [
                {"name": "operation", "value": "documents_put"},
                {"name": "storageTarget", "value": "docstore_api"},
                {"name": "fileName", "value": "summary.md"},
                {"name": "projectId", "value": "enceladus"},
            ]
        )

    assert result["allowed"] is True
    assert result["decision"] == "allowed"
