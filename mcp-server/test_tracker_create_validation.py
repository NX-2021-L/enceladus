import asyncio
import importlib.util
import json
import pathlib
import sys
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_unit", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _call_tracker_create(args: dict) -> dict:
    content = _run(server._tracker_create(args))
    assert content, "tracker_create returned empty content"
    return json.loads(content[0].text)


class _FakeDdb:
    def __init__(self):
        self.put_requests = []

    def get_item(self, TableName, Key):  # noqa: N803
        if TableName == server.PROJECTS_TABLE:
            return {
                "Item": {
                    "project_id": {"S": "devops"},
                    "prefix": {"S": "DVP"},
                }
            }
        return {}

    def query(self, **_kwargs):
        return {"Items": []}

    def put_item(self, **kwargs):
        self.put_requests.append(kwargs)


def test_tracker_create_task_rejects_missing_acceptance_criteria():
    gov_hash = server._compute_governance_hash()
    with patch.object(server, "_get_ddb") as mock_get_ddb:
        result = _call_tracker_create(
            {
                "project_id": "devops",
                "record_type": "task",
                "title": "Task missing criteria",
                "governance_hash": gov_hash,
            }
        )

    assert "error" in result
    assert "acceptance_criteria" in result["error"]
    mock_get_ddb.assert_not_called()


def test_tracker_create_task_stores_acceptance_criteria():
    gov_hash = server._compute_governance_hash()
    fake_ddb = _FakeDdb()
    with patch.object(server, "_get_ddb", return_value=fake_ddb):
        result = _call_tracker_create(
            {
                "project_id": "devops",
                "record_type": "task",
                "title": "Task with criteria",
                "governance_hash": gov_hash,
                "acceptance_criteria": ["  first criterion  ", "", "second criterion"],
            }
        )

    assert result.get("success") is True
    assert fake_ddb.put_requests
    item = fake_ddb.put_requests[0]["Item"]
    assert "acceptance_criteria" in item
    criteria = [entry["S"] for entry in item["acceptance_criteria"]["L"]]
    assert criteria == ["first criterion", "second criterion"]
