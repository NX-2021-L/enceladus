import asyncio
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import pathlib
import sys
import threading
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
        self.counters = {}

    def get_item(self, TableName, Key, **_kwargs):  # noqa: N803
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

    def update_item(self, **kwargs):
        key = kwargs["Key"]
        item_key = (key["project_id"]["S"], key["record_id"]["S"])
        seed = int(kwargs["ExpressionAttributeValues"][":seed"]["N"])
        current = self.counters.get(item_key, seed)
        next_num = current + 1
        self.counters[item_key] = next_num
        return {"Attributes": {"next_num": {"N": str(next_num)}}}

    def put_item(self, **kwargs):
        self.put_requests.append(kwargs)


class _ConcurrentIdFakeDdb:
    def __init__(self, existing_max: int = 500):
        self.lock = threading.Lock()
        self.items = {}
        self.put_requests = []
        for num in range(1, existing_max + 1):
            rid = f"DVP-TSK-{num:03d}"
            key = ("devops", f"task#{rid}")
            self.items[key] = {
                "project_id": {"S": "devops"},
                "record_id": {"S": f"task#{rid}"},
                "item_id": {"S": rid},
                "record_type": {"S": "task"},
            }

    def get_item(self, TableName, Key, **_kwargs):  # noqa: N803
        if TableName == server.PROJECTS_TABLE:
            return {
                "Item": {
                    "project_id": {"S": "devops"},
                    "prefix": {"S": "DVP"},
                }
            }
        if TableName == server.TRACKER_TABLE:
            key = (Key["project_id"]["S"], Key["record_id"]["S"])
            with self.lock:
                item = self.items.get(key)
            return {"Item": dict(item)} if item else {}
        return {}

    def query(self, **kwargs):
        pid = kwargs["ExpressionAttributeValues"][":pid"]["S"]
        record_prefix = kwargs["ExpressionAttributeValues"][":rtype_prefix"]["S"]
        with self.lock:
            rows = [
                {"record_id": {"S": record_id}}
                for (project_id, record_id), _item in self.items.items()
                if project_id == pid and record_id.startswith(record_prefix)
            ]
        return {"Items": rows}

    def update_item(self, **kwargs):
        key = kwargs["Key"]
        item_key = (key["project_id"]["S"], key["record_id"]["S"])
        seed = int(kwargs["ExpressionAttributeValues"][":seed"]["N"])
        with self.lock:
            existing = dict(self.items.get(item_key, {}))
            current = int(existing.get("next_num", {"N": str(seed)})["N"])
            next_num = current + 1
            existing["project_id"] = {"S": item_key[0]}
            existing["record_id"] = {"S": item_key[1]}
            existing["next_num"] = {"N": str(next_num)}
            self.items[item_key] = existing
        return {"Attributes": {"next_num": {"N": str(next_num)}}}

    def put_item(self, **kwargs):
        item = kwargs["Item"]
        key = (item["project_id"]["S"], item["record_id"]["S"])
        with self.lock:
            if kwargs.get("ConditionExpression") == "attribute_not_exists(record_id)" and key in self.items:
                raise server.ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "collision"}},
                    "PutItem",
                )
            self.items[key] = dict(item)
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


def test_tracker_create_concurrent_ids_are_unique_for_100_plus_requests():
    gov_hash = server._compute_governance_hash()
    fake_ddb = _ConcurrentIdFakeDdb(existing_max=500)

    def _create(idx: int) -> str:
        result = _call_tracker_create(
            {
                "project_id": "devops",
                "record_type": "task",
                "title": f"Concurrent task {idx}",
                "governance_hash": gov_hash,
                "acceptance_criteria": [f"criterion {idx}"],
            }
        )
        assert result.get("success") is True, result
        return result["record_id"]

    with patch.object(server, "_get_ddb", return_value=fake_ddb):
        with ThreadPoolExecutor(max_workers=24) as pool:
            ids = list(pool.map(_create, range(120)))

    assert len(ids) == 120
    assert len(set(ids)) == 120
    numeric = sorted(int(record_id.split("-")[2]) for record_id in ids)
    assert numeric[0] == 501
    assert numeric[-1] == 620
