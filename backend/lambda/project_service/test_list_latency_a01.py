"""DVP-TSK-A01 — GET /api/v1/projects latency: response shape and DynamoDB call-count pins.

Root cause being pinned: the list handler used to run, per project and serially, a full paginated
Query over the project's tracker records (project-type-index, projection ALL) just to compute
days_since_active. Cost scaled with total tracker size and was paid on every request.

These tests use a stub DynamoDB client (no AWS, no moto) that records every call, and assert:
  * the response contract is unchanged (compared against a verbatim copy of the pre-A01
    per-project computation, run against the same stub data);
  * a cold list is exactly 1 projects Scan + one Query chain per project (no tracker Scan,
    no GetItem, no repeated work), and a warm list is exactly 1 projects Scan;
  * cache misses are looked up concurrently, and failures are never cached.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import sys
import threading
import unittest

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "project_service_a01",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
ps = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ps)


def _iso(days_ago: float) -> str:
    when = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago, hours=1)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _legacy_days_since_active(ddb, project_id: str):
    """Verbatim copy of the pre-A01 _compute_days_since_active (reference for parity)."""
    try:
        resp = ddb.query(
            TableName=ps.TRACKER_TABLE,
            IndexName=ps.TRACKER_GSI,
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": project_id}},
            ProjectionExpression="updated_at",
            ScanIndexForward=False,
        )
    except ClientError:
        return None
    max_ts = None
    for item in resp.get("Items", []):
        ts = item.get("updated_at", {}).get("S")
        if ts and (max_ts is None or ts > max_ts):
            max_ts = ts
    while resp.get("LastEvaluatedKey"):
        try:
            resp = ddb.query(
                TableName=ps.TRACKER_TABLE,
                IndexName=ps.TRACKER_GSI,
                KeyConditionExpression="project_id = :pid",
                ExpressionAttributeValues={":pid": {"S": project_id}},
                ProjectionExpression="updated_at",
                ScanIndexForward=False,
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
        except ClientError:
            break
        for item in resp.get("Items", []):
            ts = item.get("updated_at", {}).get("S")
            if ts and (max_ts is None or ts > max_ts):
                max_ts = ts
    if not max_ts:
        return None
    last_dt = dt.datetime.fromisoformat(max_ts.replace("Z", "+00:00"))
    return (dt.datetime.now(dt.timezone.utc) - last_dt).days


class FakeDynamo:
    """Records every call. Projects table: Scan (optionally paged). Tracker GSI: paged Query."""

    def __init__(self, projects, tracker, page_size=2, barrier=None):
        self.projects = projects  # list of plain dicts of S attributes
        self.tracker = tracker  # project_id -> [updated_at ISO strings]
        self.page_size = page_size
        self.barrier = barrier
        self.calls = []
        self.fail_queries_for = set()
        self._lock = threading.Lock()

    def _record(self, op, kwargs):
        with self._lock:
            self.calls.append((op, kwargs.get("TableName"), kwargs.get("IndexName")))

    def scan(self, **kwargs):
        self._record("scan", kwargs)
        assert kwargs["TableName"] == ps.PROJECTS_TABLE, "list must never scan the tracker table"
        return {"Items": [{k: {"S": v} for k, v in p.items()} for p in self.projects]}

    def get_item(self, **kwargs):  # pragma: no cover - must never be called by the list path
        self._record("get_item", kwargs)
        raise AssertionError("list path must not GetItem")

    def query(self, **kwargs):
        self._record("query", kwargs)
        if self.barrier is not None:
            self.barrier.wait(timeout=5)  # only passes if queries are in flight concurrently
        pid = kwargs["ExpressionAttributeValues"][":pid"]["S"]
        if pid in self.fail_queries_for:
            raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException"}}, "Query")
        stamps = self.tracker.get(pid, [])
        start = int(kwargs.get("ExclusiveStartKey", {}).get("n", {}).get("N", "0"))
        page = stamps[start:start + self.page_size]
        resp = {"Items": [{"updated_at": {"S": s}} for s in page]}
        if start + self.page_size < len(stamps):
            resp["LastEvaluatedKey"] = {"n": {"N": str(start + self.page_size)}}
        return resp

    def count(self, op=None, table=None):
        return sum(1 for c in self.calls if (op is None or c[0] == op) and (table is None or c[1] == table))


def _project(pid, status="active", **extra):
    base = {"project_id": pid, "prefix": pid[:3].upper(), "status": status, "summary": f"{pid} summary"}
    base.update(extra)
    return base


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig = {
            "_ddb": ps._ddb,
            "keys": ps.COORDINATION_INTERNAL_API_KEYS,
            "scopes": ps.INTERNAL_API_KEY_SCOPES,
            "ttl": getattr(ps, "_ACTIVITY_TTL", None),  # getattr: suite also runs on pre-A01 code
        }
        getattr(ps, "_activity_cache", {}).clear()
        ps.COORDINATION_INTERNAL_API_KEYS = ("test-key",)
        ps.INTERNAL_API_KEY_SCOPES = {}

    def tearDown(self):
        ps._ddb = self._orig["_ddb"]
        ps.COORDINATION_INTERNAL_API_KEYS = self._orig["keys"]
        ps.INTERNAL_API_KEY_SCOPES = self._orig["scopes"]
        if self._orig["ttl"] is not None:
            ps._ACTIVITY_TTL = self._orig["ttl"]
        getattr(ps, "_activity_cache", {}).clear()

    def install(self, fake):
        ps._ddb = fake
        return fake

    def list_projects(self, query=None):
        event = {
            "httpMethod": "GET",
            "path": "/api/v1/projects",
            "headers": {"x-coordination-internal-key": "test-key"},
            "queryStringParameters": query or None,
        }
        return ps.lambda_handler(event, None)


def _standard_fake(**kw):
    projects = [
        _project("zeta", deploy_policy="manual"),
        _project("alpha"),
        _project("mid", status="closed"),
        _project("quiet"),
    ]
    tracker = {
        "alpha": [_iso(9), _iso(0.2), _iso(3), _iso(1), _iso(5)],  # 3 pages of 2
        "zeta": [_iso(12)],
        "mid": [_iso(40), _iso(41)],
        # "quiet" has no tracker records -> days_since_active null
    }
    return FakeDynamo(projects, tracker, **kw)


class ResponseShapeTests(_Base):
    def test_contract_matches_pre_a01_computation(self):
        fake = self.install(_standard_fake())
        resp = self.list_projects()
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(sorted(body), ["count", "projects", "success"])
        self.assertTrue(body["success"] is True)
        self.assertEqual(body["count"], 4)
        self.assertEqual([p["project_id"] for p in body["projects"]], ["alpha", "mid", "quiet", "zeta"])

        # Rebuild the exact pre-A01 output from the same stub data and compare the whole body.
        expected = []
        for raw in fake.projects:
            item = dict(raw)
            item["days_since_active"] = _legacy_days_since_active(fake, raw["project_id"])
            policy = str(item.get("deploy_policy") or "").strip().lower()
            item["deploy_policy"] = policy if policy in ps._VALID_DEPLOY_POLICIES else ps._DEFAULT_DEPLOY_POLICY
            expected.append(item)
        expected.sort(key=lambda p: p["project_id"])
        self.assertEqual(
            resp["body"],
            json.dumps({"success": True, "projects": expected, "count": len(expected)}),
        )
        self.assertEqual(
            {p["project_id"]: p["days_since_active"] for p in body["projects"]},
            {"alpha": 0, "mid": 40, "quiet": None, "zeta": 12},
        )
        for p in body["projects"]:
            self.assertIn(p["deploy_policy"], ps._VALID_DEPLOY_POLICIES)
        self.assertEqual(resp["headers"]["Content-Type"], "application/json")

    def test_status_and_active_filters_unchanged(self):
        self.install(_standard_fake())
        by_status = json.loads(self.list_projects({"status": "closed"})["body"])
        self.assertEqual([p["project_id"] for p in by_status["projects"]], ["mid"])
        active = json.loads(self.list_projects({"active": "true"})["body"])
        self.assertEqual([p["project_id"] for p in active["projects"]], ["alpha", "quiet", "zeta"])

    def test_get_single_project_still_enriched(self):
        fake = self.install(_standard_fake())
        fake.get_item = lambda **kw: {"Item": {k: {"S": v} for k, v in _project("zeta").items()}}
        resp = ps.lambda_handler(
            {
                "httpMethod": "GET",
                "path": "/api/v1/projects/zeta",
                "pathParameters": {"projectName": "zeta"},
                "headers": {"x-coordination-internal-key": "test-key"},
            },
            None,
        )
        project = json.loads(resp["body"])["project"]
        self.assertEqual(project["days_since_active"], 12)
        self.assertEqual(project["deploy_policy"], ps._DEFAULT_DEPLOY_POLICY)


class CallCountTests(_Base):
    def test_cold_list_is_one_scan_plus_one_query_chain_per_project(self):
        fake = self.install(_standard_fake())
        self.list_projects()
        # alpha: 5 records / page 2 -> 3 pages; zeta: 1; mid: 1; quiet: 1 (empty page).
        self.assertEqual(fake.count("scan"), 1)
        self.assertEqual(fake.count("scan", ps.PROJECTS_TABLE), 1)
        self.assertEqual(fake.count("get_item"), 0)
        self.assertEqual(fake.count("query", ps.TRACKER_TABLE), 3 + 1 + 1 + 1)
        self.assertEqual(len(fake.calls), 1 + 6)
        # Every tracker read is the project GSI Query, never a table Scan.
        self.assertTrue(all(c[2] == ps.TRACKER_GSI for c in fake.calls if c[0] == "query"))

    def test_warm_list_is_a_single_projects_scan(self):
        fake = self.install(_standard_fake())
        first = self.list_projects()
        fake.calls.clear()
        second = self.list_projects()
        self.assertEqual(fake.calls, [("scan", ps.PROJECTS_TABLE, None)])
        self.assertEqual(first["body"], second["body"])

    def test_filtered_list_only_looks_up_returned_projects(self):
        fake = self.install(_standard_fake())
        self.list_projects({"status": "closed"})
        self.assertEqual(fake.count("query"), 1)  # "mid" only, one page

    def test_expired_entry_is_refreshed_once_not_per_request(self):
        fake = self.install(_standard_fake())
        self.list_projects()
        ps._activity_cache["zeta"] = (-1.0, ps._activity_cache["zeta"][1])  # force expiry
        fake.calls.clear()
        self.list_projects()
        self.assertEqual(fake.count("query"), 1)
        fake.calls.clear()
        self.list_projects()
        self.assertEqual(fake.count("query"), 0)

    def test_ttl_zero_disables_the_cache(self):
        fake = self.install(_standard_fake())
        ps._ACTIVITY_TTL = 0.0
        self.list_projects()
        fake.calls.clear()
        self.list_projects()
        self.assertEqual(fake.count("query"), 6)

    def test_cache_holds_timestamp_so_day_count_stays_exact(self):
        fake = self.install(_standard_fake())
        self.list_projects()
        newest_zeta = ps._activity_cache["zeta"][1]
        self.assertEqual(newest_zeta, fake.tracker["zeta"][0])  # a timestamp, not a day count
        ps._activity_cache["zeta"] = (ps._activity_cache["zeta"][0], _iso(30))
        days = json.loads(self.list_projects()["body"])["projects"][3]["days_since_active"]
        self.assertEqual(days, 30)


class ConcurrencyAndFailureTests(_Base):
    def test_cache_misses_are_looked_up_concurrently(self):
        projects = [_project(f"p{i}") for i in range(4)]
        tracker = {f"p{i}": [_iso(i)] for i in range(4)}
        # Each Query blocks until all 4 are in flight: a serial implementation times out.
        fake = self.install(FakeDynamo(projects, tracker, barrier=threading.Barrier(4)))
        resp = self.list_projects()
        self.assertEqual(resp["statusCode"], 200)
        days = [p["days_since_active"] for p in json.loads(resp["body"])["projects"]]
        self.assertEqual(days, [0, 1, 2, 3])
        self.assertEqual(fake.count("query"), 4)

    def test_failed_lookup_is_null_and_never_cached(self):
        fake = self.install(_standard_fake())
        fake.fail_queries_for = {"zeta"}
        body = json.loads(self.list_projects()["body"])
        self.assertIsNone([p for p in body["projects"] if p["project_id"] == "zeta"][0]["days_since_active"])
        self.assertNotIn("zeta", ps._activity_cache)
        fake.fail_queries_for = set()
        fake.calls.clear()
        body = json.loads(self.list_projects()["body"])
        self.assertEqual([p for p in body["projects"] if p["project_id"] == "zeta"][0]["days_since_active"], 12)
        self.assertEqual(fake.count("query"), 1)  # only the previously failed project

    def test_stale_value_is_served_when_refresh_fails(self):
        fake = self.install(_standard_fake())
        self.list_projects()
        ps._activity_cache["zeta"] = (-1.0, ps._activity_cache["zeta"][1])
        fake.fail_queries_for = {"zeta"}
        body = json.loads(self.list_projects()["body"])
        self.assertEqual([p for p in body["projects"] if p["project_id"] == "zeta"][0]["days_since_active"], 12)

    def test_projects_scan_failure_is_still_a_500(self):
        fake = self.install(_standard_fake())

        def boom(**kw):
            raise ClientError({"Error": {"Code": "InternalServerError"}}, "Scan")

        fake.scan = boom
        resp = self.list_projects()
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(json.loads(resp["body"]), {"success": False, "error": "Database read failed."})


if __name__ == "__main__":
    unittest.main()
