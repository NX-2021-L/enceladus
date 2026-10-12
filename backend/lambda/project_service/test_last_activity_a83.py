"""DVP-TSK-A83 -- days_since_active from a stored projects.last_activity_at (zero tracker queries).

Builds on the A01 stub DynamoDB client and contract helpers. Pins:
  * rows that carry last_activity_at: zero tracker Query calls, 1 projects Scan, and the response
    body is byte-for-byte what the pre-A01 per-project computation produces (the internal
    attribute is stripped, so the response shape does not change);
  * rows that do not carry it (or carry an unusable value): the A01 cached tracker-query path;
  * a mixed list queries only the rows that lack the stored value;
  * GET /projects/{name} follows the same rule.
"""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import test_list_latency_a01 as a01  # noqa: E402  (shares the A01 module instance and stub)

ps = a01.ps


class _GetFake(a01.FakeDynamo):
    """A01 stub plus GetItem on the projects table (the list path must still never GetItem)."""

    def get_item(self, **kwargs):
        self._record("get_item", kwargs)
        assert kwargs["TableName"] == ps.PROJECTS_TABLE
        pid = kwargs["Key"]["project_id"]["S"]
        for p in self.projects:
            if p["project_id"] == pid:
                return {"Item": {k: {"S": v} for k, v in p.items()}}
        return {}


def _stored_fake(**kw):
    """alpha/zeta/mid carry last_activity_at == the newest tracker stamp (what the consumer writes)."""
    tracker = {
        "alpha": [a01._iso(9), a01._iso(0.2), a01._iso(3), a01._iso(1), a01._iso(5)],
        "zeta": [a01._iso(12)],
        "mid": [a01._iso(40), a01._iso(41)],
    }
    projects = [
        a01._project("zeta", deploy_policy="manual", last_activity_at=max(tracker["zeta"])),
        a01._project("alpha", last_activity_at=max(tracker["alpha"])),
        a01._project("mid", status="closed", last_activity_at=max(tracker["mid"])),
    ]
    return _GetFake(projects, tracker, **kw)


class StoredValueTests(a01._Base):
    def test_stored_value_means_zero_tracker_queries_and_unchanged_contract(self):
        fake = self.install(_stored_fake())
        resp = self.list_projects()
        self.assertEqual(resp["statusCode"], 200)

        self.assertEqual(fake.count("query"), 0, "stored last_activity_at must not touch the tracker")
        self.assertEqual(fake.count("scan", ps.TRACKER_TABLE), 0)
        self.assertEqual(fake.count("get_item"), 0)
        self.assertEqual(fake.count("scan", ps.PROJECTS_TABLE), 1)
        self.assertEqual(len(fake.calls), 1)

        # Byte-for-byte against the verbatim pre-A01 computation over the same tracker data;
        # the stored attribute must be stripped from every project in the response.
        expected = []
        for raw in fake.projects:
            item = {k: v for k, v in raw.items() if k != "last_activity_at"}
            item["days_since_active"] = a01._legacy_days_since_active(fake, raw["project_id"])
            policy = str(item.get("deploy_policy") or "").strip().lower()
            item["deploy_policy"] = policy if policy in ps._VALID_DEPLOY_POLICIES else ps._DEFAULT_DEPLOY_POLICY
            expected.append(item)
        expected.sort(key=lambda p: p["project_id"])
        # The legacy reference queries the stub too; only the list call above is under test.
        self.assertEqual(
            resp["body"],
            json.dumps({"success": True, "projects": expected, "count": len(expected)}),
        )
        body = json.loads(resp["body"])
        self.assertEqual(
            {p["project_id"]: p["days_since_active"] for p in body["projects"]},
            {"alpha": 0, "mid": 40, "zeta": 12},
        )
        for p in body["projects"]:
            self.assertNotIn("last_activity_at", p)

    def test_stored_value_is_authoritative_even_when_tracker_disagrees(self):
        fake = self.install(_stored_fake())
        for p in fake.projects:
            if p["project_id"] == "alpha":
                p["last_activity_at"] = a01._iso(20)  # tracker says 0 days; stored says 20
        body = json.loads(self.list_projects()["body"])
        by_id = {p["project_id"]: p["days_since_active"] for p in body["projects"]}
        self.assertEqual(by_id["alpha"], 20)
        self.assertEqual(fake.count("query"), 0)

    def test_warm_and_cold_are_identical_for_stored_rows(self):
        fake = self.install(_stored_fake())
        first = self.list_projects()["body"]
        second = self.list_projects()["body"]
        self.assertEqual(first, second)
        self.assertEqual(fake.count("query"), 0)
        self.assertEqual(fake.count("scan", ps.PROJECTS_TABLE), 2)

    def test_get_single_project_uses_stored_value(self):
        fake = self.install(_stored_fake())
        resp = ps.lambda_handler(
            {
                "httpMethod": "GET",
                "path": "/api/v1/projects/alpha",
                "headers": {"x-coordination-internal-key": "test-key"},
            },
            None,
        )
        self.assertEqual(resp["statusCode"], 200)
        project = json.loads(resp["body"])["project"]
        self.assertEqual(project["days_since_active"], 0)
        self.assertNotIn("last_activity_at", project)
        self.assertEqual(fake.count("query"), 0)
        self.assertEqual(fake.count("get_item"), 1)


class FallbackTests(a01._Base):
    def test_rows_without_the_attribute_use_the_a01_query_path(self):
        fake = self.install(a01._standard_fake())  # no project carries last_activity_at
        body = json.loads(self.list_projects()["body"])
        self.assertEqual(
            {p["project_id"]: p["days_since_active"] for p in body["projects"]},
            {"alpha": 0, "mid": 40, "quiet": None, "zeta": 12},
        )
        queried = {c for c in fake.calls if c[0] == "query"}
        self.assertEqual(queried, {("query", ps.TRACKER_TABLE, ps.TRACKER_GSI)})
        self.assertGreaterEqual(fake.count("query"), 4)  # at least one Query chain per project

        # ...and the A01 cache still makes the second request a single projects Scan.
        before = len(fake.calls)
        self.list_projects()
        self.assertEqual(len(fake.calls) - before, 1)

    def test_mixed_list_queries_only_the_rows_missing_the_value(self):
        fake = self.install(_stored_fake())
        fake.projects.append(a01._project("legacy"))
        fake.tracker["legacy"] = [a01._iso(7)]
        seen = []
        original_query = fake.query

        def spy(**kwargs):
            seen.append(kwargs["ExpressionAttributeValues"][":pid"]["S"])
            return original_query(**kwargs)

        fake.query = spy
        body = json.loads(self.list_projects()["body"])
        self.assertEqual(set(seen), {"legacy"})
        self.assertEqual(
            {p["project_id"]: p["days_since_active"] for p in body["projects"]},
            {"alpha": 0, "legacy": 7, "mid": 40, "zeta": 12},
        )
        for p in body["projects"]:
            self.assertNotIn("last_activity_at", p)

    def test_unusable_stored_values_fall_back_instead_of_reporting_null(self):
        fake = self.install(_stored_fake())
        for p in fake.projects:
            p["last_activity_at"] = "not-a-timestamp"
        body = json.loads(self.list_projects()["body"])
        self.assertEqual(
            {p["project_id"]: p["days_since_active"] for p in body["projects"]},
            {"alpha": 0, "mid": 40, "zeta": 12},
        )
        self.assertGreaterEqual(fake.count("query"), 3)

    def test_get_single_project_without_the_attribute_falls_back(self):
        fake = self.install(_GetFake([a01._project("legacy")], {"legacy": [a01._iso(3)]}))
        resp = ps.lambda_handler(
            {
                "httpMethod": "GET",
                "path": "/api/v1/projects/legacy",
                "headers": {"x-coordination-internal-key": "test-key"},
            },
            None,
        )
        self.assertEqual(json.loads(resp["body"])["project"]["days_since_active"], 3)
        self.assertGreaterEqual(fake.count("query"), 1)


if __name__ == "__main__":
    unittest.main()
