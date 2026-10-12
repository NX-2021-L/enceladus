"""DVP-TSK-A83: tools/backfill_project_last_activity.py is read-only unless --apply."""

from __future__ import annotations

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "backfill_project_last_activity",
    os.path.join(os.path.dirname(__file__), "backfill_project_last_activity.py"),
)
bf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bf)


class _Cond(Exception):
    pass


class _Fake:
    class exceptions:  # noqa: N801 - mirrors the botocore client attribute
        ConditionalCheckFailedException = _Cond

    def __init__(self):
        self.writes = []

    def scan(self, **kwargs):
        return {
            "Items": [
                {"project_id": {"S": "dormant"}},
                {"project_id": {"S": "fresh"}, "last_activity_at": {"S": "2026-10-12T00:00:00Z"}},
                {"project_id": {"S": "empty"}},
            ]
        }

    def query(self, **kwargs):
        pid = kwargs["ExpressionAttributeValues"][":pid"]["S"]
        stamps = {
            "dormant": ["2026-10-01T00:00:00Z", "2026-10-02T00:00:00+00:00"],
            "fresh": ["2026-10-05T00:00:00Z"],
        }.get(pid, [])
        return {"Items": [{"updated_at": {"S": s}} for s in stamps]}

    def update_item(self, **kwargs):
        self.writes.append(kwargs)


def test_default_run_never_writes():
    fake = _Fake()
    counts = bf.run(fake, "projects", "tracker", apply=False, out=lambda *_: None)
    assert fake.writes == []
    assert counts["would_write"] == 1 and counts["written"] == 0


def test_apply_writes_only_rows_that_need_it_with_the_monotonic_condition():
    fake = _Fake()
    counts = bf.run(fake, "projects", "tracker", apply=True, out=lambda *_: None)
    assert len(fake.writes) == 1
    write = fake.writes[0]
    assert write["Key"] == {"project_id": {"S": "dormant"}}
    assert write["ExpressionAttributeValues"] == {":ts": {"S": "2026-10-02T00:00:00Z"}}
    assert write["ConditionExpression"] == bf.CONDITION
    assert counts["written"] == 1 and counts["skipped"] == 1 and counts["no_tracker_records"] == 1
