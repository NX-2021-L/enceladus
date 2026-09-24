"""Unit tests for feed delta version_seq queries (ENC-TSK-L27)."""

from __future__ import annotations

import importlib.util
import os

_DELTA_SPEC = importlib.util.spec_from_file_location(
    "feed_delta",
    os.path.join(os.path.dirname(__file__), "delta.py"),
)
delta = importlib.util.module_from_spec(_DELTA_SPEC)
assert _DELTA_SPEC.loader is not None
_DELTA_SPEC.loader.exec_module(delta)


def test_parse_since_version():
    assert delta.parse_since_version("0") == 0
    assert delta.parse_since_version("42") == 42
    assert delta.parse_since_version("") is None
    assert delta.parse_since_version("-1") is None
    assert delta.parse_since_version("abc") is None


def test_query_version_delta_splits_items_and_tombstones():
    class FakePaginator:
        def paginate(self, **kwargs):
            assert kwargs["IndexName"] == delta.VERSION_SEQ_INDEX
            assert kwargs["ExpressionAttributeValues"][":since"]["N"] == "10"
            yield {
                "Items": [
                    {
                        "project_id": {"S": "enceladus"},
                        "record_id": {"S": "task#ENC-TSK-001"},
                        "record_type": {"S": "task"},
                        "item_id": {"S": "ENC-TSK-001"},
                        "version_seq": {"N": "11"},
                    },
                    {
                        "record_type": {"S": delta.FEED_TOMBSTONE_RECORD_TYPE},
                        "item_id": {"S": "ENC-TSK-002"},
                        "target_project_id": {"S": "enceladus"},
                        "target_record_id": {"S": "task#ENC-TSK-002"},
                        "target_record_type": {"S": "task"},
                        "version_seq": {"N": "12"},
                    },
                ]
            }

    class FakeDdb:
        def get_paginator(self, name):
            assert name == "query"
            return FakePaginator()

        def batch_get_item(self, **kwargs):
            return {
                "Responses": {
                    "devops-project-tracker-gamma": [
                        {
                            "project_id": {"S": "enceladus"},
                            "record_id": {"S": "task#ENC-TSK-001"},
                            "record_type": {"S": "task"},
                            "item_id": {"S": "ENC-TSK-001"},
                            "version_seq": {"N": "11"},
                            "status": {"S": "open"},
                            "title": {"S": "Alpha"},
                            "updated_at": {"S": "2026-07-05T08:00:00Z"},
                        }
                    ]
                }
            }

    items, tombstones, latest = delta.query_version_delta(
        FakeDdb(),
        "devops-project-tracker-gamma",
        10,
        is_stale_closed=lambda _item, _cutoff: False,
        transform_record=lambda raw, pid: {
            "record_id": "ENC-TSK-001",
            "record_type": "task",
            "project_id": pid,
            "title": "Alpha",
            "record_key": f"tracker:{pid}:ENC-TSK-001",
            "source": "tracker",
            "attrs": {},
        },
        cutoff=None,
    )
    assert latest == 12
    assert len(items) == 1
    assert items[0]["version_seq"] == 11
    assert tombstones[0]["record_id"] == "ENC-TSK-002"
    assert tombstones[0]["version_seq"] == 12
