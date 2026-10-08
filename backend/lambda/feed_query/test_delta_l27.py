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

    items, tombstones, latest, truncated = delta.query_version_delta(
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
    assert truncated is False
    assert len(items) == 1
    assert items[0]["version_seq"] == 11
    assert tombstones[0]["record_id"] == "ENC-TSK-002"
    assert tombstones[0]["version_seq"] == 12


def _tracker_row(seq: int) -> dict:
    return {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"task#ENC-TSK-{seq:03d}"},
        "record_type": {"S": "task"},
        "item_id": {"S": f"ENC-TSK-{seq:03d}"},
        "version_seq": {"N": str(seq)},
    }


class _PagedDdb:
    """Fake DDB whose version-seq-index holds rows 1..total, paged by Limit."""

    def __init__(self, total: int):
        self.total = total
        self.queries = []

    def get_paginator(self, name):
        assert name == "query"
        outer = self

        class _Paginator:
            def paginate(self, **kwargs):
                outer.queries.append(kwargs)
                since = int(kwargs["ExpressionAttributeValues"][":since"]["N"])
                limit = kwargs["Limit"]
                rows = [_tracker_row(seq) for seq in range(since + 1, outer.total + 1)]
                for start in range(0, len(rows), limit):
                    yield {"Items": rows[start : start + limit]}

        return _Paginator()

    def batch_get_item(self, **kwargs):
        keys = kwargs["RequestItems"]["t"]["Keys"]
        out = []
        for key in keys:
            seq = int(key["record_id"]["S"].rsplit("-", 1)[-1])
            row = _tracker_row(seq)
            row["title"] = {"S": f"Task {seq}"}
            out.append(row)
        return {"Responses": {"t": out}}


def _identity_transform(raw, pid):
    item_id = raw["item_id"]["S"]
    return {"record_id": item_id, "record_key": f"tracker:{pid}:{item_id}", "source": "tracker"}


def test_query_version_delta_caps_window_and_resumes():
    """ENC-TSK-Q34 AC-3: since=0 cannot produce an unbounded response."""
    ddb = _PagedDdb(total=7)
    kwargs = dict(is_stale_closed=lambda _i, _c: False, transform_record=_identity_transform, cutoff=None)

    items, tombstones, latest, truncated = delta.query_version_delta(ddb, "t", 0, max_items=3, **kwargs)
    assert [i["version_seq"] for i in items] == [1, 2, 3]
    assert (latest, truncated, tombstones) == (3, True, [])

    items, _, latest, truncated = delta.query_version_delta(ddb, "t", latest, max_items=3, **kwargs)
    assert [i["version_seq"] for i in items] == [4, 5, 6]
    assert (latest, truncated) == (6, True)

    items, _, latest, truncated = delta.query_version_delta(ddb, "t", latest, max_items=3, **kwargs)
    assert [i["version_seq"] for i in items] == [7]
    assert (latest, truncated) == (7, False)


def test_query_version_delta_exact_fit_is_not_truncated():
    ddb = _PagedDdb(total=3)
    items, _, latest, truncated = delta.query_version_delta(
        ddb, "t", 0, max_items=3,
        is_stale_closed=lambda _i, _c: False, transform_record=_identity_transform, cutoff=None,
    )
    assert len(items) == 3
    assert (latest, truncated) == (3, False)


def _doc(document_id, seq=None, status="active", **extra):
    row = {"document_id": document_id, "project_id": "devops", "title": document_id, "status": status,
           "updated_at": "2026-10-08T02:29:33Z"}
    if seq is not None:
        row["version_seq"] = seq
    row.update(extra)
    return row


def _build_doc_entry(document):
    return {"record_id": document["document_id"], "record_type": "document",
            "record_key": f"document::{document['document_id']}", "source": "document"}


def _is_counter(document):
    return document.get("document_id") == "__COUNTER__VERSION_SEQ__" or document.get("record_type") == "counter"


def test_query_document_delta_returns_changes_and_tombstones_in_doc_space():
    """ENC-TSK-Q34 AC-1 / ENC-ISS-765: documents reach clients through delta."""
    documents = [
        _doc("DOC-LEGACY"),                      # pre-P72 row: no version_seq
        _doc("DOC-OLD", 180),                    # at/below the cursor
        _doc("DOC-NEW", 185),
        _doc("DOC-GONE", 186, status="archived"),
        _doc("DOC-NEWER", 187),
        _doc("__COUNTER__VERSION_SEQ__", 187, record_type="counter"),
    ]
    items, tombstones, latest, truncated = delta.query_document_delta(
        documents, 180, build_entry=_build_doc_entry, is_counter_row=_is_counter,
    )
    assert [(i["record_id"], i["version_seq"]) for i in items] == [("DOC-NEW", 185), ("DOC-NEWER", 187)]
    assert tombstones == [{
        "record_key": "document::DOC-GONE", "record_id": "DOC-GONE", "record_type": "document",
        "project_id": "devops", "version_seq": 186,
    }]
    assert (latest, truncated) == (187, False)


def test_query_document_delta_caps_and_resumes():
    documents = [_doc(f"DOC-{seq}", seq) for seq in (5, 6, 7)]
    kwargs = dict(build_entry=_build_doc_entry, is_counter_row=_is_counter, max_items=2)
    items, _, latest, truncated = delta.query_document_delta(documents, 0, **kwargs)
    assert [i["version_seq"] for i in items] == [5, 6]
    assert (latest, truncated) == (6, True)
    items, _, latest, truncated = delta.query_document_delta(documents, latest, **kwargs)
    assert [i["version_seq"] for i in items] == [7]
    assert (latest, truncated) == (7, False)
