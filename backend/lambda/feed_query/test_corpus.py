"""Unit tests for feed corpus pagination (ENC-TSK-L23)."""

from __future__ import annotations

import importlib.util
import os

_CORPUS_SPEC = importlib.util.spec_from_file_location(
    "feed_corpus",
    os.path.join(os.path.dirname(__file__), "corpus.py"),
)
corpus = importlib.util.module_from_spec(_CORPUS_SPEC)
assert _CORPUS_SPEC.loader is not None
_CORPUS_SPEC.loader.exec_module(corpus)


def _entry(
    record_id: str,
    *,
    record_type: str = "task",
    project_id: str = "enceladus",
    title: str = "Alpha",
    updated_at: str = "2026-07-05T10:00:00Z",
    status: str = "open",
    priority: str = "P1",
) -> dict:
    return corpus.build_tracker_entry(
        record_type,
        record_id,
        project_id,
        title,
        updated_at,
        {"status": status, "priority": priority},
    )


def test_paginate_returns_next_cursor_and_facets():
    entries = [
        _entry("ENC-TSK-BBB", updated_at="2026-07-05T11:00:00Z"),
        _entry("ENC-TSK-AAA", updated_at="2026-07-05T10:00:00Z"),
        corpus.build_document_entry(
            {
                "document_id": "DOC-123",
                "project_id": "enceladus",
                "title": "Doc",
                "status": "active",
                "updated_at": "2026-07-05T09:00:00Z",
                "keywords": ["wave-b"],
            }
        ),
    ]
    entries = [entry for entry in entries if entry]

    first = corpus.paginate_corpus(entries, {"limit": 2, "sort": "updated_at_desc"})
    assert len(first["items"]) == 2
    assert first["items"][0]["record_id"] == "ENC-TSK-BBB"
    assert first["next_cursor"]
    assert first["facets"]["record_type"]["task"] == 2
    assert first["facets"]["record_type"]["document"] == 1

    second = corpus.paginate_corpus(
        entries,
        {"limit": 2, "sort": "updated_at_desc", "cursor": first["next_cursor"]},
    )
    assert len(second["items"]) == 1
    assert second["items"][0]["record_id"] == "DOC-123"
    assert second["next_cursor"] is None


def test_filter_by_record_type_and_query():
    entries = [
        _entry("ENC-TSK-AAA", title="Search alpha"),
        _entry("ENC-ISS-BBB", record_type="issue", title="Other"),
    ]
    page = corpus.paginate_corpus(
        entries,
        {"limit": 10, "record_type": ["task"], "q": "search"},
    )
    assert page["total_matches"] == 1
    assert page["items"][0]["record_id"] == "ENC-TSK-AAA"


def test_invalid_cursor_decode_returns_none():
    assert corpus.decode_cursor("not-valid") is None


def test_document_entry_skips_deleted():
    assert corpus.build_document_entry({"document_id": "DOC-1", "status": "deleted"}) is None


def test_paginate_cursor_key_missing_order_seeks_instead_of_restarting():
    # ENC-ISS-711: a continuation can be served by a container whose per-
    # container corpus cache lacks the cursor's exact record. The resume must
    # land order-positionally (first row strictly after the cursor position),
    # never silently restart from the top.
    entries = [
        _entry("ENC-TSK-FFF", updated_at="2026-07-05T15:00:00Z"),
        _entry("ENC-TSK-EEE", updated_at="2026-07-05T14:00:00Z"),
        _entry("ENC-TSK-DDD", updated_at="2026-07-05T13:00:00Z"),
        _entry("ENC-TSK-CCC", updated_at="2026-07-05T12:00:00Z"),
        _entry("ENC-TSK-BBB", updated_at="2026-07-05T11:00:00Z"),
        _entry("ENC-TSK-AAA", updated_at="2026-07-05T10:00:00Z"),
    ]
    first = corpus.paginate_corpus(entries, {"limit": 2, "sort": "updated_at_desc"})
    assert [i["record_id"] for i in first["items"]] == ["ENC-TSK-FFF", "ENC-TSK-EEE"]
    cursor = first["next_cursor"]
    assert cursor

    # The "other container": ENC-TSK-EEE is absent from its cache entirely.
    other = [e for e in entries if e["record_id"] != "ENC-TSK-EEE"]
    second = corpus.paginate_corpus(
        other, {"limit": 2, "sort": "updated_at_desc", "cursor": cursor}
    )
    assert [i["record_id"] for i in second["items"]] == ["ENC-TSK-DDD", "ENC-TSK-CCC"]


def test_paginate_cursor_key_missing_desc_tiebreak():
    # Equal updated_at rows order record_key DESC under the reverse-tuple sort;
    # the order-seek must resume strictly after (ts, key) in that ordering.
    ts = "2026-07-05T12:00:00Z"
    entries = [
        _entry("ENC-TSK-CCC", updated_at=ts),
        _entry("ENC-TSK-BBB", updated_at=ts),
        _entry("ENC-TSK-AAA", updated_at=ts),
    ]
    first = corpus.paginate_corpus(entries, {"limit": 1, "sort": "updated_at_desc"})
    assert first["items"][0]["record_id"] == "ENC-TSK-CCC"
    cursor = first["next_cursor"]

    other = [e for e in entries if e["record_id"] != "ENC-TSK-CCC"]
    second = corpus.paginate_corpus(
        other, {"limit": 2, "sort": "updated_at_desc", "cursor": cursor}
    )
    assert [i["record_id"] for i in second["items"]] == ["ENC-TSK-BBB", "ENC-TSK-AAA"]


def test_paginate_cursor_key_missing_asc_sort_order_seeks():
    entries = [
        _entry("ENC-TSK-AAA", updated_at="2026-07-05T10:00:00Z"),
        _entry("ENC-TSK-BBB", updated_at="2026-07-05T11:00:00Z"),
        _entry("ENC-TSK-CCC", updated_at="2026-07-05T12:00:00Z"),
        _entry("ENC-TSK-DDD", updated_at="2026-07-05T13:00:00Z"),
    ]
    first = corpus.paginate_corpus(entries, {"limit": 2, "sort": "record_id_asc"})
    assert [i["record_id"] for i in first["items"]] == ["ENC-TSK-AAA", "ENC-TSK-BBB"]
    cursor = first["next_cursor"]

    other = [e for e in entries if e["record_id"] != "ENC-TSK-BBB"]
    second = corpus.paginate_corpus(
        other, {"limit": 2, "sort": "record_id_asc", "cursor": cursor}
    )
    assert [i["record_id"] for i in second["items"]] == ["ENC-TSK-CCC", "ENC-TSK-DDD"]
