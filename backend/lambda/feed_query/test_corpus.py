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
