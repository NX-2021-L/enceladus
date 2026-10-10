"""Regenerates the @io-kit/feed conformance fixture from feed_query's own handler code (DVP-TSK-919).

The committed conformance/enceladus-feed-query.json is replayed by frontend/ui-v2's vitest runner
(src/feed/feedConformance.test.ts) through @io-kit/feed/testing, so FT-01..FT-12 run against what this
code actually emits: corpus pages come from corpus.paginate_corpus (real signed v1 cursors),
record_key is the real single-colon form 'tracker:<project>:<id>', and error bodies come from _error().

    python3 -m pytest -q test_conformance_fixture.py        # verifies the committed file is current
    REGEN_CONFORMANCE=1 python3 -m pytest -q test_conformance_fixture.py   # rewrites it
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import corpus  # noqa: E402
import cursor_codec  # noqa: E402
import lambda_function  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "conformance", "enceladus-feed-query.json")
NOW = 1788228600  # 2026-09-01T02:10:00Z; the fixture's frozen clock
BASE = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
HEAD_SEQ = 120


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry(i, updated_at=None, version_seq=None):
    rid = f"ENC-TSK-{1000 + i}"
    return {
        "record_id": rid, "record_type": "task", "project_id": "enceladus", "title": f"Task {1000 + i}",
        "updated_at": updated_at or _iso(BASE + timedelta(minutes=i)), "source": "tracker",
        "record_key": corpus.tracker_record_key("enceladus", rid), "attrs": {}, "version_seq": version_seq or i,
    }


def _walk(entries, sort="updated_at_desc", limit=50):
    """Every request/response pair of a full cursor walk through paginate_corpus."""
    out, cursor = [], ""
    while True:
        q = {"limit": str(limit), "sort": sort}
        if cursor:
            q["cursor"] = cursor
        page = corpus.paginate_corpus(entries, corpus.parse_corpus_query(dict(q)))
        out.append({"request": {"path": "/api/v1/feed/corpus", "query": q}, "status": 200, "response": page})
        cursor = page["next_cursor"] or ""
        if not cursor:
            return out


def _delta(since, latest, items, tombstones, truncated=False, at="2026-09-01T02:05:00Z", phase=None):
    q = {"since": str(since)}
    if phase:
        q["_phase"] = phase
    return {
        "request": {"path": "/api/v1/feed/delta", "query": q}, "status": 200,
        "response": {"success": True, "generated_at": at, "since": since, "latest_version_seq": latest,
                     "truncated": truncated, "items": items, "tombstones": tombstones},
    }


def _tombstone(i, seq):
    rid = f"ENC-TSK-{1000 + i}"
    return {"record_key": corpus.tracker_record_key("enceladus", rid), "record_id": rid,
            "record_type": "task", "project_id": "enceladus", "version_seq": seq}


def build_fixture():
    # Frozen clock + fixed key so cursors (and the file) are deterministic.
    os.environ["FEED_CURSOR_KEYS"] = json.dumps({"conformance": "conformance-test-key"})
    os.environ["FEED_CURSOR_ACTIVE_KID"] = "conformance"
    os.environ.pop("COORDINATION_INTERNAL_API_KEY", None)
    saved_env = {k: os.environ.get(k) for k in ("FEED_CURSOR_KEYS", "FEED_CURSOR_ACTIVE_KID", "COORDINATION_INTERNAL_API_KEY")}
    real_time = cursor_codec.time.time
    cursor_codec.time.time = lambda: NOW
    try:
        entries = [_entry(i) for i in range(1, HEAD_SEQ + 1)]
        recorded = _walk(entries)
        # after one edit: 1110 re-upserted at seq 121, 1100 tombstoned at seq 122
        edited = [e for e in entries if e["record_id"] != "ENC-TSK-1100"]
        edited = [_entry(110, "2026-09-01T02:01:00Z", 121) if e["record_id"] == "ENC-TSK-1110" else e for e in edited]
        for row in _walk(edited):
            if not row["request"]["query"].get("cursor"):
                row["request"]["query"]["_phase"] = "after_edit"
                recorded.append(row)
        recorded += [
            _delta(HEAD_SEQ, HEAD_SEQ, [], [], at="2026-09-01T02:10:00Z"),
            _delta(HEAD_SEQ, 122, [_entry(110, "2026-09-01T02:01:00Z", 121)], [_tombstone(100, 122)], phase="after_edit"),
            _delta(115, 122, [_entry(i) for i in range(116, 121)] + [_entry(110, "2026-09-01T02:01:00Z", 121)],
                   [_tombstone(100, 122)], phase="after_edit"),
            _delta(0, 500, [_entry(i) for i in range(1, 6)], [], truncated=True),
        ]
        # A cursor minted for another sort must be refused by the handler: record the real 400.
        foreign = corpus.paginate_corpus(entries, corpus.parse_corpus_query({"limit": "50", "sort": "title_asc"}))["next_cursor"]
        bad_q = {"limit": "50", "sort": "updated_at_desc", "cursor": foreign}
        assert corpus.decode_cursor(foreign, corpus.cursor_filter(corpus.parse_corpus_query(bad_q))) is None
        err = lambda_function._error(400, "Invalid cursor", code="cursor_invalid")
        recorded.append({"request": {"path": "/api/v1/feed/corpus", "query": bad_q}, "status": err["statusCode"],
                         "response": json.loads(err["body"])})
        return {
            "provenance": "generated by backend/lambda/feed_query/test_conformance_fixture.py from corpus.paginate_corpus "
                          "and lambda_function._error (DVP-TSK-919); regenerate with REGEN_CONFORMANCE=1",
            "recorded_from": "handler code, frozen clock 2026-09-01T02:10:00Z, test signing key; record_key uses the "
                             "real single-colon form tracker:<project>:<id>. Phase 'after_edit' = ENC-TSK-1110 "
                             "re-upserted at seq 121, ENC-TSK-1100 tombstoned at seq 122.",
            "handler": {"corpus": "GET /api/v1/feed/corpus?limit&cursor&sort", "delta": "GET /api/v1/feed/delta?since=<version_seq>",
                        "max_delta_items": 500, "cursor": "signed v1: base64url(JSON{v,k,f,scope,exp,kid}).base64url(HMAC-SHA256)"},
            "now": "2026-09-01T02:10:00Z", "head_seq": HEAD_SEQ, "page_size": 50,
            "expected_head_ids": [e["record_id"] for e in sorted(entries, key=lambda e: e["updated_at"], reverse=True)],
            "invalid_cursor": {"sort": "updated_at_desc", "cursor": foreign},
            "recorded": recorded,
        }
    finally:
        cursor_codec.time.time = real_time
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_committed_fixture_matches_what_the_handler_emits():
    built = json.dumps(build_fixture(), indent=1, sort_keys=True) + "\n"
    if os.environ.get("REGEN_CONFORMANCE") == "1":
        with open(FIXTURE, "w") as fh:
            fh.write(built)
    with open(FIXTURE) as fh:
        assert fh.read() == built, "stale conformance fixture: run REGEN_CONFORMANCE=1 python3 -m pytest -q test_conformance_fixture.py"


def test_fixture_has_signed_cursors_single_colon_keys_and_a_400():
    fx = json.loads(open(FIXTURE).read())
    pages = [r for r in fx["recorded"] if r["request"]["path"].endswith("/corpus") and r["status"] == 200]
    assert all("." in (r["response"]["next_cursor"] or ".") for r in pages)
    assert all(i["record_key"].startswith("tracker:enceladus:") and "::" not in i["record_key"]
               for r in pages for i in r["response"]["items"])
    assert any(r["status"] == 400 for r in fx["recorded"])
