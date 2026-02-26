"""Unit tests for feed_query incremental delta behavior."""

from __future__ import annotations

import importlib.util
import json
import os


_SPEC = importlib.util.spec_from_file_location(
    "feed_query_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_query = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_query)


def _feed_get_event(since: str) -> dict:
    return {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/api/v1/feed",
        "headers": {"Cookie": "enceladus_id_token=test-token"},
        "queryStringParameters": {"since": since},
    }


def test_since_delta_applies_lookback_and_returns_no_cache(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})

    captured = {}

    def _fake_query_incremental(since_iso: str):
        captured["since_iso"] = since_iso
        return [], [], [], ["ENC-TSK-123"]

    monkeypatch.setattr(feed_query, "_query_incremental", _fake_query_incremental)

    resp = feed_query.lambda_handler(_feed_get_event("2026-02-25T12:00:10Z"), None)

    assert resp["statusCode"] == 200
    assert captured["since_iso"] == "2026-02-25T12:00:00Z"
    assert resp["headers"]["Cache-Control"] == "no-cache, no-store, must-revalidate"
    payload = json.loads(resp["body"])
    assert payload["closed_ids"] == ["ENC-TSK-123"]


def test_invalid_since_returns_400(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})

    resp = feed_query.lambda_handler(_feed_get_event("not-a-date"), None)

    assert resp["statusCode"] == 400
    payload = json.loads(resp["body"])
    assert "since" in payload["error"]
