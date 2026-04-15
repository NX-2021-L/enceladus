"""Unit tests for devops-titan-embedding-backfill Lambda and shared helpers.

Exercises the pure-function surface without real Bedrock or Neo4j — network
clients are stubbed. Run locally with:

    cd backend/lambda/titan_embedding_backfill
    python3 -m pytest test_lambda_function.py -v

Or via repo-wide pytest from the root.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make both the shared helper and the local Lambda importable.
SHARED_PATH = (
    Path(__file__).resolve().parent.parent
    / "shared_layer"
    / "python"
)
LAMBDA_PATH = Path(__file__).resolve().parent
for p in (str(SHARED_PATH), str(LAMBDA_PATH)):
    if p not in sys.path:
        sys.path.insert(0, p)

from enceladus_shared import embedding as shared_embedding  # noqa: E402


# ---------------------------------------------------------------------------
# extract_embeddable_text
# ---------------------------------------------------------------------------


def test_extract_text_prefers_title_intent_description():
    record = {
        "title": "Add HNSW index",
        "intent": "Phase 1 gate requires vector indexes",
        "description": "Creates six per-label indexes",
        "summary": "should not appear when description present",
    }
    text = shared_embedding.extract_embeddable_text(record)
    assert "Title: Add HNSW index" in text
    assert "Intent: Phase 1 gate" in text
    assert "Description: Creates six" in text
    assert "should not appear" not in text


def test_extract_text_falls_through_to_summary_when_no_description():
    record = {"title": "Doc title", "summary": "Doc summary body"}
    text = shared_embedding.extract_embeddable_text(record)
    assert "Title: Doc title" in text
    assert "Summary: Doc summary body" in text


def test_extract_text_fallback_when_all_text_missing():
    record = {"record_id": "task#ENC-TSK-B91", "record_type": "task"}
    text = shared_embedding.extract_embeddable_text(record)
    assert "task" in text
    assert "ENC-TSK-B91" in text


def test_extract_text_truncates_over_cap(monkeypatch):
    monkeypatch.setattr(shared_embedding, "MAX_EMBEDDABLE_TEXT_CHARS", 50)
    record = {"title": "A" * 200}
    text = shared_embedding.extract_embeddable_text(record)
    assert len(text) == 50


# ---------------------------------------------------------------------------
# invoke_titan_v2_embedding
# ---------------------------------------------------------------------------


def _mock_bedrock_response(vector):
    body = MagicMock()
    body.read.return_value = json.dumps({"embedding": vector}).encode("utf-8")
    return {"body": body}


def test_invoke_titan_happy_path():
    client = MagicMock()
    client.invoke_model.return_value = _mock_bedrock_response([0.1] * 256)
    vec = shared_embedding.invoke_titan_v2_embedding(client, "hello world", max_retries=1)
    assert len(vec) == 256
    assert all(isinstance(x, float) for x in vec)
    # Request body must pin dimensions and normalize per Phase 1 contract.
    kwargs = client.invoke_model.call_args.kwargs
    body = json.loads(kwargs["body"])
    assert body == {"inputText": "hello world", "dimensions": 256, "normalize": True}
    assert kwargs["modelId"] == "amazon.titan-embed-text-v2:0"


def test_invoke_titan_raises_on_empty_text():
    with pytest.raises(ValueError):
        shared_embedding.invoke_titan_v2_embedding(MagicMock(), "   ")


def test_invoke_titan_retries_on_throttling(monkeypatch):
    monkeypatch.setattr(shared_embedding.time, "sleep", lambda *_: None)
    client = MagicMock()

    class ThrottlingException(Exception):
        pass

    # First two calls raise, third succeeds.
    client.invoke_model.side_effect = [
        ThrottlingException("Rate exceeded"),
        ThrottlingException("Rate exceeded"),
        _mock_bedrock_response([0.2] * 256),
    ]
    vec = shared_embedding.invoke_titan_v2_embedding(
        client,
        "retryable",
        max_retries=5,
        initial_backoff_seconds=0.01,
    )
    assert len(vec) == 256
    assert client.invoke_model.call_count == 3


def test_invoke_titan_propagates_non_retryable_error():
    client = MagicMock()

    class AccessDeniedException(Exception):
        pass

    client.invoke_model.side_effect = AccessDeniedException("Not authorized")
    with pytest.raises(AccessDeniedException):
        shared_embedding.invoke_titan_v2_embedding(client, "boom", max_retries=3)


def test_invoke_titan_rejects_bad_response_shape():
    client = MagicMock()
    client.invoke_model.return_value = _mock_bedrock_response([0.1] * 512)  # wrong dim
    with pytest.raises(RuntimeError):
        shared_embedding.invoke_titan_v2_embedding(client, "x", dimensions=256, max_retries=1)


# ---------------------------------------------------------------------------
# write_embedding_to_neo4j
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, returned_count):
        self._count = returned_count
        self.last_cypher = None
        self.last_params = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def run(self, cypher, **params):
        self.last_cypher = cypher
        self.last_params = params
        result = MagicMock()
        result.single.return_value = {"updated": self._count}
        return result


class _FakeDriver:
    def __init__(self, returned_count=1):
        self.session_obj = _FakeSession(returned_count)

    def session(self):
        return self.session_obj


def test_write_embedding_success():
    driver = _FakeDriver(returned_count=1)
    wrote = shared_embedding.write_embedding_to_neo4j(
        driver,
        record_id="task#ENC-TSK-B91",
        label="Task",
        embedding=[0.0] * 256,
        project_id="enceladus",
    )
    assert wrote is True
    assert "MATCH (n:Task" in driver.session_obj.last_cypher
    # Record ID must be stripped of the `task#` prefix.
    assert driver.session_obj.last_params["record_id"] == "ENC-TSK-B91"
    assert driver.session_obj.last_params["project_id"] == "enceladus"


def test_write_embedding_returns_false_when_node_missing():
    driver = _FakeDriver(returned_count=0)
    wrote = shared_embedding.write_embedding_to_neo4j(
        driver,
        record_id="ENC-TSK-B91",
        label="Task",
        embedding=[0.1] * 256,
    )
    assert wrote is False


def test_write_embedding_rejects_unknown_label():
    driver = _FakeDriver()
    with pytest.raises(ValueError):
        shared_embedding.write_embedding_to_neo4j(
            driver,
            record_id="x",
            label="Project",  # valid Neo4j label but not a governed retrieval target
            embedding=[0.0] * 256,
        )


def test_write_embedding_rejects_empty_record_id():
    driver = _FakeDriver()
    with pytest.raises(ValueError):
        shared_embedding.write_embedding_to_neo4j(
            driver,
            record_id="",
            label="Task",
            embedding=[0.0] * 256,
        )


# ---------------------------------------------------------------------------
# Lambda handler smoke test (dry_run, stubbed iteration)
# ---------------------------------------------------------------------------


def test_lambda_dry_run_emits_coverage_skeleton(monkeypatch):
    # Import the Lambda module via its local path (embedding.py is resolved
    # via the shared_layer sys.path hack at the top of this file).
    os.environ.setdefault("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")

    # Ensure a clean module load — reload if previously imported.
    if "lambda_function" in sys.modules:
        importlib.reload(sys.modules["lambda_function"])
    import lambda_function  # type: ignore

    # Stub corpus iteration so the test does not hit DynamoDB.
    def _stub_iter(allowed_labels=None):
        yield "ENC-TSK-B91", "Task", {
            "record_id": "task#ENC-TSK-B91",
            "record_type": "task",
            "title": "Stubbed task",
            "intent": "unit test",
            "project_id": "enceladus",
        }

    monkeypatch.setattr(lambda_function, "_iter_corpus", _stub_iter)

    # Stub Bedrock.
    client = MagicMock()
    client.invoke_model.return_value = _mock_bedrock_response([0.3] * 256)
    monkeypatch.setattr(lambda_function, "_get_bedrock_runtime", lambda: client)

    result = lambda_function.lambda_handler({"dry_run": True}, None)
    assert result["status"] == "ok"
    assert result["processed"] == 1
    assert result["dry_run"] is True
    assert result["dimensions"] == 256
    assert result["model_id"] == "amazon.titan-embed-text-v2:0"
    # Coverage is skipped in dry_run.
    assert result["coverage"] == {}
