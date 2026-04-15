"""Unit tests for devops-titan-embedding-backfill Lambda.

Exercises the pure-function surface without real Bedrock or Neo4j — network
clients are stubbed. Runtime parity with ENC-TSK-B94 is preserved by
importing `embedding.py` from the canonical graph_sync location (at test
time we copy it to the test dir via sys.path manipulation, matching what
deploy.sh does at build time).

Run locally with:

    cd backend/lambda/titan_embedding_backfill
    python3 -m pytest test_lambda_function.py -v
"""

from __future__ import annotations

import importlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure the graph_sync/embedding.py module is importable as `embedding`
# before lambda_function.py loads (it imports `from embedding import ...`).
# We copy the file into a tempdir on first import and prepend it to sys.path.
REPO_ROOT = Path(__file__).resolve().parents[3]
GRAPH_SYNC_EMBEDDING = REPO_ROOT / "backend" / "lambda" / "graph_sync" / "embedding.py"
LAMBDA_DIR = Path(__file__).resolve().parent


@pytest.fixture(autouse=True, scope="session")
def _stage_embedding_module(tmp_path_factory):
    """Copy graph_sync/embedding.py next to the Lambda so `from embedding import ...` resolves."""
    stage_dir = tmp_path_factory.mktemp("titan-embed-test-stage")
    dest = stage_dir / "embedding.py"
    shutil.copy(str(GRAPH_SYNC_EMBEDDING), str(dest))
    # Also make lambda_function.py importable from the same stage dir so
    # the tests exercise the real packaged shape.
    shutil.copy(str(LAMBDA_DIR / "lambda_function.py"), str(stage_dir / "lambda_function.py"))
    sys.path.insert(0, str(stage_dir))
    yield stage_dir
    # Cleanup: drop from sys.path and evict modules we imported.
    for mod in ("embedding", "lambda_function"):
        sys.modules.pop(mod, None)
    try:
        sys.path.remove(str(stage_dir))
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Upstream helper sanity — confirms the ENC-TSK-B94 module still exposes
# the expected surface. A failure here means graph_sync/embedding.py diverged
# in a breaking way and the backfill Lambda must be updated in lockstep.
# ---------------------------------------------------------------------------


def test_upstream_helper_exposes_expected_symbols():
    import embedding  # noqa: E402

    expected = {
        "TITAN_MODEL_ID",
        "EMBEDDING_DIMENSIONS",
        "EMBEDDING_PROPERTY",
        "EMBEDDING_HASH_PROPERTY",
        "EMBEDDABLE_RECORD_TYPES",
        "build_embedding_text",
        "hash_embedding_text",
        "invoke_titan_v2",
    }
    missing = expected - set(dir(embedding))
    assert not missing, f"graph_sync/embedding.py missing expected symbols: {missing}"
    assert embedding.EMBEDDING_DIMENSIONS == 256
    assert embedding.TITAN_MODEL_ID == "amazon.titan-embed-text-v2:0"


def test_upstream_build_text_respects_title_intent_description():
    import embedding  # noqa: E402

    record = {
        "title": "Backfill Titan V2",
        "intent": "Phase 1 corpus embedding",
        "description": "Batch-embed all governed records",
    }
    text = embedding.build_embedding_text(record)
    assert "Backfill Titan V2" in text
    assert "Phase 1 corpus embedding" in text
    assert "Batch-embed all governed records" in text


def test_upstream_hash_is_stable():
    import embedding  # noqa: E402

    a = embedding.hash_embedding_text("hello world")
    b = embedding.hash_embedding_text("hello world")
    c = embedding.hash_embedding_text("hello worlds")
    assert a == b
    assert a != c
    assert len(a) == 16  # sha256 truncated to 16 chars


# ---------------------------------------------------------------------------
# Lambda write helper — label allow-list enforcement and Cypher shape.
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, returned_count=1, returned_hash=None):
        self._count = returned_count
        self._hash = returned_hash
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
        if "RETURN n.embedding_text_hash" in cypher:
            result.single.return_value = {"hash": self._hash}
        elif "count(n)" in cypher and "with_embedding" in cypher:
            result.single.return_value = {"total": 10, "with_embedding": 10}
        else:
            result.single.return_value = {"updated": self._count}
        return result


class _FakeDriver:
    def __init__(self, returned_count=1, returned_hash=None):
        self.session_obj = _FakeSession(returned_count, returned_hash)

    def session(self):
        return self.session_obj


def test_write_embedding_rejects_unknown_label():
    import lambda_function  # noqa: E402

    driver = _FakeDriver()
    with pytest.raises(ValueError):
        lambda_function._write_embedding(
            driver,
            record_id="x",
            label="Project",  # valid Neo4j label but not a governed retrieval target
            embedding=[0.0] * 256,
            embedding_hash="h",
            project_id="enceladus",
        )


def test_write_embedding_sets_both_vector_and_hash():
    import lambda_function  # noqa: E402

    driver = _FakeDriver(returned_count=1)
    wrote = lambda_function._write_embedding(
        driver,
        record_id="ENC-TSK-B91",
        label="Task",
        embedding=[0.1] * 256,
        embedding_hash="abc123",
        project_id="enceladus",
    )
    assert wrote is True
    cypher = driver.session_obj.last_cypher
    assert "MATCH (n:Task" in cypher
    assert "SET n.embedding = $vec" in cypher
    assert "n.embedding_text_hash = $h" in cypher
    assert driver.session_obj.last_params["record_id"] == "ENC-TSK-B91"
    assert driver.session_obj.last_params["h"] == "abc123"


def test_write_embedding_returns_false_when_node_missing():
    import lambda_function  # noqa: E402

    driver = _FakeDriver(returned_count=0)
    wrote = lambda_function._write_embedding(
        driver,
        record_id="ENC-TSK-MISSING",
        label="Task",
        embedding=[0.0] * 256,
        embedding_hash="h",
        project_id=None,
    )
    assert wrote is False


def test_probe_existing_hash_returns_value_when_present():
    import lambda_function  # noqa: E402

    driver = _FakeDriver(returned_hash="deadbeefdeadbeef")
    h = lambda_function._probe_existing_hash(driver, "ENC-TSK-B91", "Task", "enceladus")
    assert h == "deadbeefdeadbeef"


def test_probe_existing_hash_returns_none_when_absent():
    import lambda_function  # noqa: E402

    driver = _FakeDriver(returned_hash=None)
    h = lambda_function._probe_existing_hash(driver, "X", "Task", None)
    assert h is None


def test_probe_existing_hash_rejects_unknown_label():
    import lambda_function  # noqa: E402

    driver = _FakeDriver()
    assert lambda_function._probe_existing_hash(driver, "x", "Project", None) is None


def test_bare_id_strips_type_prefix():
    import lambda_function  # noqa: E402

    assert lambda_function._bare_id("task#ENC-TSK-B91") == "ENC-TSK-B91"
    assert lambda_function._bare_id("ENC-ISS-180") == "ENC-ISS-180"
    assert lambda_function._bare_id("") == ""


# ---------------------------------------------------------------------------
# Handler smoke tests (dry_run + label validation)
# ---------------------------------------------------------------------------


def _mock_bedrock_response(vector):
    body = MagicMock()
    body.read.return_value = json.dumps({"embedding": vector}).encode("utf-8")
    return {"body": body}


def test_handler_dry_run_emits_expected_response(monkeypatch):
    import embedding  # noqa: E402
    import lambda_function  # noqa: E402

    # Stub corpus iteration — one task, one issue — so the test is
    # deterministic and does not hit DynamoDB.
    def _stub_iter(allowed_labels=None):
        yield "ENC-TSK-B91", "Task", {
            "record_id": "task#ENC-TSK-B91",
            "record_type": "task",
            "title": "Stubbed task",
            "intent": "unit test",
            "project_id": "enceladus",
        }
        yield "ENC-ISS-180", "Issue", {
            "record_id": "issue#ENC-ISS-180",
            "record_type": "issue",
            "title": "Stubbed issue",
            "description": "unit test issue",
            "project_id": "enceladus",
        }

    monkeypatch.setattr(lambda_function, "_iter_corpus", _stub_iter)

    # Stub Bedrock at the upstream module level since lambda_function.py
    # imports invoke_titan_v2 directly.
    client = MagicMock()
    client.invoke_model.return_value = _mock_bedrock_response([0.3] * 256)
    monkeypatch.setattr(embedding, "_bedrock_runtime", client)

    result = lambda_function.lambda_handler({"dry_run": True}, None)

    assert result["status"] == "ok"
    assert result["processed"] == 2
    assert result["dry_run"] is True
    assert result["dimensions"] == 256
    assert result["model_id"] == "amazon.titan-embed-text-v2:0"
    # Coverage skipped in dry_run.
    assert result["coverage"] == {}
    assert result["per_label_processed"]["Task"] == 1
    assert result["per_label_processed"]["Issue"] == 1


def test_handler_uat_probe_short_circuits(monkeypatch):
    import lambda_function  # noqa: E402

    # Set up a trap: if the handler doesn't short-circuit, _iter_corpus will
    # be called and this test will fail with a deterministic message.
    def _trap(*_args, **_kwargs):
        raise AssertionError("_iter_corpus must NOT be called for UAT probe events")

    monkeypatch.setattr(lambda_function, "_iter_corpus", _trap)

    result = lambda_function.lambda_handler(
        {
            "rawPath": "/__uat_probe__",
            "requestContext": {"http": {"method": "GET"}},
            "headers": {},
        },
        None,
    )
    assert result["status"] == "ok"
    assert result["probe"] == "uat"
    assert result["model_id"] == "amazon.titan-embed-text-v2:0"
    assert result["dimensions"] == 256


def test_handler_rejects_unknown_label_in_event():
    import lambda_function  # noqa: E402

    with pytest.raises(ValueError):
        lambda_function.lambda_handler({"labels": ["Nonexistent"]}, None)


def test_handler_rejects_non_list_labels():
    import lambda_function  # noqa: E402

    with pytest.raises(ValueError):
        lambda_function.lambda_handler({"labels": "Task"}, None)


def test_handler_skips_records_with_matching_hash(monkeypatch):
    import embedding  # noqa: E402
    import lambda_function  # noqa: E402

    stub_record = {
        "record_id": "task#ENC-TSK-B91",
        "record_type": "task",
        "title": "Already embedded",
        "intent": "no change",
        "project_id": "enceladus",
    }

    def _stub_iter(allowed_labels=None):
        yield "ENC-TSK-B91", "Task", stub_record

    monkeypatch.setattr(lambda_function, "_iter_corpus", _stub_iter)

    # Stub the Neo4j driver so _probe_existing_hash returns the matching hash.
    matching_hash = embedding.hash_embedding_text(embedding.build_embedding_text(stub_record))
    driver = _FakeDriver(returned_hash=matching_hash)
    monkeypatch.setattr(lambda_function, "_get_neo4j_driver", lambda: driver)

    # Stub Bedrock (should not be called because the hash matches).
    client = MagicMock()
    monkeypatch.setattr(embedding, "_bedrock_runtime", client)

    result = lambda_function.lambda_handler({"skip_existing": True}, None)
    assert result["skipped"] == 1
    assert result["processed"] == 0
    client.invoke_model.assert_not_called()
