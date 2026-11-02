"""Unit tests for tools/backfill_graph.py."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


MODULE_PATH = pathlib.Path(__file__).with_name("backfill_graph.py")
SPEC = importlib.util.spec_from_file_location("enceladus_backfill_graph_under_test", MODULE_PATH)
backfill_graph = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = backfill_graph
SPEC.loader.exec_module(backfill_graph)


def test_normalize_record_promotes_document_identity():
    normalized = backfill_graph._normalize_record({"document_id": "DOC-UNIT-123"})

    assert normalized["record_type"] == "document"
    assert normalized["record_id"] == "DOC-UNIT-123"


def test_entity_record_detection_includes_plan_lesson_and_document():
    assert backfill_graph._is_entity_record({"record_type": "plan"}) is True
    assert backfill_graph._is_entity_record({"record_type": "lesson"}) is True
    assert backfill_graph._is_entity_record({"record_type": "document"}) is True
    assert backfill_graph._is_entity_record({"record_type": "relationship"}) is False


def test_relationship_record_detection_is_explicit():
    assert backfill_graph._is_relationship_record({"record_type": "relationship"}) is True
    assert backfill_graph._is_relationship_record({"record_type": "task"}) is False


def test_backfill_node_upsert_projects_intent_and_description():
    """ENC-TSK-S05: backfill replays graph_sync._upsert_node, so it carries the same capped props."""
    from unittest.mock import MagicMock

    tx = MagicMock()
    backfill_graph.GS._upsert_node(tx, {
        "record_id": "ENC-TSK-ZZ1", "record_type": "task", "title": "t",
        "intent": "i" * 1500, "description": "d" * 2500,
    })
    props = tx.run.call_args.kwargs["props"]
    assert len(props["intent"]) == 1000
    assert len(props["description"]) == 2000


def test_nodes_only_never_reconciles_edges_and_honours_limit(monkeypatch):
    """ENC-TSK-S12 / P103-R14: --nodes-only upserts nodes only; no _reconcile_edges, no embedding."""
    from unittest.mock import MagicMock

    GS = backfill_graph.GS
    upserts, projects = [], []

    def _boom(*a, **k):
        raise AssertionError("_reconcile_edges must not run with --nodes-only")

    monkeypatch.setattr(GS, "_reconcile_edges", _boom)
    monkeypatch.setattr(GS, "_upsert_relationship_edge", _boom)
    monkeypatch.setattr(GS, "_delete_relationship_edge", _boom)
    monkeypatch.setattr(GS, "_upsert_node", lambda tx, rec: upserts.append(rec["record_id"]))
    monkeypatch.setattr(GS, "_upsert_project_node", lambda tx, pid: projects.append(pid))

    session = MagicMock()
    session.execute_write.side_effect = lambda fn, *a: fn(None, *a)
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    driver.session.return_value.__exit__.return_value = False

    records = [{"record_type": "task", "record_id": f"ENC-TSK-{i}", "project_id": "enceladus"} for i in range(5)]
    sleeps = []
    monkeypatch.setattr(backfill_graph.time, "sleep", lambda s: sleeps.append(s))

    assert backfill_graph.run_nodes_only(driver, records, sleep_ms=200, limit=3) == 3
    assert upserts == ["ENC-TSK-0", "ENC-TSK-1", "ENC-TSK-2"]
    assert projects == ["enceladus"] * 3
    assert sleeps == []

    many = [{"record_type": "task", "record_id": f"ENC-TSK-{i}", "project_id": "enceladus"} for i in range(250)]
    assert backfill_graph.run_nodes_only(driver, many, sleep_ms=200) == 250
    assert sleeps == [0.2, 0.2]
