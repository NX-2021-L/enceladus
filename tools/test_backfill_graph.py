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
