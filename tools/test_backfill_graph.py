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


# --- ENC-TSK-S33: --shuffle-seed and --edge-type-counts ------------------------------

def _items():
    ents = [{"record_id": f"E{i}", "record_type": "task"} for i in range(40)]
    rels = [{"record_id": f"rel#E{i}#relates-to#E{i + 1}", "record_type": "relationship"} for i in range(20)]
    return ents, rels


def test_phase2_sequence_default_order_is_entities_then_relationships():
    ents, rels = _items()
    seq = backfill_graph.phase2_sequence(ents, rels)
    assert [k for k, _ in seq] == ["entity"] * 40 + ["relationship"] * 20


def test_phase2_sequence_seeded_permutation_is_deterministic_and_complete():
    ents, rels = _items()
    a = backfill_graph.phase2_sequence(ents, rels, seed=1)
    b = backfill_graph.phase2_sequence(ents, rels, seed=1)
    c = backfill_graph.phase2_sequence(ents, rels, seed=2)
    ids = lambda seq: [r["record_id"] for _, r in seq]  # noqa: E731
    assert ids(a) == ids(b)
    assert ids(a) != ids(c)
    assert sorted(ids(a)) == sorted(r["record_id"] for r in ents + rels)
    kinds = [k for k, _ in a]
    assert kinds != ["entity"] * 40 + ["relationship"] * 20  # interleaved, not grouped


def _fake_driver(total_rows, shared_rows):
    from unittest.mock import MagicMock

    session = MagicMock()

    def run(query, *a, **k):
        assert "DELETE" not in query and "SET " not in query and "MERGE" not in query  # read-only
        return total_rows if "AS total" in query else shared_rows

    session.run.side_effect = run
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    return driver


def test_edge_type_counts_shape_and_residue_report():
    total = [
        {"t": "RELATED_TO", "total": 10, "marked": 6, "unmarked": 1, "source_id": 3},
        {"t": "INFORMS", "total": 4, "marked": 4, "unmarked": 0, "source_id": 0},
        {"t": "MUTATED", "total": 5, "marked": 0, "unmarked": 5, "source_id": 0},
        {"t": "BLOCKS", "total": 2, "marked": 0, "unmarked": 0, "source_id": 2},
        {"t": "LEGACY_GHOST", "total": 7, "marked": 0, "unmarked": 7, "source_id": 0},
    ]
    shared = [{"t": "RELATED_TO", "shared_triples": 3}]
    out = backfill_graph.edge_type_counts(_fake_driver(total, shared))
    assert out["total_edges"] == 28
    assert out["residue"] == ["LEGACY_GHOST"]
    rt = out["types"]["RELATED_TO"]
    assert (rt["total"], rt["marked"], rt["unmarked"], rt["source_id"]) == (10, 6, 1, 3)
    assert rt["shared_triples"] == 3 and rt["owner"] == "start"
    assert out["types"]["INFORMS"]["owner"] == "end"
    assert out["types"]["MUTATED"]["owner"] == "external"
    assert out["types"]["BLOCKS"]["owner"] == "relationship_record"
    assert out["types"]["INFORMS"]["shared_triples"] == 0
    import json
    json.dumps(out)  # JSON serialisable


def _run_main(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["backfill_graph.py", *argv])
    backfill_graph.main()


def test_wipe_guard_refuses_shuffle_seed_with_wipe_existing(monkeypatch, capsys):
    import pytest

    def boom(*a, **k):
        raise AssertionError("must refuse before touching AWS or Neo4j")

    monkeypatch.setattr(backfill_graph, "get_neo4j_credentials", boom)
    monkeypatch.setattr(backfill_graph, "_load_projection_records", boom)
    with pytest.raises(SystemExit) as exc:
        _run_main(monkeypatch, "--shuffle-seed", "1", "--wipe-existing")
    assert exc.value.code == 2
    assert "--wipe-existing" in capsys.readouterr().err


def test_edge_type_counts_refuses_write_flags(monkeypatch):
    import pytest

    for extra in (["--wipe-existing"], ["--nodes-only"], ["--shuffle-seed", "3"]):
        with pytest.raises(SystemExit) as exc:
            _run_main(monkeypatch, "--edge-type-counts", *extra)
        assert exc.value.code == 2


def test_edge_type_counts_cli_prints_json_and_skips_dynamodb(monkeypatch, capsys):
    import json

    def boom(*a, **k):
        raise AssertionError("--edge-type-counts must not scan DynamoDB")

    closed = []

    class _Drv:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(backfill_graph, "_load_projection_records", boom)
    monkeypatch.setattr(backfill_graph, "get_neo4j_credentials", lambda *a, **k: {})
    monkeypatch.setattr(backfill_graph, "get_neo4j_driver", lambda creds: _Drv())
    monkeypatch.setattr(backfill_graph, "edge_type_counts", lambda d: {"total_edges": 0, "types": {}, "residue": []})
    _run_main(monkeypatch, "--edge-type-counts")
    assert json.loads(capsys.readouterr().out) == {"total_edges": 0, "types": {}, "residue": []}
    assert closed == [True]
