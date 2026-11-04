"""Unit tests for tools/backfill_brd_subtype.py (ENC-FTR-152 / ENC-TSK-S25 AC-8)."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys

MODULE_PATH = pathlib.Path(__file__).with_name("backfill_brd_subtype.py")
SPEC = importlib.util.spec_from_file_location("enceladus_backfill_brd_subtype_under_test", MODULE_PATH)
backfill = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = backfill
SPEC.loader.exec_module(backfill)


class FakeDocumentClient:
    """In-memory stand-in for the document API: GET, search, If-Match PATCH."""

    def __init__(self, env, docs, page_size=50):
        self.env = env
        self.base = f"https://{env}.example/api/v1/documents"
        self.page_size = page_size
        self.docs = {d["document_id"]: copy.deepcopy(d) for d in docs}
        own = backfill.sentinel_document_id(env)
        self.docs[own] = {"document_id": own, "project_id": "enceladus", "document_subtype": "doc"}
        self.patches = []

    def get(self, document_id):
        if document_id not in self.docs:
            return 404, {}
        return 200, copy.deepcopy(self.docs[document_id])

    def search(self, **params):
        rows = [d for d in self.docs.values() if not d["document_id"].startswith("DOC-SENTINEL")]
        if params.get("project"):
            rows = [d for d in rows if d.get("project_id") == params["project"]]
        subtype = params.get("document_subtype", "")
        pattern = params.get("subtypepattern", "")
        if subtype:
            rows = [d for d in rows if d.get("document_subtype") == subtype]
        if pattern:
            rows = [d for d in rows if d.get("document_subtype") == "doc" and d.get("subtypepattern", "") == pattern]
        return 200, {"documents": rows[: self.page_size], "total_matches": len(rows)}

    def patch(self, document_id, payload, if_match):
        doc = self.docs[document_id]
        if if_match != doc["content_hash"]:
            return 412, {"error_envelope": {"code": "CONTENT_HASH_MISMATCH"}}
        self.patches.append((document_id, payload))
        doc["document_subtype"] = payload["document_subtype"]
        doc["subtypepattern"] = payload["subtypepattern"]
        doc["version"] = doc.get("version", 1) + 1
        return 200, {"success": True}

    def list_project_ids(self):
        return sorted({d.get("project_id", "") for d in self.docs.values()} - {""})


def _doc(doc_id, subtype="doc", pattern="brd", project="enceladus", content_hash=None):
    return {
        "document_id": doc_id,
        "project_id": project,
        "title": f"BRD -- {doc_id}",
        "document_subtype": subtype,
        "subtypepattern": pattern,
        "content_hash": content_hash or (doc_id[-1].lower() * 64),
        "version": 1,
        "status": "active",
        "created_at": "2026-10-01T00:00:00Z",
    }


def _sentinel_ids():
    return backfill.sentinel_document_id("prod"), backfill.sentinel_document_id("gamma")


def test_base_urls_come_from_the_elr_profile_table():
    assert backfill.document_base_url("prod").endswith("execute-api.us-west-2.amazonaws.com/api/v1/documents")
    assert backfill.document_base_url("gamma") == "https://enceladus-gamma.jreese.net/api/v1/documents"


def test_classify_shapes():
    assert backfill.classify(_doc("DOC-1"), ids_mode=False) == "eligible"
    assert backfill.classify(_doc("DOC-2", subtype="brd", pattern=""), ids_mode=False) == "already"
    assert backfill.classify(_doc("DOC-3", subtype="brd", pattern="brd"), ids_mode=False) == "eligible"
    assert backfill.classify(_doc("DOC-4", pattern="research"), ids_mode=False).startswith("ineligible")
    assert backfill.classify(_doc("DOC-5", pattern=""), ids_mode=True) == "eligible"
    assert backfill.classify(_doc("DOC-6", subtype="handoff", pattern=""), ids_mode=True).startswith("ineligible")


def test_plane_check_requires_own_sentinel_and_absent_twin():
    client = FakeDocumentClient("gamma", [])
    assert backfill.plane_check(client)["ok"] is True
    prod_sentinel, _ = _sentinel_ids()
    client.docs[prod_sentinel] = {"document_id": prod_sentinel}
    assert backfill.plane_check(client)["ok"] is False


def test_dry_run_writes_nothing():
    client = FakeDocumentClient("gamma", [_doc("DOC-A"), _doc("DOC-B")])
    result = backfill.migrate(client, apply=False)
    assert result["ok"] is True
    assert result["counts"] == {"would_migrate": 2}
    assert client.patches == []


def test_apply_migrates_metadata_only_then_second_run_is_a_no_op():
    docs = [_doc("DOC-A"), _doc("DOC-B", project="glamcocks"), _doc("DOC-C", pattern="research")]
    client = FakeDocumentClient("gamma", docs)

    first = backfill.migrate(client, apply=True)
    assert first["ok"] is True
    assert first["counts"] == {"migrated": 2}
    assert first["remaining_legacy"] == 0
    for row in first["rows"]:
        assert row["after"]["content_hash"] == row["before"]["content_hash"]
        assert row["after"]["document_subtype"] == "brd"
        assert row["after"]["subtypepattern"] == ""
    assert {doc_id for doc_id, _ in client.patches} == {"DOC-A", "DOC-B"}
    assert all(payload["caused_by"] == "ENC-TSK-S25" for _, payload in client.patches)
    assert client.docs["DOC-C"]["subtypepattern"] == "research"

    second = backfill.migrate(client, apply=True)
    assert second["ok"] is True
    assert second["counts"] == {}
    assert second["remaining_legacy"] == 0
    assert len(client.patches) == 2


def test_apply_loops_past_the_search_page_cap():
    docs = [_doc(f"DOC-P{i:02d}") for i in range(7)]
    client = FakeDocumentClient("gamma", docs, page_size=3)
    result = backfill.migrate(client, apply=True)
    assert result["counts"] == {"migrated": 7}
    assert result["remaining_legacy"] == 0


def test_ids_mode_flags_approved_candidates_and_skips_others():
    docs = [_doc("DOC-U", pattern=""), _doc("DOC-I", subtype="idea", pattern=""), _doc("DOC-H", subtype="handoff", pattern="")]
    client = FakeDocumentClient("gamma", docs)
    result = backfill.migrate(client, apply=True, ids=["DOC-U", "DOC-I", "DOC-H", "DOC-MISSING"])
    outcomes = {row["document_id"]: row["outcome"] for row in result["rows"]}
    assert outcomes == {"DOC-U": "migrated", "DOC-I": "migrated", "DOC-H": "skipped", "DOC-MISSING": "failed"}
    assert result["ok"] is False

    rerun = backfill.migrate(client, apply=True, ids=["DOC-U", "DOC-I"])
    assert {row["outcome"] for row in rerun["rows"]} == {"already"}


def test_hash_race_fails_the_document_without_writing():
    client = FakeDocumentClient("gamma", [_doc("DOC-R")])
    real_get = client.get

    def racing_get(document_id):
        status, doc = real_get(document_id)
        if document_id == "DOC-R" and not client.patches:
            doc["content_hash"] = "f" * 64  # another writer moved the body after our read
        return status, doc

    client.get = racing_get
    row = backfill.migrate_one(client, "DOC-R", apply=True, ids_mode=False)
    assert row["outcome"] == "failed"
    assert "412" in row["reason"]
    assert client.patches == []


def test_census_reports_both_shapes():
    client = FakeDocumentClient("prod", [_doc("DOC-A"), _doc("DOC-B", subtype="brd", pattern="")])
    result = backfill.census(client)
    assert result["plane_check"]["ok"] is True
    assert result["legacy_doc_subtypepattern_brd"]["ids"] == ["DOC-A"]
    assert result["document_subtype_brd"]["ids"] == ["DOC-B"]


def test_prod_apply_requires_io_approval():
    assert backfill.main(["migrate", "--env", "prod", "--apply"]) == 2
