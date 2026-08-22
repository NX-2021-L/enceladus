"""Unit tests for ENC-TSK-O47: alias_prefixes-aware prefix resolution in
backend/lambda/coordination_api/project_utils.py's _key_for_record_id().

Same motivation as tools/enceladus-mcp-server/server.py's _get_prefix_map()
fix: ENC-TSK-O45 repoints gamma's MINT `prefix` to a disjoint value, and
without alias-aware resolution here too, gamma's pre-existing ENC-* records
would still 404/ValueError through coordination_api's checkout and
tracker-mutation routes even though the MCP server resolves them fine --
same bug, different door.

Covers:
  (a) a legacy alias prefix resolves to the right project_id (via the Scan
      fallback -- also asserts alias_prefixes is actually projected, since a
      resolver that reads a field the Scan never projects would silently
      never see it)
  (b) the new mint prefix resolves to the same project_id
  (c) an unknown prefix still raises ValueError (unchanged error shape)
  (d) a mint-vs-alias collision resolves to the MINT owner and is surfaced
      via both a logger.warning and the module-level _PREFIX_COLLISIONS
      registry, independent of table row order

Related: ENC-TSK-O47, ENC-TSK-O45, ENC-ISS-538
"""

import importlib.util
import logging
import pathlib
import sys

import pytest


MODULE_PATH = pathlib.Path(__file__).with_name("project_utils.py")
SPEC = importlib.util.spec_from_file_location("project_utils_prefix_unit", MODULE_PATH)
project_utils = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = project_utils
SPEC.loader.exec_module(project_utils)


@pytest.fixture(autouse=True)
def _reset_prefix_state():
    """Every test starts with a clean project cache and collision registry."""
    project_utils._project_cache.clear()
    project_utils._project_cache_at = 0.0
    project_utils._PREFIX_COLLISIONS.clear()
    yield
    project_utils._project_cache.clear()
    project_utils._project_cache_at = 0.0
    project_utils._PREFIX_COLLISIONS.clear()


def _ser_row(project_id, prefix=None, alias_prefixes=None):
    row = {"project_id": project_utils._serialize(project_id)}
    if prefix is not None:
        row["prefix"] = project_utils._serialize(prefix)
    if alias_prefixes is not None:
        row["alias_prefixes"] = project_utils._serialize(alias_prefixes)
    return row


class _FakeDdb:
    """Single-page fake; records every ProjectionExpression/ExpressionAttributeNames
    it was called with so tests can assert alias_prefixes is actually projected."""

    def __init__(self, rows):
        self.rows = rows
        self.scan_calls = []

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        return {"Items": list(self.rows)}


def test_alias_prefix_resolves_to_project_id(monkeypatch):
    """(a) A legacy alias_prefixes entry resolves to the owning project_id,
    and the Scan actually projects alias_prefixes (not just prefix)."""
    fake_ddb = _FakeDdb([_ser_row("gamma", prefix="MNT", alias_prefixes=["enc"])])
    monkeypatch.setattr(project_utils, "_get_ddb", lambda: fake_ddb)

    project_id, record_type, sk = project_utils._key_for_record_id("ENC-TSK-123")

    assert project_id == "gamma"
    assert record_type == "task"
    assert sk == "task#ENC-TSK-123"
    assert fake_ddb.scan_calls, "expected a Scan fallback call"
    assert "alias_prefixes" in fake_ddb.scan_calls[0]["ProjectionExpression"]


def test_mint_prefix_resolves_to_same_project_id(monkeypatch):
    """(b) The project's new MINT prefix resolves to that same project_id."""
    fake_ddb = _FakeDdb([_ser_row("gamma", prefix="MNT", alias_prefixes=["ENC"])])
    monkeypatch.setattr(project_utils, "_get_ddb", lambda: fake_ddb)

    project_id, record_type, sk = project_utils._key_for_record_id("MNT-TSK-001")

    assert project_id == "gamma"
    assert record_type == "task"
    assert sk == "task#MNT-TSK-001"


def test_unknown_prefix_still_raises_value_error(monkeypatch):
    """(c) A prefix present in neither `prefix` nor `alias_prefixes` still
    raises, with the pre-existing error message shape preserved."""
    fake_ddb = _FakeDdb([_ser_row("gamma", prefix="MNT", alias_prefixes=["ENC"])])
    monkeypatch.setattr(project_utils, "_get_ddb", lambda: fake_ddb)

    with pytest.raises(ValueError, match=r"^Unknown project prefix in record ID 'ZZZ-TSK-001'$"):
        project_utils._key_for_record_id("ZZZ-TSK-001")


@pytest.mark.parametrize(
    "row_order",
    ["alias_first", "mint_first"],
    ids=["alias-row-first", "mint-row-first"],
)
def test_mint_vs_alias_collision_resolves_to_mint_and_is_surfaced(monkeypatch, caplog, row_order):
    """(d) When a prefix is simultaneously one project's alias and another
    project's MINT prefix, MINT always wins -- regardless of table row order
    -- and the collision is never silently resolved: it is logged and
    recorded in project_utils._PREFIX_COLLISIONS."""
    alias_owner_row = _ser_row("legacy-holder", prefix="OTH", alias_prefixes=["ENC"])
    mint_owner_row = _ser_row("gamma", prefix="ENC", alias_prefixes=[])
    rows = (
        [alias_owner_row, mint_owner_row]
        if row_order == "alias_first"
        else [mint_owner_row, alias_owner_row]
    )
    fake_ddb = _FakeDdb(rows)
    monkeypatch.setattr(project_utils, "_get_ddb", lambda: fake_ddb)

    with caplog.at_level(logging.WARNING, logger=project_utils.logger.name):
        project_id, record_type, sk = project_utils._key_for_record_id("ENC-TSK-001")

    # MINT wins the resolution, deterministically, regardless of row order.
    assert project_id == "gamma"
    assert record_type == "task"
    assert sk == "task#ENC-TSK-001"

    # The collision is surfaced, not silently resolved.
    assert "ENC" in project_utils._PREFIX_COLLISIONS
    assert project_utils._PREFIX_COLLISIONS["ENC"] == {
        "mint_project_id": "gamma",
        "alias_project_id": "legacy-holder",
    }
    assert any(
        "PREFIX-COLLISION" in rec.message and "ENC" in rec.message
        for rec in caplog.records
    )
