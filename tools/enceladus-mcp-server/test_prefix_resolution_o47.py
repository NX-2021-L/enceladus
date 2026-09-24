"""Unit tests for ENC-TSK-O47: additive alias_prefixes support in
tools/enceladus-mcp-server/server.py's _get_prefix_map()/_resolve_prefix().

ENC-TSK-O45 repoints gamma's MINT `prefix` to a disjoint value. Because
`prefix` was previously the *only* resolution key, that would make gamma's
pre-existing ENC-* records unresolvable. ENC-TSK-O47 makes resolution
additive: a project's optional `alias_prefixes` list also resolves to its
project_id, and a MINT-vs-alias collision always resolves to the MINT
owner -- deterministically, and surfaced rather than silently resolved
(guarding against re-creating the ENC-ISS-538 collision class).

Covers:
  (a) a legacy alias prefix resolves to the right project_id
  (b) the new mint prefix resolves to the same project_id
  (c) an unknown prefix still raises ValueError (unchanged error shape)
  (d) a mint-vs-alias collision resolves to the MINT owner and is surfaced
      via both a logger.warning and the module-level _PREFIX_COLLISIONS
      registry, independent of API row order

Related: ENC-TSK-O47, ENC-TSK-O45, ENC-ISS-538
"""

import importlib.util
import logging
import pathlib
import sys

import pytest


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_prefix_unit", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


@pytest.fixture(autouse=True)
def _reset_prefix_state():
    """Every test starts with a clean prefix-map cache and collision registry."""
    server._PREFIX_MAP_CACHE = None
    server._PREFIX_COLLISIONS.clear()
    yield
    server._PREFIX_MAP_CACHE = None
    server._PREFIX_COLLISIONS.clear()


def _fake_projects_api(projects):
    def _request(method, path="", query=None):  # noqa: ARG001 - mirrors real signature
        assert method == "GET"
        return {"projects": list(projects)}

    return _request


def test_alias_prefix_resolves_to_project_id(monkeypatch):
    """(a) A legacy alias_prefixes entry resolves to the owning project_id."""
    monkeypatch.setattr(
        server,
        "_projects_api_request",
        _fake_projects_api(
            [{"project_id": "gamma", "prefix": "MNT", "alias_prefixes": ["enc"]}]
        ),
    )

    assert server._resolve_prefix("ENC") == "gamma"


def test_mint_prefix_resolves_to_same_project_id(monkeypatch):
    """(b) The project's new MINT prefix resolves to that same project_id."""
    monkeypatch.setattr(
        server,
        "_projects_api_request",
        _fake_projects_api(
            [{"project_id": "gamma", "prefix": "MNT", "alias_prefixes": ["ENC"]}]
        ),
    )

    assert server._resolve_prefix("MNT") == "gamma"


def test_unknown_prefix_still_raises_value_error(monkeypatch):
    """(c) A prefix present in neither `prefix` nor `alias_prefixes` still raises,
    with the pre-existing error message shape preserved."""
    monkeypatch.setattr(
        server,
        "_projects_api_request",
        _fake_projects_api(
            [{"project_id": "gamma", "prefix": "MNT", "alias_prefixes": ["ENC"]}]
        ),
    )

    with pytest.raises(ValueError) as exc_info:
        server._resolve_prefix("ZZZ")

    message = str(exc_info.value)
    assert message.startswith("Unknown project prefix 'ZZZ'. Known: ")
    assert "ENC" in message and "MNT" in message


@pytest.mark.parametrize(
    "row_order",
    ["alias_first", "mint_first"],
    ids=["alias-row-first", "mint-row-first"],
)
def test_mint_vs_alias_collision_resolves_to_mint_and_is_surfaced(monkeypatch, caplog, row_order):
    """(d) When a prefix is simultaneously one project's alias and another
    project's MINT prefix, MINT always wins -- regardless of API row order --
    and the collision is never silently resolved: it is logged and recorded
    in server._PREFIX_COLLISIONS."""
    alias_owner_row = {"project_id": "legacy-holder", "prefix": "OTH", "alias_prefixes": ["ENC"]}
    mint_owner_row = {"project_id": "gamma", "prefix": "ENC", "alias_prefixes": []}
    rows = (
        [alias_owner_row, mint_owner_row]
        if row_order == "alias_first"
        else [mint_owner_row, alias_owner_row]
    )
    monkeypatch.setattr(server, "_projects_api_request", _fake_projects_api(rows))

    with caplog.at_level(logging.WARNING, logger=server.logger.name):
        resolved = server._resolve_prefix("ENC")

    # MINT wins the resolution, deterministically, regardless of row order.
    assert resolved == "gamma"

    # The collision is surfaced, not silently resolved.
    assert "ENC" in server._PREFIX_COLLISIONS
    assert server._PREFIX_COLLISIONS["ENC"] == {
        "mint_project_id": "gamma",
        "alias_project_id": "legacy-holder",
    }
    assert any(
        "PREFIX-COLLISION" in rec.message and "ENC" in rec.message
        for rec in caplog.records
    )
