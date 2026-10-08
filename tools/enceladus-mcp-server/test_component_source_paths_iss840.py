"""ENC-ISS-840: location-hint component resolution tolerates list-shaped source_paths."""

import importlib.util
import pathlib
import sys

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_iss840", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)

COMPONENTS = [
    {"component_id": "comp-elr", "component_name": "elr local runner", "category": "tooling",
     "source_paths": {"primary": "tools/elr/elr_compact_context.py", "directory": "tools/elr",
                      "domains": {"elr": {}}}},
    {"component_id": "comp-rhythm-cycle", "component_name": "rhythm cycle", "category": "lambda",
     "source_paths": ["backend/lambda/rhythm/sense.py", "backend/lambda/rhythm/decide.py"]},
    {"component_id": "comp-list-domains", "component_name": "list domains", "category": "x",
     "source_paths": {"primary": "a/b.py", "domains": ["alpha", "beta"]}},
]


def test_normalizer_shapes():
    assert server._component_source_paths(COMPONENTS[1])["primary"] == "backend/lambda/rhythm/sense.py"
    assert server._component_source_paths(COMPONENTS[2])["domains"] == {"alpha": {}, "beta": {}}
    assert server._component_source_paths({"source_paths": None}) == {}


def test_location_hint_resolution_with_list_source_paths():
    out = server._resolve_location_hint_to_components(
        "tools/elr/elr_compact_context.py; backend/lambda/rhythm/sense.py", COMPONENTS)
    ids = [e["component_id"] for e in out]
    assert "comp-elr" in ids
    assert all(isinstance(e.get("domains", []), list) for e in out)
