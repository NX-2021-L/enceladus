#!/usr/bin/env python3
"""Emit caps.json (parity contract schema 1.0.0) for the Enceladus MCP surface.

DVP-TSK-843.  The inventory is generated from the live action registry
(``mcp_server.actions.build_action_registries``) and the raw Tool schemas in
server.py through ``mcp_server.catalog.build_action_catalog`` -- the same code path
that answers ``search(action="actions.schemas")`` -- so the file can never describe
an action the server does not expose, or omit one it does.

Usage (from the repository root):
  python3 tools/enceladus-mcp-server/parity/emit_caps.py            # rewrite parity/caps.json
  python3 tools/enceladus-mcp-server/parity/emit_caps.py --check    # CI: fail if the snapshot is stale
  python3 tools/enceladus-mcp-server/parity/emit_caps.py --flags none --out /tmp/caps-noflags.json

``--flags all`` (default) is the all-flags-on registry the parity spec counts against;
``--flags none`` registers only what is on with every optional feature flag off
(escalations are default-on and stay).  The committed snapshot is always ``all``.

Needs the packages server.py needs (mcp, jsonschema) and the shared layer on the path,
which this script adds itself (backend/lambda/shared_layer/python).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PARITY_DIR = Path(__file__).resolve().parent
SERVER_DIR = PARITY_DIR.parent
REPO_ROOT = SERVER_DIR.parent.parent
SCHEMA_PATH = PARITY_DIR / "schema" / "caps.schema.json"
SNAPSHOT_PATH = PARITY_DIR / "caps.json"
SURFACE = "enceladus"
SCHEMA_VERSION = "1.0.0"


def _bootstrap_paths() -> None:
    for path in (str(SERVER_DIR), str(REPO_ROOT / "backend" / "lambda" / "shared_layer" / "python")):
        if path not in sys.path:
            sys.path.insert(0, path)


def load_server():
    """Import server.py hermetically (no route probe, no network at import time)."""
    _bootstrap_paths()
    os.environ.setdefault("ENCELADUS_COMPACT_CONTEXT_ROUTE", "off")
    spec = importlib.util.spec_from_file_location("enceladus_server_caps_emit", SERVER_DIR / "server.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_actions(flags_mode: str = "all", server=None) -> List[Dict[str, Any]]:
    server = server or load_server()
    from mcp_server.actions import ActionFeatureFlags, build_action_registries
    from mcp_server.catalog import build_action_catalog

    if flags_mode == "all":
        flags = ActionFeatureFlags(True, True, True, True, True)
    elif flags_mode == "none":
        flags = ActionFeatureFlags(False, True, False, False, False)
    else:
        raise ValueError(f"unknown --flags value {flags_mode!r}")
    search, coordination, execute = build_action_registries(flags)
    actions = build_action_catalog(search, coordination, execute, server._tool_input_schemas())
    return sorted(actions, key=lambda item: item["name"])


def build_caps(flags_mode: str = "all", server=None, generated_at: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "surface": SURFACE,
        "generatedAt": generated_at
        or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actions": build_actions(flags_mode, server),
    }


def validate_caps(caps: Dict[str, Any]) -> None:
    """Raise jsonschema.ValidationError when ``caps`` violates the bundled schema."""
    import jsonschema

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(caps), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise jsonschema.ValidationError(f"{where}: {first.message} ({len(errors)} error(s))")


def _without_timestamp(caps: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in caps.items() if key != "generatedAt"}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=SNAPSHOT_PATH, help="output path (default: parity/caps.json)")
    parser.add_argument("--flags", choices=("all", "none"), default="all")
    parser.add_argument("--check", action="store_true", help="compare against the committed snapshot; do not write")
    args = parser.parse_args(argv)

    caps = build_caps(args.flags)
    validate_caps(caps)

    if args.check:
        committed = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        validate_caps(committed)
        if _without_timestamp(committed) != _without_timestamp(caps):
            old = {a["name"]: a for a in committed["actions"]}
            new = {a["name"]: a for a in caps["actions"]}
            print("CAPS-STALE tools/enceladus-mcp-server/parity/caps.json differs from the live registry", file=sys.stderr)
            for name in sorted(set(old) - set(new)):
                print(f"  removed: {name}", file=sys.stderr)
            for name in sorted(set(new) - set(old)):
                print(f"  added: {name}", file=sys.stderr)
            for name in sorted(set(old) & set(new)):
                if old[name] != new[name]:
                    print(f"  changed: {name}", file=sys.stderr)
            print("Regenerate with: python3 tools/enceladus-mcp-server/parity/emit_caps.py", file=sys.stderr)
            return 1
        print(f"caps.json is current: {len(caps['actions'])} actions (schema {SCHEMA_VERSION})")
        return 0

    args.out.write_text(json.dumps(caps, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(caps['actions'])} actions, schema {SCHEMA_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
