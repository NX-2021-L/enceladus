#!/usr/bin/env python3
"""DVP-TSK-861: generate policy_table.json from the MCP caps.json.

One row per caps.json action (kit shape: action -> {dry_run, execute}).
io-dev-admin holds execute for every action; reads are also dry_run-able.
The escalation decide path is NOT an MCP action: it keeps its three server
gates (interactive-human ID token, decider allowlist, checkout lock) and this
table never grants or widens it.

    python3 backend/lambda/auth_refresh/gen_policy_table.py [caps.json]
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_CAPS = HERE.parents[2] / "tools" / "enceladus-mcp-server" / "parity" / "caps.json"
EXECUTE_GROUP = "io-dev-admin"


def build(caps: dict) -> dict:
    actions = {}
    for a in caps["actions"]:
        read_only = bool((a.get("annotations") or {}).get("readOnlyHint"))
        row = {"dry_run": [EXECUTE_GROUP], "execute": [EXECUTE_GROUP],
               "visibilityWhenDenied": "hide" if read_only else "disable"}
        actions[a["name"]] = row
    return {"version": "2026.10.1", "defaults": {"mode": {"agent": "dry_run", "human": "dry_run"}},
            "actions": actions}


if __name__ == "__main__":
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CAPS
    table = build(json.loads(src.read_text(encoding="utf-8")))
    (HERE / "policy_table.json").write_text(json.dumps(table, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(table['actions'])} actions")
