#!/usr/bin/env python3
"""Stdlib-only loader/CLI for envs/architecture.yaml (ENC-TSK-Q19 FR-1 / DOC-5368FE6515ED).

envs/architecture.yaml is the ONE canonical architecture declaration for every
Enceladus deploy plane. This loader is deliberately NOT a general YAML parser --
it accepts exactly the restricted, flow-style subset the file's own header
commits to (one `<plane>: {arch: ..., runtime: ..., runner: ...}` line per
plane under `planes:`, one `<env>: <plane>` line per mapping under
`env_plane:`) and fails loudly (ArchDeclarationError) on anything else,
including a well-formed YAML document that doesn't match this exact shape.

That restriction is intentional: this module has no PyYAML dependency so
plain bash (.github/workflows/_deploy.yml's `grep`-based `_parse` fallback)
and this CLI can both read the file without provisioning a package, and
bash's ability to do that depends on the file never growing beyond what a
simple regex can parse.

CLI:
    python3 tools/arch_declaration.py --env v3-prod --field arch
    python3 tools/arch_declaration.py --plane prod --field runtime
    python3 tools/arch_declaration.py --plane gamma --field runner
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[1]
DECLARATION_PATH = REPO_ROOT / "envs" / "architecture.yaml"

FIELDS = ("arch", "runtime", "runner")

# `  prod: {arch: arm64, runtime: python3.12, runner: ubuntu-24.04-arm}`
_PLANE_LINE_RE = re.compile(
    r"^  (?P<plane>[\w-]+):\s*\{\s*"
    r"arch:\s*(?P<arch>[\w.]+)\s*,\s*"
    r"runtime:\s*(?P<runtime>[\w.]+)\s*,\s*"
    r"runner:\s*(?P<runner>[\w.-]+)\s*\}\s*$"
)
# `  v3-prod: prod`
_ENV_LINE_RE = re.compile(r"^  (?P<env>[\w.-]+):\s*(?P<plane>[\w-]+)\s*$")


class ArchDeclarationError(RuntimeError):
    """Raised when envs/architecture.yaml doesn't match the FR-1 schema."""


@dataclass
class ArchDeclaration:
    schema_version: int
    planes: Dict[str, Dict[str, str]]
    env_plane: Dict[str, str]

    def plane_for_env(self, env: str) -> str:
        try:
            return self.env_plane[env]
        except KeyError:
            raise ArchDeclarationError(
                f"envs/architecture.yaml has no env_plane entry for {env!r}"
            ) from None

    def field_for_plane(self, plane: str, field_name: str) -> str:
        if plane not in self.planes:
            raise ArchDeclarationError(
                f"envs/architecture.yaml has no planes entry for {plane!r}"
            )
        if field_name not in FIELDS:
            raise ArchDeclarationError(
                f"unknown field {field_name!r}, expected one of {FIELDS}"
            )
        return self.planes[plane][field_name]

    def field_for_env(self, env: str, field_name: str) -> str:
        return self.field_for_plane(self.plane_for_env(env), field_name)


def load_declaration(path: Path = DECLARATION_PATH) -> ArchDeclaration:
    """Parse envs/architecture.yaml. Raises ArchDeclarationError on anything
    that isn't exactly the FR-1 schema -- this must fail loudly, never
    silently drop a plane or env mapping."""
    if not path.is_file():
        raise ArchDeclarationError(f"architecture declaration not found: {path}")

    schema_version = None
    planes: Dict[str, Dict[str, str]] = {}
    env_plane: Dict[str, str] = {}
    section = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if line.startswith("schema_version:"):
            value = line.split(":", 1)[1].strip()
            try:
                schema_version = int(value)
            except ValueError:
                raise ArchDeclarationError(
                    f"schema_version must be an integer, got {value!r}"
                )
            section = None
            continue

        if line == "planes:":
            section = "planes"
            continue

        if line == "env_plane:":
            section = "env_plane"
            continue

        if line.startswith("  "):
            if section == "planes":
                m = _PLANE_LINE_RE.match(line)
                if not m:
                    raise ArchDeclarationError(f"unparseable planes line: {line!r}")
                planes[m.group("plane")] = {
                    "arch": m.group("arch"),
                    "runtime": m.group("runtime"),
                    "runner": m.group("runner"),
                }
            elif section == "env_plane":
                m = _ENV_LINE_RE.match(line)
                if not m:
                    raise ArchDeclarationError(f"unparseable env_plane line: {line!r}")
                env_plane[m.group("env")] = m.group("plane")
            else:
                raise ArchDeclarationError(
                    f"indented line outside a known section (planes:/env_plane:): {line!r}"
                )
            continue

        # Unindented, non-empty, non-comment line that isn't a recognized
        # section header or the schema_version line.
        raise ArchDeclarationError(f"unexpected top-level line: {line!r}")

    if schema_version != 1:
        raise ArchDeclarationError(
            f"unsupported schema_version: {schema_version!r} (expected 1)"
        )
    if not planes:
        raise ArchDeclarationError("no planes declared under planes:")
    if not env_plane:
        raise ArchDeclarationError("no env_plane mappings declared under env_plane:")

    for env, plane in env_plane.items():
        if plane not in planes:
            raise ArchDeclarationError(
                f"env_plane[{env!r}] references undeclared plane {plane!r}"
            )
    for plane, fields_dict in planes.items():
        missing = [f for f in FIELDS if f not in fields_dict]
        if missing:
            raise ArchDeclarationError(f"plane {plane!r} missing fields: {missing}")

    return ArchDeclaration(schema_version=schema_version, planes=planes, env_plane=env_plane)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--env", help="Env name (e.g. v3-prod), resolved via env_plane.")
    target.add_argument("--plane", help="Plane name (e.g. prod), read directly.")
    parser.add_argument("--field", required=True, choices=FIELDS)
    args = parser.parse_args(argv)

    try:
        decl = load_declaration()
        if args.env:
            value = decl.field_for_env(args.env, args.field)
        else:
            value = decl.field_for_plane(args.plane, args.field)
    except ArchDeclarationError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
