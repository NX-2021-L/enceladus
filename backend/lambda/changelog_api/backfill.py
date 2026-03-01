#!/usr/bin/env python3
"""backfill.py — One-time historical changelog backfill (ENC-FTR-033 Phase 8)

Reads workspace/backfill_manifest.json (produced by ENC-TSK-688 synthesis agent)
and writes deploy# records into the devops-deployment-manager DynamoDB table so the
changelog_api Lambda can serve historical data.

Usage:
    # Dry-run (default — shows what would be written, no DynamoDB writes):
    python3 backend/lambda/changelog_api/backfill.py

    # Dry-run from version.ts (no manifest needed):
    python3 backend/lambda/changelog_api/backfill.py --from-version-ts

    # Live write from manifest:
    python3 backend/lambda/changelog_api/backfill.py --write

    # Live write from version.ts (enceladus/pwa entries; no manifest needed):
    python3 backend/lambda/changelog_api/backfill.py --from-version-ts --write

    # Custom manifest or table:
    python3 backend/lambda/changelog_api/backfill.py \\
        --manifest path/to/backfill_manifest.json \\
        --table devops-deployment-manager \\
        --region us-west-2 \\
        --write

    # Write only a specific project:
    python3 backend/lambda/changelog_api/backfill.py --write --project enceladus

Requires:
    - AWS credentials with dynamodb:PutItem + dynamodb:GetItem on devops-deployment-manager
    - boto3 (pip install boto3)

Related: ENC-FTR-033, ENC-TSK-687, ENC-TSK-688, ENC-TSK-689
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def _find_workspace() -> Path:
    """Walk up from this script until we find a sibling 'workspace/' directory."""
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        ws = p / "workspace"
        if ws.is_dir():
            return ws
    return Path("workspace")  # fallback: CWD-relative

DEFAULT_MANIFEST = _find_workspace() / "backfill_manifest.json"
DEFAULT_TABLE = "devops-deployment-manager"
DEFAULT_REGION = "us-west-2"


# ---------------------------------------------------------------------------
# version.ts parser (--from-version-ts mode)
# ---------------------------------------------------------------------------

def _find_version_ts() -> Path:
    """Walk up from this script to find frontend/ui/src/lib/version.ts."""
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        candidate = p / "frontend" / "ui" / "src" / "lib" / "version.ts"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not find frontend/ui/src/lib/version.ts. "
        "Run from within the repo checkout or pass --manifest instead."
    )


def _extract_ts_objects(s: str) -> List[str]:
    """Extract top-level {...} blocks from a TypeScript array string."""
    objects: List[str] = []
    depth = 0
    start: Optional[int] = None
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(s[start : i + 1])
                start = None
    return objects


def _ts_str(obj: str, field: str) -> Optional[str]:
    """Extract a single-quoted string value for a TypeScript field."""
    m = re.search(rf"{re.escape(field)}:\s*'([^']*)'", obj)
    return m.group(1) if m else None


def _ts_str_array(obj: str, field: str) -> List[str]:
    """Extract a string array value for a TypeScript field (single-quoted strings)."""
    m = re.search(rf"{re.escape(field)}:\s*\[(.*?)\]", obj, re.DOTALL)
    if not m:
        return []
    return re.findall(r"'([^']*)'", m.group(1))


def _parse_version_ts(path: Path) -> List[Dict]:
    """Parse RELEASE_NOTES from version.ts and return manifest-shaped entries.

    Returns entries in newest-first order (matching the version.ts declaration order).
    Each entry has the same shape as a backfill_manifest.json entry so it can be
    passed directly to _entry_to_ddb_item().
    """
    content = path.read_text()

    # Locate the RELEASE_NOTES array using bracket-depth tracking so we don't
    # accidentally match an earlier '[' in the file (e.g. in import statements).
    marker = "export const RELEASE_NOTES"
    try:
        marker_idx = content.index(marker)
    except ValueError:
        raise ValueError(f"'export const RELEASE_NOTES' not found in {path}")

    # Search for '= [' to skip past the TypeScript type annotation 'ReleaseNote[]'
    # which also contains '[' and would cause bracket-depth tracking to terminate early.
    eq_bracket = re.search(r"=\s*\[", content[marker_idx:])
    if not eq_bracket:
        raise ValueError(f"Could not find '= [' assignment in RELEASE_NOTES declaration in {path}")
    open_bracket = marker_idx + eq_bracket.end() - 1  # position of the '[' character

    depth = 0
    close_bracket: Optional[int] = None
    for i in range(open_bracket, len(content)):
        if content[i] == "[":
            depth += 1
        elif content[i] == "]":
            depth -= 1
            if depth == 0:
                close_bracket = i
                break

    if close_bracket is None:
        raise ValueError(f"Unmatched '[' in RELEASE_NOTES array in {path}")

    array_body = content[open_bracket + 1 : close_bracket]

    type_map = {"major": "major", "minor": "minor", "patch": "patch"}

    entries: List[Dict] = []
    for obj_str in _extract_ts_objects(array_body):
        version = _ts_str(obj_str, "version")
        date = _ts_str(obj_str, "date")
        ts_type = _ts_str(obj_str, "type")
        summary = _ts_str(obj_str, "summary")
        changes = _ts_str_array(obj_str, "changes")

        if not version or not date:
            continue  # Skip malformed entries

        entries.append(
            {
                "project_id": "enceladus",
                "component": "pwa",
                "version": version,
                "previous_version": None,
                "change_type": type_map.get(ts_type or "", ts_type or "patch"),
                "deployed_at": f"{date}T12:00:00Z",
                "source": "static_version_ts",
                "confidence": "high",
                "summary": summary,
                "changes": changes if changes else None,
            }
        )

    return entries


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _get_ddb(region: str):
    return boto3.client("dynamodb", region_name=region)


def _to_ddb(value: Any) -> Dict:
    """Convert a Python value to DynamoDB AttributeValue."""
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, (int, float)):
        return {"N": str(value)}
    if isinstance(value, list):
        if not value:
            return {"L": []}
        return {"L": [_to_ddb(v) for v in value]}
    if isinstance(value, dict):
        return {"M": {k: _to_ddb(v) for k, v in value.items()}}
    return {"S": str(value)}


def _item_exists(ddb, table: str, project_id: str, record_id: str) -> bool:
    try:
        resp = ddb.get_item(
            TableName=table,
            Key={
                "project_id": {"S": project_id},
                "record_id": {"S": record_id},
            },
            ProjectionExpression="project_id",
        )
        return "Item" in resp
    except ClientError as e:
        print(f"  [WARN] get_item failed for {record_id}: {e}", file=sys.stderr)
        return False


def _put_item(ddb, table: str, item: Dict[str, Any]) -> bool:
    try:
        ddb.put_item(
            TableName=table,
            Item={k: _to_ddb(v) for k, v in item.items() if v is not None},
            ConditionExpression="attribute_not_exists(project_id)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False  # Already exists — skip silently (idempotent)
        raise


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

def _make_record_id(entry: Dict) -> str:
    """Build the SK (record_id) for a manifest entry."""
    spec_id = entry.get("spec_id")
    if spec_id:
        return f"deploy#{spec_id}"
    # Synthetic SK for version.ts-sourced entries (no spec_id)
    version = entry["version"].replace(".", "-")
    source = entry.get("source", "backfill")
    return f"deploy#{source}-v{version}"


def _entry_to_ddb_item(entry: Dict) -> Dict[str, Any]:
    """Convert a manifest entry to the DynamoDB item shape the Lambda expects."""
    record_id = _make_record_id(entry)
    item: Dict[str, Any] = {
        "project_id": entry["project_id"],
        "record_id": record_id,
        "version": entry.get("version"),
        "previous_version": entry.get("previous_version"),
        "change_type": entry.get("change_type"),
        "deployed_at": entry.get("deployed_at"),
        "source": entry.get("source", "backfill"),
        "confidence": entry.get("confidence", "high"),
        "backfill": True,
    }
    # Optional fields — only set if non-null/non-empty
    if entry.get("summary"):
        item["release_summary"] = entry["summary"]
    if entry.get("changes"):
        item["changes"] = entry["changes"]
    if entry.get("spec_id"):
        item["spec_id"] = entry["spec_id"]
    if entry.get("related_record_ids"):
        item["related_record_ids"] = entry["related_record_ids"]
    if entry.get("component") and entry["component"] != "unknown":
        item["component"] = entry["component"]
    return item


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="ENC-FTR-033 historical changelog backfill")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                        help=f"Path to backfill_manifest.json (default: {DEFAULT_MANIFEST})")
    parser.add_argument("--from-version-ts", action="store_true",
                        help=(
                            "Parse entries directly from frontend/ui/src/lib/version.ts "
                            "(enceladus/pwa project only; no manifest file needed)"
                        ))
    parser.add_argument("--table", default=DEFAULT_TABLE,
                        help=f"DynamoDB table name (default: {DEFAULT_TABLE})")
    parser.add_argument("--region", default=DEFAULT_REGION,
                        help=f"AWS region (default: {DEFAULT_REGION})")
    parser.add_argument("--project", default=None,
                        help="Only write entries for this project_id (default: all)")
    parser.add_argument("--write", action="store_true",
                        help="Actually write to DynamoDB (default: dry-run)")
    args = parser.parse_args()

    # ---------------------------------------------------------------------------
    # Load entries from the chosen source
    # ---------------------------------------------------------------------------

    source_label: str

    if args.from_version_ts:
        try:
            version_ts_path = _find_version_ts()
            entries = _parse_version_ts(version_ts_path)
            source_label = str(version_ts_path)
        except Exception as e:
            print(f"[ERROR] --from-version-ts: {e}", file=sys.stderr)
            return 1
    else:
        manifest_path = Path(args.manifest)
        if not manifest_path.exists():
            print(f"[ERROR] Manifest not found: {manifest_path}", file=sys.stderr)
            print(
                "  Options:\n"
                "    --from-version-ts   Parse enceladus/pwa entries directly from the repo\n"
                "    --manifest <path>   Point at an existing backfill_manifest.json\n"
                "  Or run the Phase 8 synthesis agent first to generate the manifest.",
                file=sys.stderr,
            )
            return 1
        with open(manifest_path) as f:
            manifest = json.load(f)
        entries = manifest.get("entries", [])
        source_label = str(manifest_path)

    if args.project:
        entries = [e for e in entries if e.get("project_id") == args.project]

    mode = "LIVE WRITE" if args.write else "DRY RUN"
    print(f"\n{'='*60}")
    print(f"  ENC-FTR-033 Changelog Backfill — {mode}")
    print(f"{'='*60}")
    print(f"  Source   : {source_label}")
    print(f"  Table    : {args.table} ({args.region})")
    print(f"  Entries  : {len(entries)}")
    if args.project:
        print(f"  Filter   : project_id = {args.project!r}")
    print()

    if not args.write:
        print("  [DRY RUN] Pass --write to execute. Showing first 5 records:\n")

    ddb = _get_ddb(args.region) if args.write else None

    written = skipped = errors = 0

    for i, entry in enumerate(entries):
        item = _entry_to_ddb_item(entry)
        record_id = item["record_id"]
        project_id = item["project_id"]
        label = f"[{i+1:3d}/{len(entries)}] {project_id}/{record_id}"

        if not args.write:
            if i < 5:
                print(f"  {label}")
                print(f"           version={item.get('version')}  change_type={item.get('change_type')}  deployed_at={item.get('deployed_at')}")
            elif i == 5:
                print(f"  ... ({len(entries) - 5} more entries not shown)")
            continue

        # Check existence first to give informative skip messages
        if _item_exists(ddb, args.table, project_id, record_id):
            print(f"  SKIP  {label}  (already exists)")
            skipped += 1
            continue

        try:
            ok = _put_item(ddb, args.table, item)
            if ok:
                print(f"  WRITE {label}  v{item.get('version')} [{item.get('change_type')}]")
                written += 1
            else:
                print(f"  SKIP  {label}  (race condition — already exists)")
                skipped += 1
        except Exception as e:
            print(f"  ERROR {label}: {e}", file=sys.stderr)
            errors += 1

        # Polite pacing — avoid DynamoDB throttling
        time.sleep(0.05)

    print()
    if args.write:
        print(f"{'='*60}")
        print(f"  Written : {written}")
        print(f"  Skipped : {skipped}  (already existed)")
        print(f"  Errors  : {errors}")
        print(f"{'='*60}\n")
        if errors:
            print("[WARN] Some writes failed. Re-run to retry — the script is idempotent.")
            return 1
        print("[SUCCESS] Backfill complete.")
    else:
        print(f"{'='*60}")
        print(f"  Would write: {len(entries)} entries (skipping existence checks in dry-run)")
        print(f"  Re-run with --write to execute.")
        print(f"{'='*60}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
