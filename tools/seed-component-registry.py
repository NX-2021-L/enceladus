#!/usr/bin/env python3
"""
ENC-FTR-041: Seed the component registry with known Enceladus components.

Usage:
    python3 tools/seed-component-registry.py [--dry-run] [--base-url URL] [--api-key KEY]

Environment variables (can be set instead of flags):
    ENCELADUS_COORDINATION_INTERNAL_API_KEY  — internal API key
    COORDINATION_API_BASE                    — base URL (default: https://jreese.net/api/v1/coordination)

The script is idempotent: it creates components with PUT semantics (409 on duplicate is
treated as success if the existing record has the same transition_type, otherwise a
warning is emitted and the record is skipped without overwriting).

Components seeded:
    comp-checkout-service      enceladus  lambda      github_pr_deploy
    comp-coordination-api      enceladus  lambda      github_pr_deploy
    comp-tracker-mutation      enceladus  lambda      github_pr_deploy
    comp-enceladus-mcp-server  enceladus  library     github_pr_deploy
    comp-enceladus-pwa         enceladus  frontend    web_deploy
    comp-harrisonfamily-site   harrisonfamily frontend web_deploy
    comp-cloudformation-data   enceladus  infrastructure no_code
    comp-cloudformation-app    enceladus  infrastructure no_code
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

KNOWN_COMPONENTS = [
    {
        "component_id": "comp-checkout-service",
        "component_name": "Checkout Service Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "description": "Enceladus checkout service Lambda — sole authorized caller for task status transitions and worklog appends.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
    {
        "component_id": "comp-coordination-api",
        "component_name": "Coordination API Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "description": "Enceladus coordination API Lambda — coordination mode, governance routes, projects, documents, components.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
    {
        "component_id": "comp-tracker-mutation",
        "component_name": "Tracker Mutation Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "description": "Enceladus tracker mutation Lambda — handles all tracker record writes (create, set, log, etc.).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
    {
        "component_id": "comp-enceladus-mcp-server",
        "component_name": "MCP Server (server.py)",
        "project_id": "enceladus",
        "category": "library",
        "transition_type": "github_pr_deploy",
        "description": "Enceladus MCP server (tools/enceladus-mcp-server/server.py) — exposed to Claude agents via MCP protocol.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
    {
        "component_id": "comp-enceladus-pwa",
        "component_name": "Enceladus PWA (jreese.net)",
        "project_id": "enceladus",
        "category": "frontend",
        "transition_type": "web_deploy",
        "description": "Enceladus Progressive Web App — React UI deployed to jreese.net via CloudFront/S3.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
    {
        "component_id": "comp-harrisonfamily-site",
        "component_name": "Harrison Family Site",
        "project_id": "harrisonfamily",
        "category": "frontend",
        "transition_type": "web_deploy",
        "description": "Harrison Family static site — Eleventy + 11ty deployed to CloudFront/S3.",
        "github_repo": "me-jreese/harrisonfamily",
        "status": "active",
    },
    {
        "component_id": "comp-cloudformation-data",
        "component_name": "CloudFormation Data Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "no_code",
        "description": "Enceladus data CloudFormation stack (01-data.yaml) — DynamoDB tables, S3 buckets, etc. Updated by product lead via elevated IAM role.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
    {
        "component_id": "comp-cloudformation-app",
        "component_name": "CloudFormation App Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "no_code",
        "description": "Enceladus compute/app CloudFormation stack (02-compute.yaml) — Lambda functions, API Gateway, EventBridge rules, etc. Updated by product lead via elevated IAM role.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
    },
]


def _api_request(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    payload: dict | None = None,
) -> tuple[int, dict]:
    url = f"{base_url.rstrip('/')}{path}"
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        try:
            err_body = json.loads(body_bytes)
        except Exception:
            err_body = {"raw": body_bytes.decode(errors="replace")}
        return exc.code, err_body


def seed(base_url: str, api_key: str, dry_run: bool) -> None:
    ok_count = 0
    skip_count = 0
    err_count = 0

    for comp in KNOWN_COMPONENTS:
        cid = comp["component_id"]
        print(f"\n[{cid}] ({comp['transition_type']})", end="")

        if dry_run:
            print(" — DRY RUN, skipping")
            continue

        # Check if already exists
        status, existing = _api_request(base_url, api_key, "GET", f"/components/{cid}")
        if status == 200:
            existing_type = existing.get("component", {}).get("transition_type", "")
            if existing_type == comp["transition_type"]:
                print(f" — already exists with same transition_type ({existing_type}), skipping")
                skip_count += 1
                continue
            else:
                print(
                    f" — already exists with DIFFERENT transition_type "
                    f"({existing_type} vs {comp['transition_type']}), SKIPPING to avoid overwrite"
                )
                skip_count += 1
                continue

        # Create the component
        status, result = _api_request(base_url, api_key, "POST", "/components", comp)
        if status == 201:
            print(f" — CREATED ✓")
            ok_count += 1
        elif status == 409:
            print(f" — 409 Conflict (already exists), skipping")
            skip_count += 1
        else:
            print(f" — ERROR {status}: {result.get('error', result)}")
            err_count += 1

    print(f"\n\n=== Seed complete ===")
    print(f"Created:  {ok_count}")
    print(f"Skipped:  {skip_count}")
    print(f"Errors:   {err_count}")
    if err_count:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Enceladus component registry (ENC-FTR-041)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done without making API calls")
    parser.add_argument("--base-url", default=None, help="Coordination API base URL")
    parser.add_argument("--api-key", default=None, help="Internal API key")
    args = parser.parse_args()

    base_url = (
        args.base_url
        or os.environ.get("COORDINATION_API_BASE", "")
        or "https://jreese.net/api/v1/coordination"
    )
    api_key = (
        args.api_key
        or os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "")
        or os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    )

    if not api_key and not args.dry_run:
        print("ERROR: --api-key or ENCELADUS_COORDINATION_INTERNAL_API_KEY env var is required", file=sys.stderr)
        sys.exit(1)

    print(f"Base URL: {base_url}")
    print(f"Dry run:  {args.dry_run}")
    print(f"Components to seed: {len(KNOWN_COMPONENTS)}")

    seed(base_url, api_key, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
