#!/usr/bin/env python3
"""
ENC-FTR-041 / ENC-FTR-042: Seed the component registry for all managed projects.

Usage:
    python3 tools/seed-component-registry.py [--dry-run] [--base-url URL] [--api-key KEY]
        [--assistant-key KEY] [--direct-apigw-base URL]

Environment variables (can be set instead of flags):
    ENCELADUS_COORDINATION_INTERNAL_API_KEY  — internal API key
    COORDINATION_API_BASE                    — base URL (default: https://jreese.net/api/v1/coordination)
    CHECKOUT_ASSISTANT_KEY                   — checkout-service-assistant key (allows setting
                                               non-default transition_type at create time)
    COORDINATION_DIRECT_APIGW_BASE           — direct APIGW URL used for assistant-key calls
                                               (bypasses CloudFront header stripping);
                                               default: https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/coordination

Auth note for non-default transition_type:
    Creating a component with a non-default transition_type (anything other than
    "github_pr_deploy") requires either Cognito auth (PWA session) or the checkout-service-
    assistant key (--assistant-key / CHECKOUT_ASSISTANT_KEY). If neither is provided, the
    script creates the component with the default "github_pr_deploy" type and emits a warning
    that a manual PATCH via the PWA is needed to set the correct type.

    The assistant-key PATCH must be sent to the direct APIGW URL (not CloudFront) because
    CloudFront strips custom headers before reaching the Lambda backend.

The script is idempotent: it GETs each component first. If the existing record has the same
transition_type as the seed entry it is skipped. If the type differs, a warning is emitted
and the record is left unchanged.

ENC-TSK-F50 / ENC-ISS-270 update (2026-04-19): every entry below now also carries a
``required_transition_type`` field, matched to the governance-intent decisions in
DOC-240A67973B13 (AC-1 review). ``required_transition_type`` is the field that
checkout_service reads for strictness enforcement post-F50 — ``transition_type`` is
retained for back-compat documentation. For all current components in this manifest
the two fields carry the same value, but that equivalence is a deliberate governance
output, not a blind copy. The coordination API create handler rejects any POST missing
``required_transition_type`` with HTTP 400 (F50/AC-6 strict mode).

Components seeded:
    Enceladus project (ENC-FTR-041):
        comp-checkout-service      enceladus  lambda          github_pr_deploy
        comp-coordination-api      enceladus  lambda          github_pr_deploy
        comp-tracker-mutation      enceladus  lambda          github_pr_deploy
        comp-enceladus-mcp-server  enceladus  library         github_pr_deploy
        comp-enceladus-pwa         enceladus  frontend        web_deploy          (needs assistant-key)
        comp-cloudformation-data   enceladus  infrastructure  no_code             (needs assistant-key)
        comp-cloudformation-app    enceladus  infrastructure  no_code             (needs assistant-key)

    Harrisonfamily project:
        comp-harrisonfamily-site   harrisonfamily  frontend  web_deploy           (needs assistant-key)

    MOD project (vagamod.io):
        comp-mod-web               mod  frontend        github_pr_deploy
        comp-mod-api               mod  lambda          github_pr_deploy
        comp-mod-infra             mod  infrastructure  github_pr_deploy
        comp-mod-keycloak          mod  external        no_code                  (needs assistant-key)

    DevOps project (ENC-FTR-042):
        comp-devops-governance     devops  workflow  no_code                     (needs assistant-key)

    jreesewebops project (ENC-FTR-042):
        comp-jwo-web-infra         jreesewebops  infrastructure  no_code         (needs assistant-key)

    jreeseGPT project (ENC-FTR-042):
        comp-jgp-platform          jreeseGPT  external  no_code                  (needs assistant-key)

    jobapps project (ENC-FTR-042):
        comp-jap-jds-platform      jobapps  external  no_code                    (needs assistant-key)

    intelligent-scraper-generator project (ENC-FTR-042):
        comp-isg-toolkit           intelligent-scraper-generator  library  no_code  (needs assistant-key)

    property160c1 project (ENC-FTR-042):
        comp-prp-planning          property160c1  workflow  no_code              (needs assistant-key)

    agentharmony project (ENC-FTR-042):
        comp-agh-governance        agentharmony  workflow  no_code               (needs assistant-key)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

KNOWN_COMPONENTS = [
    # ── Enceladus ────────────────────────────────────────────────────────────
    {
        "component_id": "comp-checkout-service",
        "component_name": "Checkout Service Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "Enceladus checkout service Lambda — sole authorized caller for task status transitions and worklog appends.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "backend/lambda/checkout_service/lambda_function.py",
            "directory": "backend/lambda/checkout_service/",
            "workflow": ".github/workflows/lambda-checkout-service-deploy.yml",
            "related": ["backend/lambda/shared_layer/"],
            "architecture_sections": ["4.17"],
        },
    },
    {
        "component_id": "comp-coordination-api",
        "component_name": "Coordination API Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "Enceladus coordination API Lambda — coordination mode, governance routes, projects, documents, components.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "backend/lambda/coordination_api/lambda_function.py",
            "directory": "backend/lambda/coordination_api/",
            "workflow": ".github/workflows/api-mcp-backend-deploy.yml",
            "deploy_script": "backend/lambda/coordination_api/deploy.sh",
            "related": [
                "backend/lambda/coordination_api/governance_data_dictionary.json",
                "backend/lambda/coordination_api/config.py",
            ],
            "architecture_sections": ["4.2", "5.1"],
        },
    },
    {
        "component_id": "comp-tracker-mutation",
        "component_name": "Tracker Mutation Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "Enceladus tracker mutation Lambda — handles all tracker record writes (create, set, log, etc.).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "backend/lambda/tracker_mutation/lambda_function.py",
            "directory": "backend/lambda/tracker_mutation/",
            "workflow": ".github/workflows/lambda-tracker-mutation-api-deploy.yml",
            "deploy_script": "backend/lambda/tracker_mutation/deploy.sh",
            "related": ["backend/lambda/shared_layer/"],
            "architecture_sections": ["4.1", "5.1"],
        },
    },
    {
        "component_id": "comp-enceladus-mcp-server",
        "component_name": "MCP Server (server.py)",
        "project_id": "enceladus",
        "category": "library",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "Enceladus MCP server (tools/enceladus-mcp-server/server.py) — exposed to Claude agents via MCP protocol.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "tools/enceladus-mcp-server/server.py",
            "directory": "tools/enceladus-mcp-server/",
            "related": ["tools/enceladus-mcp-server/install_profile.sh"],
            "architecture_sections": ["8.1"],
        },
    },
    {
        "component_id": "comp-enceladus-pwa",
        "component_name": "Enceladus PWA (jreese.net)",
        "project_id": "enceladus",
        "category": "frontend",
        "transition_type": "web_deploy",
        "required_transition_type": "web_deploy",
        "description": "Enceladus Progressive Web App — React UI deployed to jreese.net via CloudFront/S3.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "frontend/ui/src/App.tsx",
            "directory": "frontend/ui/src/",
            "domains": {
                "auth": [
                    "frontend/ui/src/lib/authState.tsx",
                    "frontend/ui/src/lib/authSession.ts",
                    "frontend/ui/src/lib/logout.ts",
                    "frontend/ui/src/api/auth.ts",
                    "frontend/ui/src/api/authTokens.ts",
                    "frontend/ui/src/hooks/useSessionLifecycle.ts",
                    "frontend/ui/src/hooks/useSessionTimer.ts",
                    "frontend/ui/src/pages/AuthTokensPage.tsx",
                ],
                "routing": [
                    "frontend/ui/src/lib/routes.tsx",
                    "frontend/ui/src/components/layout/AppShell.tsx",
                    "frontend/ui/src/components/layout/Header.tsx",
                    "frontend/ui/src/components/layout/BottomNav.tsx",
                ],
                "tracker": [
                    "frontend/ui/src/api/mutations.ts",
                    "frontend/ui/src/api/client.ts",
                    "frontend/ui/src/hooks/useTasks.ts",
                    "frontend/ui/src/hooks/useIssues.ts",
                    "frontend/ui/src/hooks/useFeatures.ts",
                    "frontend/ui/src/hooks/useRecordMutation.ts",
                    "frontend/ui/src/pages/TaskDetailPage.tsx",
                    "frontend/ui/src/pages/IssueDetailPage.tsx",
                    "frontend/ui/src/pages/FeatureDetailPage.tsx",
                    "frontend/ui/src/pages/ProjectDetailPage.tsx",
                ],
                "feeds": [
                    "frontend/ui/src/api/feeds.ts",
                    "frontend/ui/src/contexts/LiveFeedContext.tsx",
                    "frontend/ui/src/hooks/useFeed.ts",
                    "frontend/ui/src/hooks/useFilterState.ts",
                    "frontend/ui/src/hooks/useInfiniteList.ts",
                    "frontend/ui/src/pages/FeedPage.tsx",
                    "frontend/ui/src/pages/DashboardPage.tsx",
                ],
                "deploy": [
                    "frontend/ui/src/api/changelog.ts",
                    "frontend/ui/src/hooks/useChangelog.ts",
                    "frontend/ui/src/pages/ChangelogListPage.tsx",
                    "frontend/ui/src/pages/ProjectChangelogPage.tsx",
                ],
                "coordination": [
                    "frontend/ui/src/api/coordination.ts",
                    "frontend/ui/src/hooks/useCoordination.ts",
                    "frontend/ui/src/pages/CoordinationPage.tsx",
                    "frontend/ui/src/pages/CoordinationDetailPage.tsx",
                ],
                "documents": [
                    "frontend/ui/src/api/documents.ts",
                    "frontend/ui/src/api/documents2.ts",
                    "frontend/ui/src/hooks/useDocuments.ts",
                    "frontend/ui/src/pages/DocumentsListPage.tsx",
                    "frontend/ui/src/pages/DocumentDetailPage.tsx",
                ],
            },
            "architecture_sections": ["7.1", "7.2", "7.3", "7.4"],
        },
    },
    {
        "component_id": "comp-cloudformation-data",
        "component_name": "CloudFormation Data Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "Enceladus data CloudFormation stack (01-data.yaml) — DynamoDB tables, S3 buckets, etc. Updated by product lead via elevated IAM role.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "infrastructure/cloudformation/01-data.yaml",
            "directory": "infrastructure/cloudformation/",
            "architecture_sections": ["3.1", "3.2", "3.3"],
        },
    },
    {
        "component_id": "comp-cloudformation-app",
        "component_name": "CloudFormation App Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "Enceladus compute/app CloudFormation stack (02-compute.yaml) — Lambda functions, API Gateway, EventBridge rules, etc. Updated by product lead via elevated IAM role.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "source_paths": {
            "primary": "infrastructure/cloudformation/02-compute.yaml",
            "directory": "infrastructure/cloudformation/",
            "related": ["infrastructure/lambda_workflow_manifest.json"],
            "architecture_sections": ["2.1", "4.0"],
        },
    },
    # ── Harrisonfamily ───────────────────────────────────────────────────────
    {
        "component_id": "comp-harrisonfamily-site",
        "component_name": "Harrison Family Site",
        "project_id": "harrisonfamily",
        "category": "frontend",
        "transition_type": "web_deploy",
        "required_transition_type": "web_deploy",
        "description": "Harrison Family static site — Eleventy + 11ty deployed to CloudFront/S3.",
        "github_repo": "me-jreese/harrisonfamily",
        "status": "active",
        "source_paths": {
            "primary": "repo/11ty/.eleventy.js",
            "directory": "repo/11ty/",
            "related": ["workspace/11ty-dev/", "repo/11ty/js/", "repo/11ty/_data/"],
        },
    },
    # ── MOD (vagamod.io) ─────────────────────────────────────────────────────
    {
        "component_id": "comp-mod-web",
        "component_name": "MOD Next.js Frontend (vagamod.io)",
        "project_id": "mod",
        "category": "frontend",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "MOD Next.js/SST frontend app — deployed via GitHub Actions sst deploy to CloudFront/Lambda@Edge.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    {
        "component_id": "comp-mod-api",
        "component_name": "MOD Lambda API Handlers",
        "project_id": "mod",
        "category": "lambda",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "MOD Lambda API handlers (objects, custody, users, comments, search, QR) — deployed via GitHub Actions sst deploy.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    {
        "component_id": "comp-mod-infra",
        "component_name": "MOD SST Infrastructure (DynamoDB + CloudFormation)",
        "project_id": "mod",
        "category": "infrastructure",
        "transition_type": "github_pr_deploy",
        "required_transition_type": "github_pr_deploy",
        "description": "MOD SST v3 infrastructure stack — DynamoDB tables, IAM roles, CloudFront, API Gateway; deployed via GitHub Actions sst deploy.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    {
        "component_id": "comp-mod-keycloak",
        "component_name": "MOD Keycloak Auth (Lightsail)",
        "project_id": "mod",
        "category": "external",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "MOD Keycloak identity provider on AWS Lightsail (auth.vagamod.io) — admin-managed via Lightsail console and SSH. No GitHub Actions pipeline.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    # ── DevOps (ENC-FTR-042) ─────────────────────────────────────────────────
    {
        "component_id": "comp-devops-governance",
        "component_name": "DevOps Governance & Deployment Config",
        "project_id": "devops",
        "category": "workflow",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "DevOps governance policies (agents.md, data dictionary), deployment configs, and agent SOPs in S3. Updated via MCP governance_update.",
        "status": "active",
        "source_paths": {
            "primary": "governance://agents.md",
            "related": [
                "tools/seed-component-registry.py",
                "backend/lambda/coordination_api/governance_data_dictionary.json",
            ],
        },
    },
    # ── jreesewebops (ENC-FTR-042) ───────────────────────────────────────────
    {
        "component_id": "comp-jwo-web-infra",
        "component_name": "Web Infrastructure (CloudFront/S3/Cloudflare/Lightsail)",
        "project_id": "jreesewebops",
        "category": "infrastructure",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "Unified web infrastructure for jreese.net, jree.se, go.thepup.io — CloudFront distributions, S3 origins, Cloudflare Workers/DNS, Lightsail instances. Admin-managed via consoles.",
        "status": "active",
    },
    # ── jreeseGPT (ENC-FTR-042) ──────────────────────────────────────────────
    {
        "component_id": "comp-jgp-platform",
        "component_name": "jreeseGPT AI Platform",
        "project_id": "jreeseGPT",
        "category": "external",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "AI recruiter assistant — corpus ingestion, embeddings, Bedrock/Lambda APIs, scheduling workflows. Development stage.",
        "status": "active",
    },
    # ── jobapps (ENC-FTR-042) ────────────────────────────────────────────────
    {
        "component_id": "comp-jap-jds-platform",
        "component_name": "Job Discovery System (JDS)",
        "project_id": "jobapps",
        "category": "external",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "JDS scraper runners, configuration playbooks, ChromeDriver hardening, and analytics. Development stage.",
        "status": "active",
    },
    # ── intelligent-scraper-generator (ENC-FTR-042) ──────────────────────────
    {
        "component_id": "comp-isg-toolkit",
        "component_name": "Intelligent Scraper Generator",
        "project_id": "intelligent-scraper-generator",
        "category": "library",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "LLM-assisted toolkit for analyzing employer career sites and generating scraper/playbook scaffolding. Child of jobapps JDS pipeline.",
        "status": "active",
    },
    # ── property160c1 (ENC-FTR-042) ──────────────────────────────────────────
    {
        "component_id": "comp-prp-planning",
        "component_name": "Property 160C1 Planning",
        "project_id": "property160c1",
        "category": "workflow",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "Property 160C1 project planning and requirements artifacts. Planning stage.",
        "status": "active",
    },
    # ── agentharmony (ENC-FTR-042) ───────────────────────────────────────────
    {
        "component_id": "comp-agh-governance",
        "component_name": "Agent Harmony Governance & Templates",
        "project_id": "agentharmony",
        "category": "workflow",
        "transition_type": "no_code",
        "required_transition_type": "no_code",
        "description": "Agent documentation standards, templates (bootstrap-session.sh, codex-auto.sh), and operational tooling inherited by all downstream projects.",
        "status": "active",
    },
]

_DEFAULT_TRANSITION_TYPE = "github_pr_deploy"


def _api_request(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    payload: dict | None = None,
    extra_headers: dict | None = None,
) -> tuple[int, dict]:
    url = f"{base_url.rstrip('/')}{path}"
    body = json.dumps(payload).encode() if payload is not None else None
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-Coordination-Internal-Key": api_key,
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
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


def seed(
    base_url: str,
    api_key: str,
    dry_run: bool,
    assistant_key: str = "",
    direct_apigw_base: str = "",
) -> None:
    ok_count = 0
    skip_count = 0
    err_count = 0
    needs_manual_patch: list[tuple[str, str]] = []  # (component_id, target_transition_type)

    for comp in KNOWN_COMPONENTS:
        cid = comp["component_id"]
        target_type = comp["transition_type"]
        print(f"\n[{cid}] ({target_type})", end="")

        if dry_run:
            print(" — DRY RUN, skipping")
            continue

        # Check if already exists
        status, existing = _api_request(base_url, api_key, "GET", f"/components/{cid}")
        if status == 200:
            existing_type = existing.get("component", {}).get("transition_type", "")
            if existing_type == target_type:
                print(f" — already exists with same transition_type ({existing_type}), skipping")
                skip_count += 1
                continue
            else:
                print(
                    f" — already exists with DIFFERENT transition_type "
                    f"({existing_type} vs {target_type}), SKIPPING to avoid overwrite"
                )
                skip_count += 1
                continue

        # Non-default transition_type requires assistant key or Cognito.
        # Without those: create with default type, record for manual follow-up.
        needs_type_auth = target_type != _DEFAULT_TRANSITION_TYPE

        if needs_type_auth and not assistant_key:
            create_payload = {k: v for k, v in comp.items() if k != "transition_type"}
            status, result = _api_request(base_url, api_key, "POST", "/components", create_payload)
            if status == 201:
                print(
                    f" — CREATED with default type (github_pr_deploy); "
                    f"⚠️  MANUAL PATCH needed → transition_type={target_type} (via PWA or --assistant-key)"
                )
                needs_manual_patch.append((cid, target_type))
                ok_count += 1
            elif status == 409:
                print(f" — 409 Conflict (already exists), skipping")
                skip_count += 1
            else:
                print(f" — ERROR {status}: {result.get('error', result)}")
                err_count += 1
            continue

        # Build create payload; use assistant key + direct APIGW for non-default types
        create_payload = dict(comp)
        if needs_type_auth and assistant_key:
            extra = {"X-Checkout-Assistant-Key": assistant_key}
            create_base = (direct_apigw_base or base_url).rstrip("/")
            status, result = _api_request(
                create_base, api_key, "POST", "/components", create_payload, extra
            )
        else:
            status, result = _api_request(base_url, api_key, "POST", "/components", create_payload)

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
    if needs_manual_patch:
        print(f"\n⚠️  {len(needs_manual_patch)} component(s) created with wrong transition_type — manual PATCH needed:")
        for cid, tt in needs_manual_patch:
            print(f"   {cid}  →  {tt}")
        print(
            "\n   Fix options:\n"
            "   1. Open jreese.net/components, find the component, click Edit, set Transition Type.\n"
            "   2. Re-run with: CHECKOUT_ASSISTANT_KEY=<key> python3 tools/seed-component-registry.py\n"
            "      (script will SKIP existing correct-type entries; only patch mismatches need manual fix)"
        )
    if err_count:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed Enceladus component registry (ENC-FTR-041)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be done without making API calls",
    )
    parser.add_argument("--base-url", default=None, help="Coordination API base URL")
    parser.add_argument("--api-key", default=None, help="Internal API key")
    parser.add_argument(
        "--assistant-key", default=None,
        help=(
            "Checkout-service-assistant key (X-Checkout-Assistant-Key). "
            "Allows setting non-default transition_type at create time without Cognito. "
            "Env var: CHECKOUT_ASSISTANT_KEY"
        ),
    )
    parser.add_argument(
        "--direct-apigw-base", default=None,
        help=(
            "Direct API Gateway base URL for assistant-key requests (bypasses CloudFront). "
            "Env var: COORDINATION_DIRECT_APIGW_BASE. "
            "Default: https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/coordination"
        ),
    )
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
    assistant_key = args.assistant_key or os.environ.get("CHECKOUT_ASSISTANT_KEY", "")
    direct_apigw_base = (
        args.direct_apigw_base
        or os.environ.get("COORDINATION_DIRECT_APIGW_BASE", "")
        or "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/coordination"
    )

    if not api_key and not args.dry_run:
        print(
            "ERROR: --api-key or ENCELADUS_COORDINATION_INTERNAL_API_KEY env var is required",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Base URL:      {base_url}")
    print(f"Direct APIGW:  {direct_apigw_base}")
    print(f"Dry run:       {args.dry_run}")
    print(f"Assistant key: {'set' if assistant_key else 'not set — non-default types will default to github_pr_deploy'}")
    print(f"Components:    {len(KNOWN_COMPONENTS)}")

    seed(
        base_url,
        api_key,
        dry_run=args.dry_run,
        assistant_key=assistant_key,
        direct_apigw_base=direct_apigw_base,
    )


if __name__ == "__main__":
    main()
