#!/usr/bin/env python3
"""reference_summary_generator.py — Token-optimized project summary generator.

Generates concise project summaries from S3 reference files for population into
the projects DynamoDB table 'summary' attribute. Enables terminal sessions to
query projects table (1-2KB) instead of reading full reference docs (10KB+).

Usage:
  # Generate summary for a single project
  python3 tools/reference_summary_generator.py generate enceladus

  # Generate summaries for all projects in projects table
  python3 tools/reference_summary_generator.py generate-all

  # Check if summary needs update (returns exit code)
  python3 tools/reference_summary_generator.py needs-update enceladus

Key features:
- Extracts key sections from markdown reference files
- Change detection with SHA256 checksums
- Respects ~150-300 token limit for optimal context efficiency
- Structured metadata extraction (status, technologies, key features)
- Idempotent: detects unchanged content, skips DynamoDB updates
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import urllib.parse
from typing import Any, Dict, Optional, Tuple

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    print("[ERROR] boto3 required: pip3 install boto3", file=sys.stderr)
    sys.exit(1)

# ============================================================================
# Configuration
# ============================================================================

REFERENCE_S3_BUCKET = os.environ.get("REFERENCE_S3_BUCKET", "jreese-net")
REFERENCE_S3_PREFIX = os.environ.get("REFERENCE_S3_PREFIX", "mobile/v1/reference")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")

# Summary generation constraints
SUMMARY_TARGET_TOKENS = 150  # Target ~150 tokens (very concise)
SUMMARY_MAX_TOKENS = 300  # Hard limit ~300 tokens
SUMMARY_TARGET_CHARS = SUMMARY_TARGET_TOKENS * 4  # Rough estimate: 1 token ≈ 4 chars

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


# ============================================================================
# Core Functions
# ============================================================================


def _get_s3_client():
    """Get boto3 S3 client."""
    return boto3.client("s3", region_name=DYNAMODB_REGION)


def _get_dynamodb_client():
    """Get boto3 DynamoDB client."""
    return boto3.client("dynamodb", region_name=DYNAMODB_REGION)


def _fetch_reference_from_s3(project_id: str) -> Optional[str]:
    """Fetch full reference markdown from S3."""
    s3_key = f"{REFERENCE_S3_PREFIX}/{project_id}.md"
    s3 = _get_s3_client()
    try:
        logger.info(f"Fetching reference from s3://{REFERENCE_S3_BUCKET}/{s3_key}")
        resp = s3.get_object(Bucket=REFERENCE_S3_BUCKET, Key=s3_key)
        content = resp["Body"].read().decode("utf-8", errors="replace")
        logger.info(f"Reference fetched: {len(content)} bytes")
        return content
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchKey":
            logger.warning(f"Reference not found: s3://{REFERENCE_S3_BUCKET}/{s3_key}")
            return None
        logger.exception("S3 get_object failed")
        return None


def _extract_summary_sections(reference_md: str) -> Dict[str, str]:
    """Extract key sections from markdown reference file for summary generation.

    Returns dict with keys: executive_summary, status, tech_stack, key_features, etc.
    """
    sections: Dict[str, str] = {}

    # Try to extract Executive Summary section (preferred)
    # Handle formats like "## 1. 🧭 Executive Summary" or "## Executive Summary"
    exec_summary_match = re.search(
        r"#+\s*(?:\d+\.\s*)?(?:🧭\s*)?Executive Summary.*?\n(.*?)(?=\n#+\s*(?:\d+\.)?|\Z)",
        reference_md,
        re.IGNORECASE | re.DOTALL,
    )
    if exec_summary_match:
        exec_text = exec_summary_match.group(1).strip()
        # Take first 2-3 paragraphs
        paragraphs = re.split(r"\n\n+", exec_text)
        summary_paras = []
        for para in paragraphs[:3]:
            para_stripped = para.strip()
            # Skip table of contents and list-only sections
            if para_stripped and not all(
                para_stripped.startswith(prefix) for prefix in ("- ", "* ", "1.", "2.", "###")
            ):
                summary_paras.append(para_stripped)
        if summary_paras:
            sections["executive_summary"] = " ".join(summary_paras)

    # Extract project overview (first paragraph or intro section)
    if not sections.get("executive_summary"):
        intro_match = re.search(r"^#+\s+(.+?)(?:\n\n|\n#{1,6}\s)", reference_md, re.MULTILINE)
        if intro_match:
            sections["intro"] = intro_match.group(1).strip()

    # Extract status if mentioned
    status_match = re.search(
        r"(?:Product/Development\s)?[Ss]tatus[`:\s]*[`*]*(\w+[^*\n`]*)[`*]*",
        reference_md,
    )
    if status_match:
        sections["status"] = status_match.group(1).strip()

    # Extract technology stack
    tech_section = re.search(
        r"#+\s*(?:Technology|Tech Stack|Stack|Built with|Operational Platforms).*?\n(.*?)(?=\n#+\s|\Z)",
        reference_md,
        re.IGNORECASE | re.DOTALL,
    )
    if tech_section:
        tech_text = tech_section.group(1).strip()
        # Extract key technologies (usually in code blocks or bullet points)
        techs = re.findall(r"[-*]\s*(?:\*\*)?([^:\n*]+?)(?:\*\*)?(?:\s*[:—-]|$)", tech_text)
        if techs:
            sections["technologies"] = ", ".join([t.strip() for t in techs[:5]])

    # Extract key features / capabilities
    features_section = re.search(
        r"#+\s*(?:Features|Key Features|Capabilities).*?\n(.*?)(?=\n#+\s|\Z)",
        reference_md,
        re.IGNORECASE | re.DOTALL,
    )
    if features_section:
        features_text = features_section.group(1).strip()
        features = re.findall(r"[-*]\s*(?:\*\*)?([^:\n*]+?)(?:\*\*)?(?:\s*[:—-]|$)", features_text)
        if features:
            sections["features"] = "; ".join([f.strip() for f in features[:3]])

    return sections


def _generate_summary(reference_md: str, project_id: str) -> str:
    """Generate concise summary from full reference markdown.

    Target: 150-300 tokens (200-1200 chars).
    Includes: project purpose, status, key technologies, key features.

    Strategy:
    1. If Executive Summary exists in reference, use it (already optimized)
    2. Otherwise, synthesize from extracted sections
    """
    sections = _extract_summary_sections(reference_md)

    # Prefer executive summary if available
    if sections.get("executive_summary"):
        summary = sections["executive_summary"]
    else:
        summary_parts = []

        # Add intro
        if sections.get("intro"):
            intro = sections["intro"]
            if intro.startswith("#"):
                intro = intro.lstrip("#").strip()
            summary_parts.append(intro)

        # Add status
        if sections.get("status"):
            summary_parts.append(f"Status: {sections['status']}")

        # Add key technologies
        if sections.get("technologies"):
            summary_parts.append(f"Built with: {sections['technologies']}")

        # Add key features
        if sections.get("features"):
            summary_parts.append(f"Features: {sections['features']}")

        summary = " ".join(summary_parts).strip()

    # Truncate to target size if needed
    if len(summary) > SUMMARY_TARGET_CHARS:
        # Try to truncate at sentence boundary
        truncated = summary[: SUMMARY_TARGET_CHARS]
        last_period = truncated.rfind(".")
        if last_period > SUMMARY_TARGET_CHARS * 0.8:
            summary = truncated[: last_period + 1]
        else:
            # Try paragraph boundary
            last_newline = truncated.rfind("\n")
            if last_newline > SUMMARY_TARGET_CHARS * 0.7:
                summary = truncated[:last_newline].strip()
            else:
                summary = truncated.rstrip() + "…"

    logger.info(f"Generated summary: {len(summary)} chars (~{len(summary)//4} tokens)")
    return summary


def _compute_checksum(summary: str) -> str:
    """Compute SHA256 checksum of summary for change detection."""
    return hashlib.sha256(summary.encode("utf-8")).hexdigest()


def _get_current_project_summary(project_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Get current summary and checksum from projects table.

    Returns: (summary, checksum) or (None, None) if not found.
    """
    ddb = _get_dynamodb_client()
    try:
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="summary, summary_checksum",
        )
        item = resp.get("Item", {})
        summary = item.get("summary", {}).get("S")
        checksum = item.get("summary_checksum", {}).get("S")
        return summary, checksum
    except ClientError:
        logger.exception("DynamoDB get_item failed")
        return None, None


def _update_project_summary(project_id: str, summary: str, checksum: str) -> bool:
    """Update projects table with new summary and checksum.

    Returns: True if updated, False otherwise.
    """
    ddb = _get_dynamodb_client()
    try:
        ddb.update_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            UpdateExpression="SET #summary = :summary, #checksum = :checksum, #updated = :now",
            ExpressionAttributeNames={
                "#summary": "summary",
                "#checksum": "summary_checksum",
                "#updated": "summary_updated_at",
            },
            ExpressionAttributeValues={
                ":summary": {"S": summary},
                ":checksum": {"S": checksum},
                ":now": {"S": _now_z()},
            },
        )
        logger.info(f"Updated project {project_id} summary in DynamoDB")
        return True
    except ClientError:
        logger.exception("DynamoDB update_item failed")
        return False


def _now_z() -> str:
    """Return current timestamp in ISO 8601 format (UTC)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================================
# Public Interface
# ============================================================================


def generate_summary(project_id: str) -> Dict[str, Any]:
    """Generate summary for a project and update DynamoDB if changed.

    Args:
        project_id: Project identifier (e.g., "enceladus")

    Returns:
        Dict with keys:
        - success (bool)
        - project_id (str)
        - summary (str) — the generated summary
        - checksum (str) — SHA256 of summary
        - changed (bool) — True if DynamoDB was updated
        - error (str, optional) — error message if failed
    """
    logger.info(f"[START] Generating summary for {project_id}")

    # Fetch reference from S3
    reference_md = _fetch_reference_from_s3(project_id)
    if not reference_md:
        logger.warning(f"No reference found for {project_id}, skipping")
        return {
            "success": False,
            "project_id": project_id,
            "error": f"Reference file not found in S3 for {project_id}",
        }

    # Generate summary
    try:
        summary = _generate_summary(reference_md, project_id)
        checksum = _compute_checksum(summary)
    except Exception as exc:
        logger.exception("Summary generation failed")
        return {
            "success": False,
            "project_id": project_id,
            "error": f"Summary generation failed: {exc}",
        }

    # Check if changed
    current_summary, current_checksum = _get_current_project_summary(project_id)
    if current_checksum == checksum:
        logger.info(f"[OK] Summary unchanged for {project_id}, skipping DynamoDB update")
        return {
            "success": True,
            "project_id": project_id,
            "summary": summary,
            "checksum": checksum,
            "changed": False,
        }

    # Update DynamoDB
    if not _update_project_summary(project_id, summary, checksum):
        logger.error(f"Failed to update DynamoDB for {project_id}")
        return {
            "success": False,
            "project_id": project_id,
            "error": "DynamoDB update failed",
        }

    logger.info(f"[SUCCESS] Updated {project_id} summary")
    return {
        "success": True,
        "project_id": project_id,
        "summary": summary,
        "checksum": checksum,
        "changed": True,
    }


def needs_update(project_id: str) -> bool:
    """Check if project summary needs update (exits with 0/1).

    Fetches reference from S3, generates checksum, compares with DynamoDB.
    Returns True if checksums differ (update needed).
    """
    reference_md = _fetch_reference_from_s3(project_id)
    if not reference_md:
        logger.warning(f"Reference not found for {project_id}")
        return False

    try:
        summary = _generate_summary(reference_md, project_id)
        checksum = _compute_checksum(summary)
    except Exception:
        logger.exception("Summary generation failed")
        return False

    _, current_checksum = _get_current_project_summary(project_id)
    if current_checksum == checksum:
        logger.info(f"{project_id}: no update needed")
        return False

    logger.info(f"{project_id}: update available (new checksum: {checksum[:8]})")
    return True


# ============================================================================
# CLI
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Token-optimized project summary generator"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate <project_id>
    gen_parser = subparsers.add_parser("generate", help="Generate summary for project")
    gen_parser.add_argument("project_id", help="Project ID (e.g., enceladus)")

    # generate-all
    subparsers.add_parser("generate-all", help="Generate summaries for all projects")

    # needs-update <project_id>
    upd_parser = subparsers.add_parser("needs-update", help="Check if summary needs update")
    upd_parser.add_argument("project_id", help="Project ID")

    args = parser.parse_args()

    if args.command == "generate":
        result = generate_summary(args.project_id)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["success"] else 1)

    elif args.command == "needs-update":
        needs = needs_update(args.project_id)
        sys.exit(0 if needs else 1)

    elif args.command == "generate-all":
        # TODO: Implement generate-all by scanning projects table
        logger.error("generate-all not yet implemented")
        sys.exit(1)


if __name__ == "__main__":
    main()
