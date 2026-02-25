#!/usr/bin/env python3
"""
Sync docs/ARCHITECTURE.md from the repository to the Enceladus docstore.

This script is called by the GitHub Actions workflow `sync-architecture-doc.yml`
whenever `docs/ARCHITECTURE.md` is modified on the main branch.

It reads the file from the repo, then calls the Enceladus Document API
to update the docstore mirror (DOC-BC7A97216DF8).

Usage:
    python tools/sync_architecture_doc.py [--dry-run]

Environment:
    AWS_REGION (default: us-west-2)
    ARCHITECTURE_DOC_ID (default: DOC-BC7A97216DF8)
    COORDINATION_INTERNAL_API_KEY (required for auth)
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error

API_BASE = os.environ.get("API_BASE_URL", "https://jreese.net/api/v1")
DOC_ID = os.environ.get("ARCHITECTURE_DOC_ID", "DOC-BC7A97216DF8")
INTERNAL_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARCH_PATH = os.path.join(REPO_ROOT, "docs", "ARCHITECTURE.md")


def read_architecture_doc():
    """Read the architecture document from the repo."""
    if not os.path.exists(ARCH_PATH):
        print(f"ERROR: {ARCH_PATH} not found")
        sys.exit(1)
    with open(ARCH_PATH, "r") as f:
        return f.read()


def compute_hash(content: str) -> str:
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def patch_document(content: str, dry_run: bool = False):
    """Update the docstore document via the Document API."""
    content_hash = compute_hash(content)
    print(f"Content hash: {content_hash}")
    print(f"Content size: {len(content)} bytes")

    if dry_run:
        print("[DRY RUN] Would PATCH document:", DOC_ID)
        print("[DRY RUN] No API call made.")
        return True

    if not INTERNAL_KEY:
        print("ERROR: COORDINATION_INTERNAL_API_KEY not set")
        sys.exit(1)

    url = f"{API_BASE}/documents/{DOC_ID}"
    payload = json.dumps({
        "content": content,
        "description": f"Architecture Reference synced from repo (hash: {content_hash[:12]})",
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        method="PATCH",
        headers={
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": INTERNAL_KEY,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if body.get("success"):
                print(f"SUCCESS: Document {DOC_ID} updated")
                print(f"  Version: {body.get('version')}")
                print(f"  Updated at: {body.get('updated_at')}")
                return True
            else:
                print(f"ERROR: API returned success=false: {body}")
                return False
    except urllib.error.HTTPError as e:
        print(f"ERROR: HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Sync ARCHITECTURE.md to docstore")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without making API calls")
    args = parser.parse_args()

    print(f"Reading: {ARCH_PATH}")
    content = read_architecture_doc()
    print(f"Read {len(content)} bytes")

    success = patch_document(content, dry_run=args.dry_run)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
