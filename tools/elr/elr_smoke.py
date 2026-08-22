#!/usr/bin/env python3
"""elr_smoke.py -- ELR prod smoke test.

Runs one cheap governed READ (GET the same health endpoint the MCP
connection_health tool uses -- server.py:_health_api_request /
HEALTH_API_URL) through InternalClient, and prints ONLY the digest JSON
to stdout. Never prints the internal API key.

Usage:
    python3 tools/elr/elr_smoke.py
    python3 tools/elr/elr_smoke.py --profile internal --timeout 10

Exit code is 0 when the health check succeeded (2xx), 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Allow running this file directly (python3 tools/elr/elr_smoke.py) without
# requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib.config import get_profile  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402
from elr_lib.transport import InternalClient, classify_internal_posture  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    # ALL ELR CLIs must set allow_abbrev=False so partial/ambiguous flags
    # (e.g. "--prof" matching "--profile") are never silently accepted.
    parser = argparse.ArgumentParser(
        prog="elr_smoke",
        description="ELR prod smoke test: one cheap governed READ, digest-only output.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--profile",
        default="internal",
        choices=["internal"],
        help="ELR profile to use (only 'internal' supports the health smoke read).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15).",
    )
    return parser


def run_health_smoke(profile_name: str, timeout: int) -> Dict[str, Any]:
    config = get_profile(profile_name)
    client = InternalClient(config, timeout=timeout)

    status, body = client.health()
    key_sent = bool(config.key_for("health"))  # health never sends a key (server.py parity)
    posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
    ok = 200 <= status < 300

    counts: Optional[Dict[str, Any]] = None
    if isinstance(body, dict):
        summarized = {k: body[k] for k in ("dynamodb", "s3") if k in body}
        if summarized:
            counts = summarized
        if "error" in body:
            anomalies = list(anomalies) + [f"health_body_error: {body['error']}"]

    return build_digest(
        "elr_smoke.health_check",
        ok,
        status,
        identity_posture=posture,
        anomalies=anomalies,
        counts=counts,
    )


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    digest = run_health_smoke(args.profile, args.timeout)
    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
