#!/usr/bin/env python3
"""elr_smoke.py -- ELR prod smoke test.

Runs one cheap governed READ (GET the same health endpoint the MCP
connection_health tool uses -- server.py:_health_api_request /
HEALTH_API_URL) through InternalClient, and prints ONLY the digest JSON
to stdout. Never prints the internal API key (or, when credential-bound,
the sci -- only its remaining TTL).

Also resolves ELR's identity posture (ENC-TSK-P75, elr_lib.identity,
AC-1/AC-4) BEFORE the health read: credential-bound (a live ENC-SES
session is registered+claimed, or a cached one reused), internal-key, or
unknown. The health endpoint itself never sends a key/sci either way
(server.py parity -- it doesn't gate on identity) so this doesn't change
what gets sent on the wire; it changes what the digest truthfully
reports about who ELR currently is. See --keep-session below for the
session's fate on exit.

Usage:
    python3 tools/elr/elr_smoke.py
    python3 tools/elr/elr_smoke.py --profile internal --timeout 10
    python3 tools/elr/elr_smoke.py --keep-session

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

from elr_lib import identity as elr_identity  # noqa: E402
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
    parser.add_argument(
        "--keep-session",
        action="store_true",
        default=False,
        help=(
            "When credential-bound, cache the resolved session in "
            "~/.enceladus/session.json (0600) for reuse instead of retiring "
            "it on exit (ENC-TSK-P75 AC-3)."
        ),
    )
    return parser


def run_health_smoke(profile_name: str, timeout: int, *, keep_session: bool = False) -> Dict[str, Any]:
    config = get_profile(profile_name)
    client = InternalClient(config, timeout=timeout)

    # AC-1: resolve identity BEFORE the read. This is best-effort/never
    # raises -- resolve_identity() itself falls back through the posture
    # chain on any failure, it never propagates a network error here.
    identity_ctx = elr_identity.resolve_identity(
        profile_name=profile_name, timeout=timeout, keep_session=keep_session, client=client
    )

    try:
        status, body = client.health()
        key_sent = bool(config.key_for("health"))  # health never sends a key (server.py parity)
        # classify_internal_posture's OWN posture return is discarded here
        # -- it can only ever say "server-held-keys" for this keyless
        # endpoint, which is not one of AC-4's three smoke postures. The
        # digest's identity_posture is elr_identity's resolved posture;
        # only this call's anomaly detection (unreachable/5xx/4xx) is
        # still used, UNCHANGED from before (AC-4).
        _transport_posture, anomalies = classify_internal_posture(key_sent=key_sent, status_code=status)
        anomalies = list(identity_ctx.anomalies) + list(anomalies)
        ok = 200 <= status < 300

        counts: Optional[Dict[str, Any]] = None
        if isinstance(body, dict):
            summarized = {k: body[k] for k in ("dynamodb", "s3") if k in body}
            if summarized:
                counts = summarized
            if "error" in body:
                anomalies = list(anomalies) + [f"health_body_error: {body['error']}"]

        extra: Dict[str, Any] = {}
        if identity_ctx.posture == elr_identity.POSTURE_CREDENTIAL_BOUND:
            extra["session_id"] = identity_ctx.session_id
            extra["agent_type_id"] = identity_ctx.agent_type_id
            remaining = identity_ctx.sci_ttl_remaining_s()
            if remaining is not None:
                extra["sci_ttl_remaining_s"] = remaining

        return build_digest(
            "elr_smoke.health_check",
            ok,
            status,
            identity_posture=identity_ctx.posture,
            anomalies=anomalies,
            counts=counts,
            **extra,
        )
    finally:
        # AC-3: retire-on-exit (or cache, with --keep-session). No-op for
        # a non-credential-bound posture. Runs even if the health call
        # above raised, so a resolved session is never leaked.
        elr_identity.finalize_identity(
            identity_ctx, client, keep_session=keep_session, profile_name=profile_name, timeout=timeout
        )


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    digest = run_health_smoke(args.profile, args.timeout, keep_session=args.keep_session)
    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
