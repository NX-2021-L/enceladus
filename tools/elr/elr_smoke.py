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
    python3 tools/elr/elr_smoke.py --profile v4-gamma --timeout 10
    python3 tools/elr/elr_smoke.py --keep-session
    python3 tools/elr/elr_smoke.py --all-profiles

`--profile` (ENC-TSK-P77, default "prod", or ENCELADUS_PROFILE) selects
the ELR ENVIRONMENT profile (elr_lib.profiles: "prod" / "v4-gamma") --
NOT elr_lib.config's separate TRANSPORT profile concept ("internal" /
"mcp-http"), which this script still always uses "internal" for (the
only transport that supports the health smoke read; see elr_lib/config.py
and elr_lib/profiles.py module docstrings for the two-axis distinction).
`--all-profiles` runs the health check under EVERY environment profile
and prints one digest per profile (still one JSON object per line).

Exit code (single-profile run): 0 when the health check succeeded (2xx),
4 when the CA bundle could not be resolved (ENC-TSK-P76 AC-2), 1
otherwise. With --all-profiles: 0 only if every profile's digest was ok,
else the worst of (4 if any profile hit TLS-unresolved, else 1).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow running this file directly (python3 tools/elr/elr_smoke.py) without
# requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import identity as elr_identity  # noqa: E402
from elr_lib import profiles as elr_profiles  # noqa: E402
from elr_lib import tls as elr_tls  # noqa: E402
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
        default=elr_profiles.PROFILE_PROD,
        choices=list(elr_profiles.VALID_ENVIRONMENT_PROFILES),
        help=(
            "ELR ENVIRONMENT profile to use -- which deployed Enceladus "
            "environment to smoke-test (default: prod; ENCELADUS_PROFILE "
            "env var also selects this). Ignored when --all-profiles is set."
        ),
    )
    parser.add_argument(
        "--all-profiles",
        action="store_true",
        default=False,
        help="Run the health check under EVERY environment profile and emit one digest per profile (ENC-TSK-P77 AC-2).",
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


def run_health_smoke(
    environment_profile_name: str, timeout: int, *, keep_session: bool = False, transport_profile_name: str = "internal"
) -> Dict[str, Any]:
    config = get_profile(transport_profile_name, environment_profile_name=environment_profile_name)
    client = InternalClient(config, timeout=timeout)
    resolved_profile_name = config.environment_profile.name

    # AC-1: resolve identity BEFORE the read. This is best-effort/never
    # raises -- resolve_identity() itself falls back through the posture
    # chain on any failure, it never propagates a network error here.
    identity_ctx = elr_identity.resolve_identity(
        profile_name=transport_profile_name, timeout=timeout, keep_session=keep_session, client=client
    )

    try:
        status, body = client.health()

        # AC-2 (ENC-TSK-P76): a TLS-unresolvable CA bundle short-circuits
        # InternalClient before urlopen ever runs -- status is the
        # TLS_UNRESOLVED_STATUS sentinel (a str), never an HTTP int, so it
        # must be handled before any int comparison/classification below.
        if status == elr_tls.TLS_UNRESOLVED_STATUS:
            extra = dict(client.ca_bundle_digest_fields())
            if identity_ctx.posture == elr_identity.POSTURE_CREDENTIAL_BOUND:
                extra["session_id"] = identity_ctx.session_id
                extra["agent_type_id"] = identity_ctx.agent_type_id
            return build_digest(
                "elr_smoke.health_check",
                False,
                status,
                identity_posture=identity_ctx.posture,
                anomalies=list(identity_ctx.anomalies) + ["tls_ca_bundle_missing"],
                # ENC-TSK-P77: elr.smoke_digest schema fields -- present
                # even on the TLS-unresolved short-circuit path.
                profile=resolved_profile_name,
                prefix_map_source="none",
                unclassified=[],
                **extra,
            )

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
        governance_hash: Optional[str] = None
        if isinstance(body, dict):
            summarized = {k: body[k] for k in ("dynamodb", "s3") if k in body}
            if summarized:
                counts = summarized
            governance_hash = body.get("governance_hash") or None
            if "error" in body:
                anomalies = list(anomalies) + [f"health_body_error: {body['error']}"]

        # AC-1 (ENC-TSK-P76): ca_bundle:{source,path} on every digest, not
        # only the TLS-unresolvable one above.
        extra: Dict[str, Any] = dict(client.ca_bundle_digest_fields())
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
            # ENC-TSK-P77 / BRD elr.smoke_digest schema:
            profile=resolved_profile_name,
            governance_hash=governance_hash,
            prefix_map_source="none",  # health checks classify no record ids (see elr_lib.prefix)
            unclassified=[],
            **extra,
        )
    finally:
        # AC-3: retire-on-exit (or cache, with --keep-session). No-op for
        # a non-credential-bound posture. Runs even if the health call
        # above raised, so a resolved session is never leaked.
        elr_identity.finalize_identity(
            identity_ctx, client, keep_session=keep_session, profile_name=transport_profile_name, timeout=timeout
        )


def _digest_exit_code(digest: Dict[str, Any]) -> int:
    if digest.get("status") == elr_tls.TLS_UNRESOLVED_STATUS:
        return elr_tls.EXIT_CODE_TLS_UNRESOLVED
    return 0 if digest.get("ok") else 1


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.all_profiles:
        # ENC-TSK-P77 AC-2: one digest per environment profile, still one
        # JSON object per stdout line. A single-profile run (below) is
        # otherwise byte-for-byte unchanged apart from the new fields.
        digests: List[Dict[str, Any]] = []
        for profile_name in elr_profiles.VALID_ENVIRONMENT_PROFILES:
            digest = run_health_smoke(profile_name, args.timeout, keep_session=args.keep_session)
            print(json.dumps(digest, sort_keys=True))
            digests.append(digest)
        exit_codes = [_digest_exit_code(d) for d in digests]
        if all(code == 0 for code in exit_codes):
            return 0
        return elr_tls.EXIT_CODE_TLS_UNRESOLVED if elr_tls.EXIT_CODE_TLS_UNRESOLVED in exit_codes else 1

    digest = run_health_smoke(args.profile, args.timeout, keep_session=args.keep_session)
    print(json.dumps(digest, sort_keys=True))
    # AC-2 (ENC-TSK-P76): TLS-unresolvable is always exit code 4, distinct
    # from a plain network/auth failure (1).
    return _digest_exit_code(digest)


if __name__ == "__main__":
    sys.exit(main())
