#!/usr/bin/env python3
"""Plane-truth canary: cross-plane identity probe (ENC-ISS-640 / ENC-TSK-O42).

Prod and gamma are isolated by configuration, not by boundary: they share an
ID space (ENC-ISS-538) and route by per-Lambda env wiring with prod-pointing
defaults. When a surface mis-routes, the same record ID can resolve to two
different real records — which is how a governed checkout arc intended for a
gamma throwaway executed against PROD ENC-TSK-M29 (ENC-ISS-640).

This canary codifies the S6 hand audit that caught it, using only agent-tier
auth (a Cognito id_token cookie; both planes share the pool):

  1. Fetch each sentinel record from the PROD and GAMMA tracker APIs directly
     (default: the raw APIGW execute-api hosts, immune to CDN-layer routing).
  2. Classify: BOTH_MATCH / PROD_ONLY / GAMMA_ONLY / DIVERGENT / ERROR.
     DIVERGENT (one ID, two identities) is the ISS-538/640 collision signal.
  3. Optionally probe extra surfaces (--surface NAME=BASE_URL, e.g. an MCP
     gateway's REST facade) and attribute each answer to the plane whose
     direct read it matches — a mis-routed surface shows up immediately.

Exit codes: 0 clean, 1 fetch errors only, 2 divergence/mis-attribution found.
Usage:
    export ENCELADUS_ID_TOKEN='eyJ...'      # or --cookie-file <path>
    python3 tools/plane_truth_canary.py --ids ENC-TSK-M29,ENC-TSK-N62
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

PROD_BASE = "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com"
GAMMA_BASE = "https://hi0dzmvqrc.execute-api.us-west-2.amazonaws.com"

# Python builds without a wired CA store (e.g. python.org framework installs)
# fail every https fetch with CERTIFICATE_VERIFY_FAILED. Resolve a real CA
# bundle instead of disabling verification — a plane-truth tool must never
# trust an unverified peer.
_CA_CANDIDATES = (
    "/etc/ssl/cert.pem",                      # macOS
    "/etc/ssl/certs/ca-certificates.crt",     # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",       # Amazon Linux / RHEL
)


def _ssl_context():
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0):
        return ctx
    try:
        import certifi  # type: ignore
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    for cafile in _CA_CANDIDATES:
        if os.path.exists(cafile):
            return ssl.create_default_context(cafile=cafile)
    return ctx  # verification will fail loudly rather than silently trust


SSL_CTX = _ssl_context()


def fetch(base, project, record_type, record_id, token, timeout=25):
    """Return (state, identity) where identity is (title, created_at) or None."""
    url = f"{base}/api/v1/tracker/{project}/{record_type}/{record_id}"
    req = urllib.request.Request(url, headers={
        "Cookie": f"enceladus_id_token={token}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "NOT_FOUND", None
        if e.code in (401, 403):
            return "AUTH_ERROR", None
        return f"HTTP_{e.code}", None
    except Exception as e:  # noqa: BLE001 - canary reports, never crashes
        return f"ERROR:{type(e).__name__}", None

    record = body.get("record") or body.get("task") or body
    if not body.get("success", True) or not isinstance(record, dict):
        return "NOT_FOUND", None
    identity = (record.get("title"), record.get("created_at"))
    if identity == (None, None):
        return "NOT_FOUND", None
    return "OK", identity


def classify(prod, gamma):
    pstate, pid_ = prod
    gstate, gid_ = gamma
    if pstate == "OK" and gstate == "OK":
        return "BOTH_MATCH" if pid_ == gid_ else "DIVERGENT"
    if pstate == "OK" and gstate == "NOT_FOUND":
        return "PROD_ONLY"
    if pstate == "NOT_FOUND" and gstate == "OK":
        return "GAMMA_ONLY"
    if pstate == "NOT_FOUND" and gstate == "NOT_FOUND":
        return "ABSENT_BOTH"
    return "ERROR"


def attribute(surface_result, prod, gamma):
    state, ident = surface_result
    if state != "OK":
        return state
    matches = []
    if prod[0] == "OK" and ident == prod[1]:
        matches.append("PROD")
    if gamma[0] == "OK" and ident == gamma[1]:
        matches.append("GAMMA")
    if not matches:
        return "NEITHER"
    return "+".join(matches)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ids", default="ENC-TSK-M29,ENC-TSK-N62",
                    help="comma-separated sentinel record IDs")
    ap.add_argument("--project", default="enceladus")
    ap.add_argument("--record-type", default="task")
    ap.add_argument("--prod-base", default=PROD_BASE)
    ap.add_argument("--gamma-base", default=GAMMA_BASE)
    ap.add_argument("--surface", action="append", default=[],
                    metavar="NAME=BASE_URL",
                    help="extra surface to plane-attribute (repeatable)")
    ap.add_argument("--cookie-file", help="file containing the id_token value")
    args = ap.parse_args()

    token = os.environ.get("ENCELADUS_ID_TOKEN", "")
    if args.cookie_file:
        with open(args.cookie_file, encoding="utf-8") as fh:
            token = fh.read().strip().split("=", 1)[-1]
    if not token:
        print("no auth: set ENCELADUS_ID_TOKEN or pass --cookie-file",
              file=sys.stderr)
        return 2

    surfaces = []
    for spec in args.surface:
        name, _, base = spec.partition("=")
        if not base:
            print(f"bad --surface spec: {spec}", file=sys.stderr)
            return 2
        surfaces.append((name, base.rstrip("/")))

    divergent = errors = 0
    for record_id in [i.strip() for i in args.ids.split(",") if i.strip()]:
        prod = fetch(args.prod_base, args.project, args.record_type,
                     record_id, token)
        gamma = fetch(args.gamma_base, args.project, args.record_type,
                      record_id, token)
        verdict = classify(prod, gamma)
        if verdict == "DIVERGENT":
            divergent += 1
        if verdict == "ERROR":
            errors += 1
        print(f"{record_id}: {verdict}")
        print(f"  prod : {prod[0]:<10} {prod[1] or ''}")
        print(f"  gamma: {gamma[0]:<10} {gamma[1] or ''}")
        for name, base in surfaces:
            sres = fetch(base, args.project, args.record_type, record_id, token)
            attr = attribute(sres, prod, gamma)
            print(f"  surface {name}: answers-as {attr}")
            if attr in ("NEITHER",):
                errors += 1
            # a surface named gamma answering PROD-only is the ISS-640 signal
            if name.lower().startswith("gamma") and attr == "PROD":
                divergent += 1
                print(f"  !! surface {name} attributed to PROD — mis-route")

    if divergent:
        print(f"\nRESULT: DIVERGENCE/MIS-ROUTE detected ({divergent})"
              " — ENC-ISS-538/640 class; do not trust plane-ambiguous surfaces.")
        return 2
    if errors:
        print("\nRESULT: fetch errors — canary inconclusive")
        return 1
    print("\nRESULT: clean — sentinel identities are plane-consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
