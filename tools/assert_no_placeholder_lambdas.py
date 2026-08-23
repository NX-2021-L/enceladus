#!/usr/bin/env python3
"""Fail if any deployed Lambda is still running CloudFormation's placeholder body.

WHY THIS EXISTS (ENC-ISS-663 / ENC-TSK-P03, strategy in DOC-F3585A1827EF)
-----------------------------------------------------------------------------
`infrastructure/cloudformation/02-compute.yaml` declares 49 Lambda functions
with a placeholder body:

    Code:
      ZipFile: "# managed outside CloudFormation"

Its own header says actual code arrives via each function's `deploy.sh`. So
CloudFormation owns the RESOURCE and deploy.sh owns its CONTENTS -- two
systems owning two halves of one object, with nothing reconciling them.

On 2026-08-23 that split cost three functions. PR #1140 changed only
02-compute.yaml, so `compute_affected_targets.py` produced
affected_functions=[] and the deploy logged "nothing to deploy" and exited
green -- while CloudFormation created devops-governance-mart-gamma,
enceladus-convergence-telemetry-gamma and escalation-decision-authorizer-gamma
carrying the placeholder. Every guard was green. Architectures was arm64,
the runtime was python3.12, the shared layer was attached and coherent, and
the stack read UPDATE_COMPLETE. All three returned Runtime.ImportModuleError
on every invocation.

`compute_affected_targets.py` now widens to full scope when 02-compute.yaml
changes, which PREVENTS the cause. This script DETECTS the state regardless
of cause -- a stuck deploy, a rollback, a manual replacement, or a widening
rule someone edits back out later. Prevention and detection are different
jobs and this platform has been burned by having only one.

THE PREDICATE, AND WHY IT IS NOT PACKAGE SIZE
-----------------------------------------------------------------------------
A function is DEAD if its deployed package does not contain the module its
own `Handler` names. Size is not the test: of 11 gamma functions under 5000
bytes, 8 are perfectly healthy (handler=index, index.py present) -- so a size
threshold produces 8 false positives and would be turned off within a week.
Asking "does the package contain what the Handler points at" produced exactly
3 findings out of 233 account functions, with no false positives.

Requires only lambda:GetFunction -- the presigned Code.Location downloads
with NO S3 bucket permission (AWS-managed storage, the same mechanism that
makes layer inspection work). Deliberately needs no lambda:InvokeFunction, so
it runs in any lane and under any identity that can read function config.

USAGE
-----------------------------------------------------------------------------
    python3 tools/assert_no_placeholder_lambdas.py --suffix -gamma
    python3 tools/assert_no_placeholder_lambdas.py --function-name foo-gamma
    python3 tools/assert_no_placeholder_lambdas.py --self-test

Exit 0 = every checked function carries its handler module.
Exit 1 = at least one is dead (or could not be proven live; see --strict).
"""

from __future__ import annotations

import argparse
import io
import json
import ssl
import sys
import urllib.request
import zipfile
from typing import Callable, Dict, List, Optional, Tuple

PLACEHOLDER_BODY = b"# managed outside CloudFormation"

OK = "ok"
DEAD = "dead"
UNKNOWN = "unknown"


def _download(url: str) -> bytes:
    """Fetch a presigned URL. Falls back to certifi on CERTIFICATE_VERIFY_FAILED:
    some python.org macOS builds ship without a usable system trust store, which
    otherwise looks identical to an access failure."""
    try:
        with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - AWS-signed
            return r.read()
    except urllib.error.URLError as exc:
        if "CERTIFICATE_VERIFY_FAILED" not in str(exc):
            raise
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(url, timeout=60, context=ctx) as r:  # noqa: S310
            return r.read()


def handler_module(handler: str) -> str:
    """'lambda_function.lambda_handler' -> 'lambda_function'. Handles dotted
    package handlers ('pkg.mod.fn' -> 'pkg') by taking the first segment, which
    is what must exist at the package root."""
    return (handler or "").split(".")[0]


def classify_package(handler: str, names: List[str], raw: bytes) -> Tuple[str, str]:
    """Return (state, detail) for one function's deployed package.

    DEAD is reserved for the case we can prove: the Handler names a module the
    package does not contain. That is not a heuristic -- the runtime cannot
    import it, full stop.
    """
    if not handler:
        return UNKNOWN, "function reports no Handler; cannot form a predicate"

    # AWS Lambda Web Adapter (and any custom-runtime bootstrap) names a startup
    # SCRIPT in Handler, not a Python module -- e.g. Handler="run.sh" with
    # AWS_LAMBDA_EXEC_WRAPPER=/opt/bootstrap and the LambdaAdapterLayer
    # attached. Checking the literal handler filename FIRST makes this correct
    # without special-casing environment variables or layer ARNs.
    # Found the hard way: enceladus-mcp-streaming-gateway-gamma is a healthy LWA
    # function whose package correctly ships run.sh, and a module-only predicate
    # called it dead. A guard that cries wolf on a healthy function gets
    # switched off, which is how a real finding gets lost.
    if handler in names:
        return OK, (f"handler entrypoint {handler!r} present as a package file "
                    f"(custom-runtime/adapter style; {len(names)} entries, {len(raw)} bytes)")

    mod = handler_module(handler)
    present = f"{mod}.py" in names or any(n.startswith(mod + "/") for n in names)
    if present:
        return OK, f"handler module {mod!r} present ({len(names)} entries, {len(raw)} bytes)"

    is_placeholder = names == ["index.py"] and PLACEHOLDER_BODY in raw
    if is_placeholder:
        return DEAD, (
            f"CLOUDFORMATION PLACEHOLDER: package is {len(raw)} bytes containing only "
            f"index.py with the body {PLACEHOLDER_BODY.decode()!r}, but Handler names "
            f"module {mod!r}. deploy.sh has never run for this function -- it will "
            f"return Runtime.ImportModuleError on every invocation."
        )
    return DEAD, (
        f"handler module {mod!r} is ABSENT from the deployed package "
        f"(entries: {', '.join(names[:6])}{'...' if len(names) > 6 else ''}) -- "
        f"the runtime cannot import it"
    )


def check_function(lambda_client, name: str,
                   downloader: Callable[[str], bytes] = _download) -> Dict[str, str]:
    try:
        fn = lambda_client.get_function(FunctionName=name)
    except Exception as exc:  # noqa: BLE001
        return {"function": name, "state": UNKNOWN,
                "detail": f"lambda:GetFunction failed: {type(exc).__name__}: {exc}"}

    handler = (fn.get("Configuration") or {}).get("Handler", "")
    url = (fn.get("Code") or {}).get("Location")
    if not url:
        return {"function": name, "state": UNKNOWN,
                "detail": "no presigned Code.Location on the GetFunction response"}
    try:
        raw = downloader(url)
        names = zipfile.ZipFile(io.BytesIO(raw)).namelist()
    except zipfile.BadZipFile as exc:
        return {"function": name, "state": UNKNOWN, "detail": f"package is not a valid zip: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"function": name, "state": UNKNOWN,
                "detail": f"could not download package: {type(exc).__name__}: {exc}"}

    state, detail = classify_package(handler, names, raw)
    return {"function": name, "state": state, "detail": detail, "handler": handler}


def _self_test() -> int:
    ph = io.BytesIO()
    with zipfile.ZipFile(ph, "w") as z:
        z.writestr("index.py", PLACEHOLDER_BODY.decode())
    ph_raw = ph.getvalue()

    cases = [
        ("placeholder is DEAD",
         classify_package("lambda_function.lambda_handler", ["index.py"], ph_raw), DEAD),
        ("real package is OK",
         classify_package("lambda_function.lambda_handler",
                          ["lambda_function.py", "requirements.txt"], b"x"), OK),
        ("legitimately small index-handler function is OK, NOT a false positive",
         classify_package("index.handler", ["index.py"], b"def handler(e,c): pass"), OK),
        ("package-style handler is OK when the package dir exists",
         classify_package("pkg.mod.fn", ["pkg/__init__.py", "pkg/mod.py"], b"x"), OK),
        ("missing handler module is DEAD even without the placeholder body",
         classify_package("lambda_function.lambda_handler", ["other.py"], b"x"), DEAD),
        ("no handler is UNKNOWN, never OK",
         classify_package("", ["lambda_function.py"], b"x"), UNKNOWN),
        ("Lambda Web Adapter script handler is OK -- run.sh is the entrypoint, "
         "not a python module (enceladus-mcp-streaming-gateway-gamma)",
         classify_package("run.sh", ["run.sh", "dispatch_plan_generator.py"], b"x"), OK),
        ("a script handler that is genuinely ABSENT is still DEAD",
         classify_package("run.sh", ["other.py"], b"x"), DEAD),
    ]
    failed = 0
    for label, (state, detail), expected in cases:
        ok = state == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {label}  -> {state}")
        if not ok:
            print(f"        expected {expected}, detail={detail}")
            failed += 1
    # The regression that matters: the placeholder must never read OK.
    assert classify_package("lambda_function.lambda_handler", ["index.py"], ph_raw)[0] != OK
    print(f"\n{len(cases) - failed}/{len(cases)} self-tests passed")
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--function-name", action="append", default=[],
                   help="Explicit function name. Repeatable.")
    p.add_argument("--suffix", default=None,
                   help="Check every account function whose name ends with this (e.g. -gamma).")
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--profile", default=None)
    p.add_argument("--strict", action="store_true",
                   help="Treat UNKNOWN as failure. Off by default so a transient AWS "
                        "error does not red a deploy, but ON is right for a scheduled audit.")
    p.add_argument("--output", default=None, help="Also write the JSON report here.")
    p.add_argument("--self-test", action="store_true", help="Run self-tests (no AWS) and exit.")
    args = p.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not args.function_name and not args.suffix:
        p.error("supply --function-name and/or --suffix (or --self-test)")

    try:
        import boto3  # noqa: PLC0415
    except ImportError:
        print(json.dumps({"error": "boto3 not available"}), file=sys.stderr)
        return 2

    session = boto3.Session(**({"profile_name": args.profile} if args.profile else {}))
    client = session.client("lambda", region_name=args.region)

    targets = list(args.function_name)
    if args.suffix:
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for f in page["Functions"]:
                if f["FunctionName"].endswith(args.suffix):
                    targets.append(f["FunctionName"])
    targets = sorted(set(targets))

    results = [check_function(client, n) for n in targets]
    dead = [r for r in results if r["state"] == DEAD]
    unknown = [r for r in results if r["state"] == UNKNOWN]

    report = {"checked": len(results), "dead": len(dead), "unknown": len(unknown),
              "results": results}
    text = json.dumps(report, indent=2)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    for r in dead:
        print(f"::error title=Placeholder Lambda::{r['function']}: {r['detail']}", file=sys.stderr)
    for r in unknown:
        print(f"::warning title=Unverified Lambda::{r['function']}: {r['detail']}", file=sys.stderr)

    if dead:
        print(f"\nFAIL: {len(dead)} function(s) cannot import their handler module.", file=sys.stderr)
        return 1
    if unknown and args.strict:
        print(f"\nFAIL (--strict): {len(unknown)} function(s) could not be verified.", file=sys.stderr)
        return 1
    print(f"\nOK: {len(results)} function(s) carry their handler module.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
