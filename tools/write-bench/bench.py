#!/usr/bin/env python3
"""Enceladus write-bench harness (ENC-TSK-S26-0C; BRD DOC-E32D0ED08473 7.3 / 7.5).

    python3 tools/write-bench/bench.py --env gamma \
        --arm elr_per_process|long_lived_session|in_region_lambda_client|all \
        --series warm|cold --project <bench-sink-project-id> --out results/<run_id>.json

GAMMA ONLY. Refuses (exit 2) unless --env gamma AND the MCP URL host is exactly
mcp-gamma.jreese.net. Bearer token (Cognito id_token for the gamma MCP) comes from
$BENCH_BEARER_TOKEN or --token-file and is never printed or written to results.
Stdlib only (boto3 is needed solely for the in_region_lambda_client arm).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import stats  # noqa: E402
import wire  # noqa: E402

ARMS = ["elr_per_process", "long_lived_session", "in_region_lambda_client"]
GAMMA_LAMBDA = "devops-write-bench-client-gamma"
DEFAULT_COLD_FUNCTIONS = ("enceladus-mcp-code-gamma", "devops-tracker-mutation-api-gamma", "devops-document-api-gamma")
DEFAULT_URL = f"https://{wire.ALLOWED_HOST}{wire.DEFAULT_PATH}"


def log(msg: str) -> None:
    print(f"[bench] {msg}", file=sys.stderr, flush=True)


def load_token(token_file: Optional[str]) -> str:
    tok = os.environ.get("BENCH_BEARER_TOKEN", "").strip()
    if not tok and token_file:
        with open(os.path.expanduser(token_file)) as fh:
            tok = fh.read().strip()
    if not tok:
        raise SystemExit("error: set BENCH_BEARER_TOKEN or pass --token-file (gamma MCP Cognito id_token)")
    return tok


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", required=True, help="must be 'gamma'")
    ap.add_argument("--arm", default="all", choices=ARMS + ["all"])
    ap.add_argument("--series", default="warm", choices=["warm", "cold"])
    ap.add_argument("--project", required=True, help="bench-sink project id (NOT the enceladus ontology project)")
    ap.add_argument("--out", help="results JSON path (default results/<run_id>.json)")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--mcp-url", default=DEFAULT_URL, help=f"host is hard-allowlisted to {wire.ALLOWED_HOST}; path configurable")
    ap.add_argument("--token-file")
    ap.add_argument("--n", type=int, default=None, help="measured calls per operation per arm (default 300 warm, 40 cold)")
    ap.add_argument("--warmup", type=int, default=10, help="warmup calls per operation per arm (warm series only)")
    ap.add_argument("--pace", type=float, default=5.0, help="seconds slept after each call (default 5; 1 for smoke)")
    ap.add_argument("--pool-size", type=int, default=10)
    ap.add_argument("--ops", default=",".join(wire.OPERATIONS), help="comma list subset of operations")
    ap.add_argument("--aws-profile", default=None, help="AWS profile (cold series bumps; Lambda arm invoke). Cold needs product-lead.")
    ap.add_argument("--aws-region", default="us-west-2")
    ap.add_argument("--cold-functions", default=",".join(DEFAULT_COLD_FUNCTIONS))
    ap.add_argument("--lambda-name", default=GAMMA_LAMBDA)
    ap.add_argument("--dry-run", action="store_true", help="print the plan and one sample payload per op; no network")
    return ap.parse_args(argv)


def guard(args: argparse.Namespace) -> None:
    try:
        wire.assert_gamma_target(args.env, args.mcp_url)
    except wire.RefusedTarget as exc:
        print(f"bench: {exc}", file=sys.stderr)
        sys.exit(2)
    if not args.lambda_name.endswith("-gamma"):
        print("bench: refused: --lambda-name must end with -gamma", file=sys.stderr)
        sys.exit(2)
    bad = [f for f in args.cold_functions.split(",") if f and not f.endswith("-gamma")]
    if bad:
        print(f"bench: refused: cold-bump functions must end with -gamma: {bad}", file=sys.stderr)
        sys.exit(2)


# ---------------------------------------------------------------- setup

def fetch_governance_hash(sess: wire.LongLivedSession) -> str:
    rec = sess.call("search", {"action": "system.connection_health", "arguments": {}}, str(uuid.uuid4()))
    gh = wire.find_key(rec["payload"], "governance_hash")
    if not rec["ok"] or not isinstance(gh, str):
        raise SystemExit(f"error: could not read governance_hash from system.connection_health (http {rec['http_status']})")
    return gh


def pool_path(out: str, project: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(out)), f"pool-{project}.json")


def ensure_pool(sess: wire.LongLivedSession, path: str, project: str, size: int, gh: str) -> List[str]:
    ids: List[str] = []
    if os.path.exists(path):
        with open(path) as fh:
            ids = list(json.load(fh).get("ids", []))
    while len(ids) < size:
        tool, arguments = wire.build_operation("tracker_create", project, ["_"], gh)
        rec = sess.call(tool, arguments, str(uuid.uuid4()))
        rid = wire.find_key(rec["payload"], "record_id")
        if not rec["ok"] or not isinstance(rid, str):
            raise SystemExit(f"error: pool create failed (http {rec['http_status']}): {json.dumps(rec['payload'])[:300]}")
        ids.append(rid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump({"project_id": project, "ids": ids, "updated": datetime.now(timezone.utc).isoformat()}, fh, indent=2)
        log(f"pool record {len(ids)}/{size} created")
    return ids[:size]


# ---------------------------------------------------------------- arms

def call_per_process(url: str, token: str, tool: str, arguments: dict, corr: str) -> dict:
    t_wall, t0 = time.time(), time.perf_counter()
    spec = {"url": url, "token": token, "tool": tool, "arguments": arguments, "correlation_id": corr, "t_client_start": t_wall}
    proc = subprocess.run([sys.executable, "-I", os.path.join(HERE, "wire.py"), "oneshot"],
                          input=json.dumps(spec), capture_output=True, text=True, timeout=180)
    t1 = time.perf_counter()
    try:
        child = json.loads(proc.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        child = {"ok": False, "http_status": 0, "error": f"child_failed rc={proc.returncode}", "payload": None}
    if "fatal" in child:
        print(f"bench: {child['fatal']}", file=sys.stderr)
        sys.exit(2)
    return {
        "t_client_start": t_wall, "t_client_end": t_wall + (t1 - t0), "client_total_ms": (t1 - t0) * 1000.0,
        "client_session_reused": False, "client_session_init_ms": child.get("client_session_init_ms", 0.0),
        "client_tls_new": True, "client_serialize_ms": child.get("client_serialize_ms", 0.0),
        "response_bytes": child.get("response_bytes", 0), "correlation_id": corr,
        "http_status": child.get("http_status", 0), "ok": bool(child.get("ok")), "payload": child.get("payload"),
        "error": child.get("error"),
    }


class LambdaArm:
    def __init__(self, name: str, profile: Optional[str], region: str):
        import boto3  # noqa: PLC0415 -- only this arm needs it
        sess = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        self.client, self.name = sess.client("lambda"), name

    def call(self, url: str, token: str, tool: str, arguments: dict, corr: str) -> dict:
        event = {"mcp_url": url, "token": token, "tool": tool, "arguments": arguments, "correlation_id": corr}
        t0 = time.perf_counter()
        resp = self.client.invoke(FunctionName=self.name, Payload=json.dumps(event).encode())
        out = json.loads(resp["Payload"].read())
        invoke_ms = (time.perf_counter() - t0) * 1000.0
        if "errorMessage" in out:
            return {"ok": False, "http_status": 0, "error": out["errorMessage"][:300], "client_total_ms": None,
                    "correlation_id": corr, "invoke_total_ms": invoke_ms, "payload": None}
        out["correlation_id"], out["invoke_total_ms"] = corr, invoke_ms
        return out


# ---------------------------------------------------------------- cold bump

def _aws(args: List[str], profile: Optional[str], region: str) -> dict:
    cmd = ["aws", "lambda"] + args + ["--region", region, "--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"aws {args[0]} failed: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout or "{}")


def cold_bump(functions: List[str], profile: Optional[str], region: str, timeout_s: int = 180) -> float:
    """Set BENCH_COLD_NONCE=<uuid> on each gamma function (preserving the rest of its env),
    then wait for LastUpdateStatus Successful. Returns seconds spent."""
    t0 = time.time()
    nonce = str(uuid.uuid4())
    for fn in functions:
        cfg = _aws(["get-function-configuration", "--function-name", fn], profile, region)
        env = dict((cfg.get("Environment") or {}).get("Variables") or {})
        env["BENCH_COLD_NONCE"] = nonce
        _aws(["update-function-configuration", "--function-name", fn,
              "--environment", json.dumps({"Variables": env})], profile, region)
    for fn in functions:
        while True:
            cfg = _aws(["get-function-configuration", "--function-name", fn], profile, region)
            if cfg.get("LastUpdateStatus") == "Successful":
                break
            if cfg.get("LastUpdateStatus") == "Failed" or time.time() - t0 > timeout_s:
                raise RuntimeError(f"cold bump did not settle for {fn}: {cfg.get('LastUpdateStatus')}")
            time.sleep(1.0)
    return time.time() - t0


# ---------------------------------------------------------------- main loop

def run(args: argparse.Namespace) -> dict:
    token = load_token(args.token_file)
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or os.path.join("results", f"{run_id}.json")
    ops = [o for o in args.ops.split(",") if o]
    for o in ops:
        if o not in wire.OPERATIONS:
            raise SystemExit(f"error: unknown operation {o!r}")
    arms = ARMS if args.arm == "all" else [args.arm]
    n = args.n if args.n is not None else (40 if args.series == "cold" else 300)
    warmup = args.warmup if args.series == "warm" else 0

    admin = wire.LongLivedSession(args.mcp_url, token)
    gh = fetch_governance_hash(admin)
    pool = ensure_pool(admin, pool_path(out, args.project), args.project, args.pool_size, gh)
    admin.close()

    meta = {"run_id": run_id, "env": "gamma", "mcp_host": wire.ALLOWED_HOST, "series": args.series, "arms": arms,
            "operations": ops, "n": n, "warmup": warmup, "pace_s": args.pace, "project": args.project,
            "pool_size": len(pool), "governance_hash": gh, "started": datetime.now(timezone.utc).isoformat(),
            "cold_functions": args.cold_functions.split(",") if args.series == "cold" else None}
    calls: List[dict] = []
    cold_fns = [f for f in args.cold_functions.split(",") if f]

    def checkpoint() -> None:
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        tmp = out + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"meta": meta, "calls": calls}, fh)
        os.replace(tmp, out)

    for arm in arms:
        long_sess = wire.LongLivedSession(args.mcp_url, token) if arm == "long_lived_session" else None
        lam = LambdaArm(args.lambda_name, args.aws_profile, args.aws_region) if arm == "in_region_lambda_client" else None
        # round-robin ops per round so drift hits all operations equally
        for rnd in range(warmup + n):
            for op in ops:
                rot = (rnd + ops.index(op)) % len(pool)
                tool, arguments = wire.build_operation(op, args.project, pool[rot:] + pool[:rot], gh)
                corr = str(uuid.uuid4())
                bump_s = None
                if args.series == "cold":
                    bump_s = cold_bump(cold_fns, args.aws_profile, args.aws_region)
                if arm == "long_lived_session":
                    rec = long_sess.call(tool, arguments, corr)
                elif arm == "elr_per_process":
                    rec = call_per_process(args.mcp_url, token, tool, arguments, corr)
                else:
                    rec = lam.call(args.mcp_url, token, tool, arguments, corr)
                rec.pop("payload", None)
                rec.update({"operation": op, "arm": arm, "series": args.series, "round": rnd, "warmup": rnd < warmup,
                            "cold_bump_s": bump_s,
                            "headers": {"X-Enc-Surface": wire.SURFACE, "X-Correlation-Id": corr}})
                calls.append(rec)
                if not rec.get("ok"):
                    log(f"call failed arm={arm} op={op} round={rnd} http={rec.get('http_status')} err={str(rec.get('error'))[:120]}")
                time.sleep(max(0.0, args.pace))
            checkpoint()
            log(f"arm={arm} round {rnd + 1}/{warmup + n} done")
        if long_sess:
            long_sess.close()
    meta["finished"] = datetime.now(timezone.utc).isoformat()
    meta["summary"] = stats.summarize_run(calls)
    checkpoint()
    log(f"wrote {out}")
    return {"meta": meta, "calls": calls}


def dry_run(args: argparse.Namespace) -> None:
    gh = "DRY-RUN-HASH"
    pool = [f"BENCH-TSK-{i:03d}" for i in range(1, args.pool_size + 1)]
    for op in args.ops.split(","):
        tool, arguments = wire.build_operation(op, args.project, pool, gh, nonce="dryrun")
        steps = arguments.get("steps", [])
        print(f"{op}: tool={tool} steps={len(steps)} bytes={len(json.dumps(wire.build_tool_call(tool, arguments, 1)))}")


def main(argv=None) -> int:
    args = parse_args(argv)
    guard(args)
    if args.dry_run:
        dry_run(args)
        return 0
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
