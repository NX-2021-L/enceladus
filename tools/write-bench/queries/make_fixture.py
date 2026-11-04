#!/usr/bin/env python3
"""Generate fixtures/synthetic_audit_lines.jsonl from the BRD 7.2 audit schema.

Deterministic (seeded). Plants exactly one violation of each governance counter-metric
plus decoys that a correct implementation must NOT count. Run:
    python3 make_fixture.py [--out fixtures/synthetic_audit_lines.jsonl]
"""
import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

T0 = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
TOOLS = {  # tool -> (log group, base ms, ddb_ops, writes S3)
    "tracker.create": ("/aws/lambda/enceladus-mcp-code", 180, 4, False),
    "tracker.set": ("/aws/lambda/enceladus-mcp-code", 140, 3, False),
    "documents.put": ("/aws/lambda/enceladus-mcp-code", 260, 5, True),
    "checkout.advance": ("/aws/lambda/enceladus-mcp-code", 210, 4, False),
}
SURFACES = ["mcp", "elr", "pwa", "bench"]
CONSUMER_GROUP = "/aws/lambda/devops-graph-sync"
GOV_HASH = "a" * 16


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def make(seed=26):
    rnd = random.Random(seed)
    rows = []  # (ts, log_group, message)
    sessions = [f"ENC-SES-F{i:02d}" for i in range(12)]
    n_writes = 85
    for i in range(n_writes):
        ts = T0 + timedelta(minutes=30 * i + rnd.randint(0, 20))
        tool = rnd.choice(list(TOOLS))
        group, base, ops, s3 = TOOLS[tool]
        surface = rnd.choice(SURFACES)
        sess = sessions[i % len(sessions)]
        # sessions F00-F02 are cold-heavy, the rest mostly warm
        cold = rnd.random() < (0.7 if sess in sessions[:3] else 0.05)
        init_ms = round(rnd.uniform(380, 900), 1) if cold else 0
        stages = {
            "t_edge_ms": round(rnd.uniform(8, 25), 1),
            "t_auth_ms": round(rnd.uniform(3, 12), 1),
            "t_route_ms": round(rnd.uniform(2, 8), 1),
            "t_invoke_ms": round(rnd.uniform(15, 35), 1),
            "t_governance_ms": round(rnd.uniform(0, 5), 1),
            "t_validate_ms": round(rnd.uniform(1, 20), 1),
            "t_idempotency_ms": round(rnd.uniform(15, 30), 1),
            "t_counter_ms": round(rnd.uniform(5, 16), 1),
            "t_ddb_ms": round(rnd.uniform(20, 90), 1),
            "t_s3_ms": round(rnd.uniform(30, 150), 1) if s3 else 0,
            "t_compliance_ms": round(rnd.uniform(0, 4), 1),
        }
        total = round(base + sum(stages.values()) * 0.3 + rnd.uniform(0, 40) + init_ms, 1)
        corr = f"cor-{i:04d}"
        line = {
            "correlation_id": corr, "request_id": f"req-{i:04d}-{rnd.getrandbits(24):06x}",
            "session_id": sess, "tool": tool, "project_id": "enceladus",
            "record_id": f"ENC-TSK-F{i:03d}", "idempotency_key": f"idem-{i:04d}",
            "execute_step_index": 0, "surface": surface,
            "server_total_ms": total, "cold_start": cold, "hops": 2,
            **stages,
            "governance_cache_hit": not cold, "governance_hash_in": GOV_HASH,
            "governance_hash_verified": True, "idempotency_hit": False,
            "ddb_ops": ops, "ddb_retries": 0, "memory_mb": 1024, "runtime": "python3-managed",
            "arch": "arm64", "function_version": "42", "success": True,
            "receipt_hash": hashlib.sha256(f"idem-{i:04d}".encode()).hexdigest()[:16],
        }
        if surface in ("elr", "bench"):
            line.update(client_total_ms=round(total + rnd.uniform(20, 120), 1), client_session_reused=not cold,
                        client_tls_new=cold, client_serialize_ms=round(rnd.uniform(0.2, 3), 2),
                        response_bytes=rnd.randint(300, 4000))
        # cold start: init_ms in the audit line for half of them; the rest rely on the REPORT join
        if cold:
            if rnd.random() < 0.5:
                line["init_ms"] = init_ms
            else:
                rows.append((ts + timedelta(milliseconds=total), group,
                             f"REPORT RequestId: {line['request_id']}\tDuration: {total} ms\tBilled Duration: {int(total) + 1} ms\t"
                             f"Memory Size: 1024 MB\tMax Memory Used: 210 MB\tInit Duration: {init_ms} ms"))
        # warm lambda REPORT lines (no Init Duration) must be ignored by the join
        elif rnd.random() < 0.3:
            rows.append((ts + timedelta(milliseconds=total), group,
                         f"REPORT RequestId: {line['request_id']}\tDuration: {total} ms\tBilled Duration: {int(total) + 1} ms\tMemory Size: 1024 MB"))
        rows.append((ts, group, line))
        has_consumer = True
        # ---- planted violations / decoys keyed by write index ----
        if i == 20:   # CM1 planted: stale hash accepted (success true)
            line["governance_hash_verified"] = False
            line["surface"] = "mcp_server"
        if i == 21:   # CM1 decoy: stale hash but rejected
            line["governance_hash_verified"] = False
            line["success"] = False
            line["surface"] = "mcp_server"
            has_consumer = False
        if i == 30:   # CM2 planted: write that never reaches a stream consumer
            has_consumer = False
        if i == 31:   # CM2 decoy: idempotent replay hit, no new stream event expected
            line["idempotency_hit"] = True
            has_consumer = False
        if i == 40:   # CM3 planted: same idempotency_key, differing receipt hash
            twin = dict(line, correlation_id="cor-0040b", request_id="req-0040b", receipt_hash="deadbeefdeadbeef",
                        idempotency_hit=True, session_id=sess)
            rows.append((ts + timedelta(seconds=5), group, twin))
        if i == 41:   # CM3 decoy: replay with the same receipt hash
            twin = dict(line, correlation_id="cor-0041b", request_id="req-0041b", idempotency_hit=True)
            rows.append((ts + timedelta(seconds=5), group, twin))
        if i == 50:   # CM4 planted: dry_run that touched DynamoDB
            line["dry_run"] = True
        if i == 51:   # CM4 decoy: dry_run with zero ddb ops
            line.update(dry_run=True, ddb_ops=0)
            has_consumer = False
        if has_consumer:
            cts = ts + timedelta(milliseconds=210 + rnd.randint(0, 300))
            lag = round((cts - ts).total_seconds() * 1000, 1)
            cons = {"correlation_id": corr, "request_id": f"con-{i:04d}", "consumer": "graph-sync",
                    "t_stream_received": iso(cts), "t_projection_done": iso(cts + timedelta(milliseconds=40)),
                    "attempt": 1, "version_seq": i + 1, "t_ack": iso(cts + timedelta(milliseconds=45)),
                    "t_governed": iso(cts + timedelta(milliseconds=45)), "governed_lag_ms": lag + 45}
            if i == 60:  # CM5 decoy: attempt 3 failed, attempt 4 recovered
                rows.append((cts, CONSUMER_GROUP, {k: cons[k] for k in ("correlation_id", "consumer", "attempt")} | {"attempt": 3}))
                cons["attempt"] = 4
            if i == 61:  # CM5 planted: attempt 3 fails and never recovers
                cons = {"correlation_id": corr, "request_id": f"con-{i:04d}", "consumer": "graph-sync",
                        "t_stream_received": iso(cts), "attempt": 3, "version_seq": i + 1}
            if i == 70:  # CM6 planted (ENC-TSK-S46-0D): two edges skipped for a missing target
                cons.update(edges_skipped_missing_target=2, edges_placeholder_targets=1)
            if i == 71:  # CM6 decoy: placeholders materialized, nothing skipped
                cons.update(edges_skipped_missing_target=0, edges_placeholder_targets=3)
            rows.append((cts, CONSUMER_GROUP, cons))
    # a final group of recent writes inside the grace window (no consumer line yet; must not count for CM2)
    last = max(r[0] for r in rows)
    for j in range(3):
        rows.append((last + timedelta(minutes=1 + j), "/aws/lambda/enceladus-mcp-code",
                     {"correlation_id": f"cor-late-{j}", "request_id": f"req-late-{j}", "session_id": sessions[0],
                      "tool": "tracker.set", "surface": "mcp", "server_total_ms": 150.0, "cold_start": False,
                      "t_ddb_ms": 40.0, "ddb_ops": 3, "governance_hash_verified": True, "success": True,
                      "idempotency_hit": False}))
    # ENC-ISS-896: tool-Lambda pass-through. The tracker_mutation line never sees the governance hash
    # (null, verified false) while its mcp_server twin validated it. Must NOT count as CM1.
    pt_ts = last + timedelta(seconds=30)
    common = {"session_id": sessions[0], "tool": "tracker.set", "server_total_ms": 120.0, "cold_start": False,
              "t_ddb_ms": 0.0, "ddb_ops": 0, "idempotency_hit": False, "success": True}  # ddb_ops 0: not a CM2 orphan
    rows.append((pt_ts, "/aws/lambda/enceladus-mcp-code",
                 dict(common, correlation_id="cor-pt-0", request_id="req-pt-0a", surface="mcp_server",
                      governance_hash_verified=True, governance_hash_in=GOV_HASH)))
    rows.append((pt_ts + timedelta(milliseconds=40), "/aws/lambda/devops-tracker-mutation-api",
                 dict(common, correlation_id="cor-pt-0", request_id="req-pt-0b", surface="tracker_mutation",
                      governance_hash=None, governance_hash_verified=False)))
    # one sentinel consumer line at the very end so window_end is well past the late writes
    rows.sort(key=lambda r: r[0])
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).parent / "fixtures" / "synthetic_audit_lines.jsonl"))
    args = ap.parse_args()
    rows = make()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as fh:
        for ts, group, body in rows:
            msg = body if isinstance(body, str) else "[WRITE-AUDIT] " + json.dumps(body, separators=(",", ":"))
            fh.write(json.dumps({"ts": iso(ts), "log_group": group, "message": msg}) + "\n")
    print(f"wrote {len(rows)} lines to {args.out}")


if __name__ == "__main__":
    main()
