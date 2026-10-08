"""LIVE parity + latency check for elr_compact_context (ENC-TSK-Q50 AC-4,
BRD DOC-412AB7081565 M-4, A1, A4).

SKIPPED unless ELR_PARITY_LIVE=1. The coordinator runs it after the
coordination MCP gateway defect (ENC-ISS-835) is fixed and deployed:

    ELR_PARITY_LIVE=1 \\
    ELR_PARITY_GATEWAY=https://<host>/api/v1/coordination/mcp \\
    python3.11 -m pytest tools/elr/tests/test_compact_context_parity_live.py -q

ENC-TSK-Q54: ELR_PARITY_TRANSPORT=route|compose (default compose) runs the whole
set through the context.compact route or through Phase 1 client composition;
the route run asserts every digest reports retrieval.composer == "route".

Optional: ELR_PARITY_ANCHORS_FILE (JSON; default fixtures/parity_anchors.json
with 10 record anchors + 10 topic queries), ELR_PARITY_PROFILE (default prod).

For each anchor the test (1) runs the ELR verb twice (cold, then warm) with an
EXPLICIT query + anchor + top_n + record_type, (2) calls the gateway's
get_compact_context over JSON-RPC (initialize, then tools/call) with the SAME
explicit arguments, authenticated with X-Coordination-Internal-Key resolved
through elr_lib (the key is never printed), and (3) asserts the digest ranking
id sequence equals result.hybrid_retrieval.nodes record ids exactly (M-4).
It also asserts p95 wall <= 4 s warm and <= 12 s cold. Only a compact
pass/fail summary is printed.

This file is the one place that POSTs: the gateway speaks JSON-RPC over POST.
The verb under test never does.
"""

from __future__ import annotations

import json
import math
import os
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import elr_compact_context as cc
from elr_lib import config as elr_config
from elr_lib import tls as elr_tls
from elr_lib import transport as elr_transport
from elr_lib.config import get_profile

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "parity_anchors.json"
_LIVE = os.environ.get("ELR_PARITY_LIVE") == "1"
TOP_N = 20
_TRANSPORT = os.environ.get("ELR_PARITY_TRANSPORT", "compose").strip().lower()
P95_WARM_S = 4.0
P95_COLD_S = 12.0


def p95(values: List[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


class _Gateway:
    """Minimal JSON-RPC client for the coordination MCP gateway."""

    def __init__(self, url: str, key: str, timeout: int = 60):
        self.url = url
        self.key = key
        self.timeout = timeout
        self.session_id = ""
        self._id = 0
        self._ctx = elr_tls.build_ssl_context(elr_tls.resolve_ca_bundle())

    def _post(self, method: str, params: Dict[str, Any], notification: bool = False) -> Tuple[int, Dict[str, Any]]:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            self._id += 1
            payload["id"] = self._id
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            elr_config.INTERNAL_AUTH_HEADER: self.key,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                status, raw, resp_headers = resp.getcode(), resp.read(), dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            status, raw, resp_headers = exc.code, exc.read(), dict(exc.headers.items())
        self.session_id = elr_transport._get_header(resp_headers, "mcp-session-id") or self.session_id
        if notification and not raw:
            return status, {}
        return status, elr_transport.parse_mcp_http_response(resp_headers, raw)

    def initialize(self) -> None:
        status, envelope = self._post(
            "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "elr-parity", "version": "1"}},
        )
        if status != 200 or "error" in envelope:
            raise AssertionError(f"gateway initialize failed: http {status} {str(envelope.get('error'))[:120]}")
        self._post("notifications/initialized", {}, notification=True)

    def compact_context(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        status, envelope = self._post("tools/call", {"name": "get_compact_context", "arguments": arguments})
        if status != 200 or "error" in envelope:
            raise AssertionError(f"gateway tools/call failed: http {status} {str(envelope.get('error'))[:160]}")
        return elr_transport.unwrap_tool_result(envelope)


def _hybrid_ids(payload: Any) -> List[str]:
    """result.hybrid_retrieval.nodes record ids from the get_compact_context envelope."""
    if not isinstance(payload, dict):
        raise AssertionError(f"unexpected gateway payload type {type(payload).__name__}")
    container = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    hybrid = container.get("hybrid_retrieval")
    if not isinstance(hybrid, dict):
        raise AssertionError("gateway result has no hybrid_retrieval: " + ",".join(sorted(container)[:8]))
    return [str(n["record_id"]) for n in hybrid.get("nodes", [])]


@unittest.skipUnless(_LIVE, "set ELR_PARITY_LIVE=1 (and ELR_PARITY_GATEWAY) to run the live parity check")
class CompactContextLiveParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        gateway_url = os.environ.get("ELR_PARITY_GATEWAY", "").strip()
        if not gateway_url.startswith("https://") or not gateway_url.rstrip("/").endswith("/api/v1/coordination/mcp"):
            raise unittest.SkipTest("ELR_PARITY_GATEWAY must be https://<host>/api/v1/coordination/mcp")
        key, _source = elr_config.resolve_common_internal_key()
        if not key:
            raise unittest.SkipTest("no ELR credential resolvable")
        anchors_path = Path(os.environ.get("ELR_PARITY_ANCHORS_FILE", "") or _FIXTURE)
        cls.anchors = json.loads(anchors_path.read_text(encoding="utf-8"))
        cls.profile = os.environ.get("ELR_PARITY_PROFILE", "prod")
        config = get_profile("internal", environment_profile_name=cls.profile)
        cls.client = elr_transport.InternalClient(config, timeout=60)
        cls.gateway = _Gateway(gateway_url, key)
        cls.gateway.initialize()

    # -- helpers -------------------------------------------------------------

    def _run_elr(self, argv: List[str]) -> Tuple[Dict[str, Any], float]:
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as tmp:
            args = cc.build_parser().parse_args(argv + ["--out-dir", tmp, "--top-n", str(TOP_N), "--transport", _TRANSPORT])
            started = time.monotonic()
            digest, code = cc.run_compact_context(args, self.client, profile=self.profile, key_source="parity")
            elapsed = time.monotonic() - started
        self.assertEqual(code, 0, f"elr exit {code}: {digest.get('anomalies')}")
        expected = "route" if _TRANSPORT == "route" else "elr-1" if _TRANSPORT == "compose" else None
        if expected:
            self.assertEqual(digest["retrieval"]["composer"], expected, f"transport {_TRANSPORT} fell back: {digest.get('warnings')}")
        return digest, elapsed

    def _record_query(self, record_id: str) -> Tuple[str, str]:
        classified = cc.elr_batch_get.classify_id(record_id)
        status, body = self.client.request("GET", "tracker", cc.elr_batch_get.tracker_path(classified.record_type, record_id))
        self.assertEqual(status, 200, f"record read {record_id}")
        record = body.get("record", body)
        return cc.derive_query(record), str(record.get("project_id") or self.anchors["project_id"])

    # -- the check -----------------------------------------------------------

    def test_ranking_parity_and_latency_over_20_anchors(self):
        project = self.anchors["project_id"]
        cases: List[Tuple[str, List[str], Dict[str, Any]]] = []
        for record_id in self.anchors["record_anchors"][:10]:
            query, proj = self._record_query(record_id)
            cases.append(
                (
                    f"record:{record_id}",
                    ["--mode", "record", "--record-id", record_id, "--query", query, "--anchor-record-id", record_id, "--record-type", "task"],
                    {
                        "mode": "record", "record_id": record_id, "project_id": proj, "query": query,
                        "anchor_record_id": record_id, "record_type": "task", "top_n": TOP_N,
                        "include_components": False, "include_code_map": False,
                        "include_related_documents": False, "include_governance": False,
                        "include_architecture": False, "include_recent_history": False,
                    },
                )
            )
        for query in self.anchors["topic_queries"][:10]:
            cases.append(
                (
                    f"topic:{query[:24]}",
                    ["--mode", "topic", "--query", query, "--project-id", project, "--record-type", "task"],
                    {
                        "mode": "topic", "query": query, "project_id": project, "record_type": "task",
                        "top_n": TOP_N, "include_code_map": False, "include_governance": False,
                    },
                )
            )
        self.assertEqual(len(cases), 20)

        mismatches: List[str] = []
        cold: List[float] = []
        warm: List[float] = []
        for label, elr_argv, gateway_args in cases:
            digest_cold, t_cold = self._run_elr(elr_argv)
            digest_warm, t_warm = self._run_elr(elr_argv)
            cold.append(t_cold)
            warm.append(t_warm)
            mcp_ids = _hybrid_ids(self.gateway.compact_context(gateway_args))
            elr_ids = [row[0] for row in digest_warm["ranking"]]
            if elr_ids != mcp_ids[: len(elr_ids)] or len(elr_ids) != min(len(mcp_ids), TOP_N):
                mismatches.append(label)

        summary = (
            f"[{_TRANSPORT}] parity {20 - len(mismatches)}/20 exact | "
            f"p95 cold {p95(cold):.2f}s (<= {P95_COLD_S}) | p95 warm {p95(warm):.2f}s (<= {P95_WARM_S})"
        )
        print("\n[elr-parity] " + summary + (f" | MISMATCH: {', '.join(mismatches)}" if mismatches else ""))
        self.assertEqual(mismatches, [], "ranking id sequence differs from MCP hybrid_retrieval.nodes")
        self.assertLessEqual(p95(warm), P95_WARM_S, summary)
        self.assertLessEqual(p95(cold), P95_COLD_S, summary)


if __name__ == "__main__":
    unittest.main()
