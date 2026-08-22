"""ELR plane-safety module (DOC-F2CF625B7556 A.7, ENC-TSK-O54).

Five-step guard wrapped around a governed docstore write, so a write
intended for one plane (e.g. prod) cannot silently land on -- or be
mistakenly read back from -- the wrong twin environment, and so the
write's effect on the target plane is *corroborated* rather than merely
assumed from a 200 status code.

Steps (every step's outcome lands in the caller's digest under the
"plane_safety" key via build_report()):

  1. PRE-STATE probe on the target plane -- sentinel presence/version
     plus a cheap count-ish probe -- AND on plane B via an
     env-configured probe (ELR_PLANE_B_DOC_API_BASE / ELR_PLANE_B_PROBE).
     When plane B is not configured this records step "unavailable"
     with anomaly "plane-b-probe-unconfigured" and the run continues
     degraded (honest, not blocked).
  2. SENTINEL IDENTITY check through the EXACT surface about to be
     written: fetch DOC-87EC08ECF51A metadata and verify document_id
     echoes back exactly. A surface silently reading the wrong twin
     environment returns a wrong or missing sentinel -- this is the ONE
     hard gate in this module (see run_pre_write()'s "abort" field);
     the caller must not proceed to the write when this step fails.
     Steps 1 and 2 share the SAME sentinel GET (one network call serves
     both report facets -- step 1's presence/version facet and step 2's
     identity-echo facet) rather than issuing two identical requests.
  3. THE WRITE ITSELF -- performed by the CALLER (documents.put), not
     this module; its outcome is folded into the report via
     build_report()'s write_ok argument.
  4. POST-PROBE both planes: target moved (the newly minted document is
     present through the same surface), plane B unchanged where it was
     probed (best-effort; only when configured).
  5. MONOTONIC-ID corroboration: the minted document_id was not present
     in step 1's pre-state target-plane listing sample.

Reuses elr_lib.transport.InternalClient / elr_lib.config for the target
plane (the same "internal" profile the rest of ELR uses). Plane B is a
genuinely different base URL/environment, so it is addressed with a
bare urllib call using the same X-Coordination-Internal-Key convention
(mirroring server.py) -- an optional dedicated ELR_PLANE_B_API_KEY env
var, falling back to nothing (unauthenticated) when unset, since the
two planes are not guaranteed to share a key.

Python 3.11 standard library only. Nothing here imports server.py.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from . import config as elr_config
from . import transport as elr_transport

SENTINEL_DOCUMENT_ID = "DOC-87EC08ECF51A"

PLANE_B_BASE_ENV = "ELR_PLANE_B_DOC_API_BASE"
PLANE_B_PROBE_ENV = "ELR_PLANE_B_PROBE"
PLANE_B_API_KEY_ENV = "ELR_PLANE_B_API_KEY"

_COUNT_PROBE_PROJECT_QUERY_KEY = "project"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _extract_document(body: Any) -> Dict[str, Any]:
    """Mirrors elr_doc_get.py's _extract_document_payload: the nested
    "document" object and the top-level spread carry the same fields
    (backend/lambda/document_api/lambda_function.py:_get_single /
    _handle_patch both return document fields at the top level; only
    GET nests them under "document" as well). Duplicated locally (not
    imported) so this module has no cross-CLI coupling -- every ELR
    elr_*.py file only imports from elr_lib.
    """
    if not isinstance(body, dict):
        return {}
    nested = body.get("document")
    if isinstance(nested, dict):
        return nested
    return body


# ---------------------------------------------------------------------------
# Target-plane probes (via the caller's InternalClient -- the EXACT
# surface about to be written)
# ---------------------------------------------------------------------------


def _sentinel_probe(client: "elr_transport.InternalClient") -> Dict[str, Any]:
    """GET DOC-87EC08ECF51A metadata (include_content=false) through the
    exact InternalClient/document-API surface about to be written.
    """
    encoded = urllib.parse.quote(SENTINEL_DOCUMENT_ID, safe="")
    status, body = client.request("GET", "document", f"/{encoded}", query={"include_content": "false"})
    doc = _extract_document(body)
    echoed_id = doc.get("document_id")
    identity_ok = status == 200 and echoed_id == SENTINEL_DOCUMENT_ID
    return {
        "status": status,
        "ok": identity_ok,
        "document_id_echoed": echoed_id,
        "version": doc.get("version"),
    }


def _target_count_probe(client: "elr_transport.InternalClient", project_id: str) -> Dict[str, Any]:
    """A documents LIST first page for project_id, used ONLY as a
    coarse "did something change plane-side" signal (page count + a
    sample of document_ids feeding step 5's monotonic-id corroboration)
    -- never as an authoritative existence/completeness answer.

    HARD-RULE EXEMPTION: elr_batch_get.py enforces a hard rule of never
    constructing a list/scan/query route, because a caller could
    mistake a paginated LIST for a complete existence answer about
    SPECIFIC IDs (the ENC-ISS-558 undercount class). That hazard does
    not apply here: this probe never asserts that any particular ID
    does or does not exist -- it only reports what the first page
    currently contains as a LOWER-BOUND count/sample used for plane
    drift and monotonic-id checks. plane_safety is therefore explicitly
    exempt from elr_batch_get's HARD RULE for this one probe; this
    comment is the citation a future reader needs before "fixing" this
    call into elr_batch_get's per-ID shape.
    """
    status, body = client.request(
        "GET", "document", "", query={_COUNT_PROBE_PROJECT_QUERY_KEY: project_id}
    )
    ok = status == 200 and isinstance(body, dict) and not body.get("error")
    docs = body.get("documents") if isinstance(body, dict) else None
    sample_ids: List[str] = []
    if isinstance(docs, list):
        sample_ids = [d.get("document_id") for d in docs if isinstance(d, dict) and d.get("document_id")]
    return {
        "status": status,
        "ok": ok,
        "count": body.get("count") if isinstance(body, dict) else None,
        "total_matches": body.get("total_matches") if isinstance(body, dict) else None,
        "sample_ids": sample_ids,
    }


def _document_presence_probe(client: "elr_transport.InternalClient", document_id: str) -> Dict[str, Any]:
    """GET one specific document's metadata (include_content=false) --
    used post-write to confirm the target plane moved (step 4), and
    doubles as a cheap version/content_hash/compliance_score source for
    the caller when no patch step follows the create.
    """
    encoded = urllib.parse.quote(document_id, safe="")
    status, body = client.request("GET", "document", f"/{encoded}", query={"include_content": "false"})
    doc = _extract_document(body)
    present = status == 200 and doc.get("document_id") == document_id
    return {
        "status": status,
        "ok": present,
        "document_id_echoed": doc.get("document_id"),
        "version": doc.get("version"),
        "content_hash": doc.get("content_hash"),
        "size_bytes": doc.get("size_bytes"),
        "compliance_score": doc.get("compliance_score") if "compliance_score" in doc else None,
    }


# ---------------------------------------------------------------------------
# Plane B probe (env-configured, optional, degraded-but-honest)
# ---------------------------------------------------------------------------


def _plane_b_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _plane_b_get(base: str, document_id: str, key: str, timeout: int) -> Dict[str, Any]:
    encoded = urllib.parse.quote(document_id, safe="")
    query = urllib.parse.urlencode({"include_content": "false"})
    url = f"{base.rstrip('/')}/{encoded}?{query}"
    headers = {"Accept": "application/json", "User-Agent": "enceladus-elr-plane-safety/1.0"}
    if key:
        headers[elr_config.INTERNAL_AUTH_HEADER] = key

    req = urllib.request.Request(url=url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_plane_b_ssl_context()) as resp:
            status = resp.getcode()
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw or str(exc)}
    except urllib.error.URLError as exc:
        return {"status": 0, "ok": False, "error": f"unreachable: {exc}"}
    except Exception as exc:  # noqa: BLE001 -- surface, never swallow
        return {"status": 0, "ok": False, "error": f"request_failed: {exc}"}

    doc = _extract_document(parsed)
    return {
        "status": status,
        "ok": 200 <= status < 300 and doc.get("document_id") == document_id,
        "document_id_echoed": doc.get("document_id"),
        "version": doc.get("version"),
    }


def plane_b_probe(*, timeout: int = 20) -> Dict[str, Any]:
    """Probe the non-target plane via ELR_PLANE_B_DOC_API_BASE /
    ELR_PLANE_B_PROBE (a document_id to fetch there). When either is
    unset, this is recorded as "unavailable" with an anomaly, never as
    a failure -- plane B corroboration is best-effort by design.
    """
    base = os.environ.get(PLANE_B_BASE_ENV, "").strip()
    probe_id = os.environ.get(PLANE_B_PROBE_ENV, "").strip()
    if not base or not probe_id:
        return {"status": "unavailable", "ok": None, "anomaly": "plane-b-probe-unconfigured"}

    key = os.environ.get(PLANE_B_API_KEY_ENV, "").strip()
    return _plane_b_get(base, probe_id, key, timeout)


# ---------------------------------------------------------------------------
# Orchestration: pre-write (steps 1+2), post-write (steps 4+5), report
# ---------------------------------------------------------------------------


def run_pre_write(
    client: "elr_transport.InternalClient", project_id: str, *, timeout: int = 20
) -> Dict[str, Any]:
    """Steps 1 + 2. Returns a dict the caller threads through to
    run_post_write() and build_report() unchanged:

      step1_pre_state: {sentinel, count_probe, plane_b}
      step2_sentinel_identity: same dict as step1's sentinel facet
      abort: True iff the sentinel identity check failed -- the ONE
             hard gate; the caller MUST NOT proceed to the write.
      abort_reason: "plane-safety-sentinel-mismatch" or None
    """
    sentinel = _sentinel_probe(client)
    count_probe = _target_count_probe(client, project_id)
    plane_b_pre = plane_b_probe(timeout=timeout)

    abort = not sentinel["ok"]
    return {
        "step1_pre_state": {"sentinel": sentinel, "count_probe": count_probe, "plane_b": plane_b_pre},
        "step2_sentinel_identity": sentinel,
        "abort": abort,
        "abort_reason": "plane-safety-sentinel-mismatch" if abort else None,
    }


def run_post_write(
    client: "elr_transport.InternalClient",
    project_id: str,
    minted_document_id: str,
    pre_state: Dict[str, Any],
    *,
    timeout: int = 20,
) -> Dict[str, Any]:
    """Steps 4 + 5, run after the caller's write has landed."""
    target = _document_presence_probe(client, minted_document_id)

    pre_plane_b = pre_state["step1_pre_state"]["plane_b"]
    if pre_plane_b.get("status") == "unavailable":
        plane_b_post: Dict[str, Any] = {"status": "unavailable", "ok": None, "anomaly": "plane-b-probe-unconfigured"}
        plane_b_unchanged: Optional[bool] = None
    else:
        plane_b_post = plane_b_probe(timeout=timeout)
        if plane_b_post.get("status") == "unavailable":
            plane_b_unchanged = None
        else:
            plane_b_unchanged = bool(
                plane_b_post.get("ok")
                and pre_plane_b.get("ok")
                and plane_b_post.get("document_id_echoed") == pre_plane_b.get("document_id_echoed")
                and plane_b_post.get("version") == pre_plane_b.get("version")
            )

    step4 = {"target": target, "plane_b": plane_b_post, "plane_b_unchanged": plane_b_unchanged}

    pre_sample_ids = pre_state["step1_pre_state"]["count_probe"].get("sample_ids") or []
    previously_unseen = minted_document_id not in pre_sample_ids
    step5 = {
        "minted_document_id": minted_document_id,
        "previously_unseen": previously_unseen,
        "ok": previously_unseen,
    }

    return {"step4_post_probe": step4, "step5_monotonic_id": step5}


def build_report(
    pre_state: Dict[str, Any],
    post_state: Optional[Dict[str, Any]],
    *,
    write_ok: Optional[bool],
) -> Dict[str, Any]:
    """Assemble the final plane_safety report every caller digest
    carries. post_state is None when the write never happened (a
    pre-write abort or an outright PUT failure) -- steps 4/5 are then
    recorded as skipped, never fabricated.

    Overall "ok" is gated by step 2 (the hard sentinel-identity gate)
    and, when post_state is present, by steps 4/5. A degraded plane B
    (unconfigured) or a soft count-probe hiccup are reported as
    anomalies but never flip "ok" -- see the module docstring.
    """
    step1 = pre_state["step1_pre_state"]
    step2 = pre_state["step2_sentinel_identity"]

    anomalies: List[str] = []
    if step1["plane_b"].get("status") == "unavailable":
        anomalies.append(step1["plane_b"].get("anomaly", "plane-b-probe-unconfigured"))
    if not step1["count_probe"].get("ok"):
        anomalies.append("plane-safety-count-probe-failed")
    if not step2.get("ok"):
        anomalies.append("plane-safety-sentinel-mismatch")

    steps: Dict[str, Any] = {
        "1_pre_state": step1,
        "2_sentinel_identity": step2,
        "3_write": {"ok": write_ok},
    }

    ok = bool(step2.get("ok"))

    if post_state is not None:
        step4 = post_state["step4_post_probe"]
        step5 = post_state["step5_monotonic_id"]
        steps["4_post_probe"] = step4
        steps["5_monotonic_id"] = step5

        if not step4["target"]["ok"]:
            ok = False
            anomalies.append("plane-safety-target-post-probe-failed")
        if step4["plane_b_unchanged"] is False:
            ok = False
            anomalies.append("plane-safety-plane-b-drift-detected")
        if not step5["ok"]:
            ok = False
            anomalies.append("plane-safety-monotonic-id-check-failed")
    else:
        steps["4_post_probe"] = {"ok": None, "note": "skipped -- write did not complete or was not reached"}
        steps["5_monotonic_id"] = {"ok": None, "note": "skipped -- write did not complete or was not reached"}

    return {"ok": ok, "steps": steps, "anomalies": anomalies}
