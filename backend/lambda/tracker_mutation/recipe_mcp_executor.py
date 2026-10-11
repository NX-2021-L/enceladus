"""DVP-TSK-968 part C (DVP-PLN-013 E4-W2.2, architect ruling E4-R16): the EnceladusMcpExecutor.

Enceladus steps of a recipe run (tracker.*, checkout.*, documents.*, plan.*, lesson capture ...) run through the
governed MCP execute surface exactly as an agent would, with zero LLM calls: ONE tools/call execute per segment.

Transport (verified against tools/enceladus-mcp-server/server.py _handle_lambda_event and _get_http_session_manager):
  * HTTPS POST of one JSON-RPC 2.0 message to the streamable-HTTP endpoint (path /mcp) with the header
    Authorization: Bearer <ENCELADUS_MCP_API_KEY> (compared verbatim with the server's static key);
  * the Function URL transport is stateless (stateless=True, json_response=True): no initialize round-trip and no
    Mcp-Session-Id are needed, every request is self-contained and answers plain JSON.
Per segment the run service asks this executor for the governance_hash (search system.connection_health, compared
with the run's pinned hash server-side) and then makes one execute call whose steps carry governance_hash inside each
step's arguments, plus the runner session (active_agent_session_id, sci, provider) for mutating steps.
Each run owns one agent session (coordination agent.register + agent.claim), kept alive by escalation.watch while a
gate is open and retired at a terminal state.  recipe.* steps and external surfaces stay in-process (call_local).
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

import recipe_run_service as rrs

DEFAULT_URL = "https://mcp.jreese.net/mcp"
PROVIDER = "recipe_runner"
RUNTIME = "recipe_runner"
READ_VERBS = frozenset({"get", "list", "search", "read", "query", "context", "related", "describe", "health",
                        "find", "lookup", "status", "watch", "connection_health"})
KEY_FIELDS = ("ENCELADUS_MCP_API_KEY", "api_key", "apiKey", "token", "key", "value")
_KEY_CACHE: Dict[str, str] = {}                                   # per container


class McpError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def is_read_action(action: str) -> bool:
    return str(action or "").rsplit(".", 1)[-1] in READ_VERBS


def load_api_key(secret_arn: str, client: Any = None) -> str:
    """The SAME secret the MCP lambda's ENCELADUS_MCP_API_KEY comes from; cached per container, never logged."""
    if secret_arn in _KEY_CACHE:
        return _KEY_CACHE[secret_arn]
    if client is None:
        import boto3
        client = boto3.client("secretsmanager")
    raw = str(client.get_secret_value(SecretId=secret_arn).get("SecretString") or "").strip()
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except ValueError:
            obj = {}
        raw = next((obj[k].strip() for k in KEY_FIELDS if isinstance(obj.get(k), str) and obj[k].strip()), "")
    if raw:
        _KEY_CACHE[secret_arn] = raw
    return raw


def default_transport(url: str, headers: Dict[str, str], body: bytes, timeout: int = 60):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _decode(raw: bytes) -> Dict[str, Any]:
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("event:") or text.startswith("data:"):          # defensive: SSE framing
        datas = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
        text = datas[-1] if datas else ""
    return json.loads(text) if text else {}


def _payload(result: Dict[str, Any]) -> Dict[str, Any]:
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text":
            try:
                parsed = json.loads(item.get("text") or "")
            except ValueError:
                return {"success": not result.get("isError"), "text": str(item.get("text") or "")[:500]}
            return parsed if isinstance(parsed, dict) else {"success": True, "result": parsed}
    sc = result.get("structuredContent")
    return sc if isinstance(sc, dict) else {}


def _find_key(obj: Any, key: str) -> Optional[str]:
    if isinstance(obj, dict):
        if isinstance(obj.get(key), str) and obj[key].strip():
            return obj[key].strip()
        for v in obj.values():
            hit = _find_key(v, key)
            if hit:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = _find_key(v, key)
            if hit:
                return hit
    return None


def _error_of(payload: Any) -> Optional[Dict[str, str]]:
    if not isinstance(payload, dict):
        return None
    err = payload.get("error")
    if payload.get("success") is False or (isinstance(err, dict) and err):
        if isinstance(err, dict):
            return {"code": str(err.get("code") or "MCP_TOOL_ERROR"), "message": str(err.get("message") or "tool call failed")[:300]}
        return {"code": "MCP_TOOL_ERROR", "message": str(err or payload.get("message") or "tool call failed")[:300]}
    return None


def _receipt(result: Any) -> Dict[str, Any]:
    r = rrs.receipt_of(result)
    if not r and isinstance(result, dict):
        for k in ("result", "record", "data"):
            r = rrs.receipt_of(result.get(k))
            if r:
                break
    return r


def _map_step(sr: Dict[str, Any]) -> Dict[str, Any]:
    status = str(sr.get("status") or "")
    res = sr.get("result")
    if status in ("success", "dry_run"):
        return {"ok": True, "result": res, "receipt": _receipt(res)}
    inner = _error_of(res) if isinstance(res, dict) else None
    code = str((inner or {}).get("code") or sr.get("error_code") or status or "STEP_ERROR")
    msg = str(sr.get("error") or "step failed") + ((": " + inner["message"]) if inner else "")
    return {"ok": False, "error": {"code": code, "message": msg[:300]}}


class EnceladusMcpExecutor:
    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None, key_loader: Optional[Callable[[], str]] = None,
                 transport: Optional[Callable[..., Any]] = None, agent_type_id: Optional[str] = None, timeout: int = 60):
        self.url = url or DEFAULT_URL
        self._api_key, self._key_loader = api_key, key_loader
        self.transport = transport or default_transport
        self.agent_type_id = agent_type_id
        self.timeout = timeout
        self._id = 0

    @classmethod
    def from_env(cls) -> "EnceladusMcpExecutor":
        arn = os.environ.get("RECIPE_MCP_API_KEY_SECRET_ARN", "").strip()
        return cls(url=os.environ.get("RECIPE_MCP_URL", "").strip() or DEFAULT_URL, key_loader=lambda: load_api_key(arn),
                   agent_type_id=os.environ.get("RECIPE_RUNNER_AGENT_TYPE_ID", "").strip() or None)

    def _key(self) -> str:
        if not self._api_key and self._key_loader:
            try:
                self._api_key = self._key_loader()
            except Exception as exc:  # noqa: BLE001 - never echo the secret or its ARN
                raise McpError("MCP_KEY_UNAVAILABLE", type(exc).__name__)
        if not self._api_key:
            raise McpError("MCP_KEY_UNAVAILABLE", "the MCP API key is not configured.")
        return self._api_key

    def rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + self._key()}
        try:
            status, raw = self.transport(self.url, headers, body, self.timeout)
        except Exception as exc:  # noqa: BLE001
            raise McpError("MCP_TRANSPORT", type(exc).__name__)
        if status >= 400:
            raise McpError(f"MCP_HTTP_{status}", f"the MCP endpoint answered HTTP {status}.")
        try:
            msg = _decode(raw)
        except ValueError:
            raise McpError("MCP_BAD_RESPONSE", "the MCP endpoint answered a non-JSON body.")
        if isinstance(msg.get("error"), dict):
            raise McpError("MCP_RPC_ERROR", str(msg["error"].get("message") or "JSON-RPC error")[:300])
        return msg.get("result") or {}

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return _payload(self.rpc("tools/call", {"name": name, "arguments": arguments}))

    # ------------------------------------------------------------------ governance
    def governance_hash(self) -> Optional[str]:
        """search system.connection_health -> governance_hash; None when the governed surface is unreachable."""
        try:
            return _find_key(self.call_tool("search", {"action": "system.connection_health"}), "governance_hash")
        except McpError:
            return None

    # ------------------------------------------------------------------ runner session (one per run)
    def _coord(self, action: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        payload = self.call_tool("coordination", {"action": action, "arguments": arguments})
        err = _error_of(payload)
        if err:
            raise McpError(err["code"], f"{action}: {err['message']}")
        return payload

    def register_session(self, project_id: str, run_id: str, governance_hash: Optional[str] = None) -> Dict[str, Optional[str]]:
        if not self.agent_type_id:
            raise McpError("RUNNER_AGENT_TYPE_MISSING", "RECIPE_RUNNER_AGENT_TYPE_ID is not configured.")
        reg = self._coord("agent.register", {"agent_type_id": self.agent_type_id, "runtime": RUNTIME,
                                             "project_id": project_id, "purpose": f"recipe run {run_id}"})
        sid = _find_key(reg, "session_id")
        if not sid:
            raise McpError("RUNNER_SESSION_MISSING", "agent.register returned no session_id.")
        # agent.claim takes exactly {session_id, governance_hash} (verified live); project_id is rejected.
        ghash = governance_hash or self.governance_hash()
        if not ghash:
            raise McpError("GOVERNANCE_HASH_UNAVAILABLE", "agent.claim needs the governance_hash; connection_health returned none.")
        claim = self._coord("agent.claim", {"session_id": sid, "governance_hash": ghash})
        return {"session_id": sid, "sci": _find_key(claim, "sci")}

    def heartbeat(self, project_id: str, session_id: Optional[str]) -> None:
        if session_id:
            self._coord("escalation.watch", {"session_id": session_id, "project_id": project_id})

    def retire(self, project_id: str, session_id: Optional[str]) -> None:
        if session_id:
            self._coord("agent.retire", {"session_id": session_id, "project_id": project_id})

    # ------------------------------------------------------------------ the segment's execute call
    def execute_steps(self, calls: List[Dict[str, Any]], governance_hash: Optional[str], session: Optional[Dict[str, Any]],
                      continue_on_error: bool = False, idem_seed: str = "") -> List[Dict[str, Any]]:
        steps: List[Dict[str, Any]] = []
        for call in calls:
            args = dict(call.get("arguments") or {})
            if governance_hash:
                args.setdefault("governance_hash", governance_hash)           # INSIDE each step's arguments
            if session and session.get("session_id") and not is_read_action(call.get("action")):
                args.setdefault("active_agent_session_id", session["session_id"])
                if session.get("sci"):
                    args.setdefault("sci", session["sci"])
                args.setdefault("provider", PROVIDER)
            step = {"action": call.get("action"), "arguments": args,
                    "on_error": "continue" if (continue_on_error or call.get("on_error") == "continue") else "abort"}
            if call.get("dry_run"):
                step["dry_run"] = True
            steps.append(step)
        key = f"{idem_seed}:{hashlib.sha256(json.dumps(steps, sort_keys=True, default=str).encode()).hexdigest()[:20]}"
        payload = self.call_tool("execute", {"steps": steps, "idempotency_key": key})
        sr = payload.get("step_results")
        if not isinstance(sr, list):
            err = _error_of(payload) or {"code": "EXECUTE_FAILED", "message": "execute returned no step_results"}
            return [{"ok": False, "error": err}]
        return [_map_step(s) if isinstance(s, dict) else {"ok": False, "error": {"code": "NO_RESULT", "message": "malformed step result"}}
                for s in sr[:len(calls)]]


def execute_batch(batch: Dict[str, Any], executor: EnceladusMcpExecutor, session: Optional[Dict[str, Any]],
                  call_local: Callable[[Dict[str, Any], bool], Dict[str, Any]]) -> Dict[str, Any]:
    """ctx.execute for one segment.  Governed enceladus steps are batched into ONE execute call (a step that binds to
    an earlier step of the same batch flushes the batch first); recipe.* and external-surface steps use call_local."""
    results: Dict[str, Any] = {}
    out: List[Dict[str, Any]] = []
    group: List[Dict[str, Any]] = []
    cont = bool(batch.get("continue_on_error"))
    state = {"stop": False}
    seed = str(batch.get("run_id") or "")

    def tolerant(call: Dict[str, Any]) -> bool:
        return cont or call.get("on_error") == "continue"

    def flush() -> None:
        if not group:
            return
        try:
            rs = executor.execute_steps(group, batch.get("governance_hash"), session, cont, seed)
        except McpError as exc:
            rs = [{"ok": False, "error": {"code": exc.code, "message": exc.message}}]
        except Exception as exc:  # noqa: BLE001
            rs = [{"ok": False, "error": {"code": "EXECUTE_FAILED", "message": type(exc).__name__}}]
        for call, res in zip(group, rs):
            res = dict(res, step_id=call["step_id"])
            out.append(res)
            if res.get("ok"):
                results[call["step_id"]] = res.get("result")
            elif not tolerant(call):
                state["stop"] = True
        group.clear()

    for call in batch.get("calls", []):
        if state["stop"]:
            break
        try:
            args = rrs.resolve_refs(call.get("arguments", {}), results)
        except (KeyError, TypeError):
            flush()
            if state["stop"]:
                break
            try:
                args = rrs.resolve_refs(call.get("arguments", {}), results)
            except (KeyError, TypeError) as exc:
                out.append({"step_id": call["step_id"], "ok": False, "error": {"code": "BINDING_FAILED", "message": f"unresolved in-segment binding: {exc}"}})
                if tolerant(call):
                    continue
                break
        call = dict(call, arguments=args)
        dry = bool(call.get("dry_run") or batch.get("dry_run"))
        local = (call.get("surface") or "enceladus") != "enceladus" or str(call.get("action") or "").startswith("recipe.")
        if local:
            flush()
            if state["stop"]:
                break
            res = dict(call_local(call, dry), step_id=call["step_id"])
            out.append(res)
            if res.get("ok"):
                results[call["step_id"]] = res.get("result")
            elif not tolerant(call):
                break
        else:
            group.append(dict(call, dry_run=dry))
    flush()
    return {"results": out}
