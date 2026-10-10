/**
 * DVP-TSK-895: governed transport for the generic action forms. The ONLY place
 * the action layer touches the network (AC-13: fetch lives in src/api).
 *
 * The kit (`@io-kit/schema_form/execute`) never holds credentials; this closure
 * carries the PWA session (cookie, credentials: 'include'). Every action goes
 * through the coordination API's MCP JSON-RPC route (POST /coordination/mcp,
 * Cognito cookie auth, same as every other coordination call): `tools/call`
 * `execute` (dry_run:true for the preview, dry_run:false with an idempotency
 * key for the execute), or `search`/`coordination` for the wrapper actions.
 * Server validation and the io-dev-admin gate stay authoritative (E2-R14).
 */
import type { Transport, TransportRequest, TransportResponse } from '@io-kit/schema_form/execute'
import { API_BASE, SessionExpiredError } from './client'

type Json = Record<string, unknown>

export function isRecord(v: unknown): v is Json {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** The first step result of an MCP execute envelope, or undefined. */
export function firstStep(body: unknown): Json | undefined {
  if (!isRecord(body)) return undefined
  const steps = body.step_results
  return Array.isArray(steps) && isRecord(steps[0]) ? (steps[0] as Json) : undefined
}

/** MCP envelope -> what the kit expects for each phase. Pure; unit-tested. */
export function adaptResponse(req: TransportRequest, status: number, body: unknown): TransportResponse {
  const ok = status >= 200 && status < 300
  if (!ok) return { status, body }
  const step = firstStep(body)
  if (req.phase === 'dry_run') {
    // ResolvedCall v1 is the step's resolved_call (DVP-TSK-892); anything else passes through
    // and the kit rejects it as invalid-dry-run rather than the UI inventing a preview.
    // execute puts it on the step; the coordination wrapper (DVP-TSK-892 follow-up) returns it top-level.
    if (step && isRecord(step.resolved_call)) return { status, body: step.resolved_call }
    if (isRecord(body) && isRecord(body.resolved_call)) return { status, body: body.resolved_call }
    return { status, body }
  }
  const failed = step && step.ok === false
  if (failed) return { status: typeof step.status === 'number' ? step.status : 422, body: step.problem ?? step }
  const source: Json = step ?? (isRecord(body) ? body : {})
  const structured = source.structuredContent ?? source.result ?? source
  return {
    status,
    body: {
      ok: true,
      structuredContent: structured,
      ...(isRecord(source.minted) ? { minted: source.minted } : {}),
      ...(Array.isArray(source.echo) ? { echo: source.echo } : {}),
      ...(isRecord(source.inputRequired) ? { inputRequired: source.inputRequired } : {}),
    },
  }
}

/** tools/call params for the action: `execute` for via=execute, `search`/`coordination` for the wrappers. */
export function buildToolCall(req: TransportRequest, via: string | undefined): { name: string; arguments: Json } {
  const b = req.body as Json
  if (via === 'search') {
    return { name: via, arguments: { action: req.action, arguments: b.arguments } }
  }
  if (via === 'coordination') {
    // Coordination writes take top-level dry_run (DVP-TSK-892 follow-up, E2-R16).
    return {
      name: via,
      arguments: {
        action: req.action,
        arguments: b.arguments,
        ...(req.phase === 'dry_run' ? { dry_run: true } : {}),
        ...(b.idempotencyKey ? { idempotency_key: b.idempotencyKey } : {}),
        ...(b.schemaHash ? { schema_hash: b.schemaHash } : {}),
      },
    }
  }
  return {
    name: 'execute',
    arguments: {
      steps: [{ action: req.action, arguments: b.arguments }],
      dry_run: req.phase === 'dry_run',
      idempotency_key: b.idempotencyKey,
      schema_hash: b.schemaHash,
    },
  }
}

let rpcId = 0

export function buildEnvelope(req: TransportRequest, via: string | undefined): Json {
  return { jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: buildToolCall(req, via) }
}

/**
 * JSON-RPC response -> the tool payload (result.content[0].text parsed) or a problem.
 * A JSON-RPC error and an isError result both become an RFC 9457 problem so the kit maps them.
 */
export function unwrapRpc(status: number, rpc: unknown): { status: number; body: unknown } {
  if (!isRecord(rpc)) return { status, body: rpc }
  if (isRecord(rpc.error)) {
    const code = typeof rpc.error.code === 'number' ? rpc.error.code : 0
    const http = code === -32602 ? 422 : code === -32601 ? 404 : 500
    return { status: http, body: { type: 'about:blank', title: String(rpc.error.message ?? 'MCP error'), status: http } }
  }
  const result = isRecord(rpc.result) ? rpc.result : undefined
  const first = result && Array.isArray(result.content) && isRecord(result.content[0]) ? result.content[0] : undefined
  let payload: unknown = result?.structuredContent ?? result
  if (first && typeof first.text === 'string') {
    try {
      payload = JSON.parse(first.text)
    } catch {
      payload = first.text
    }
  }
  if (result?.isError === true) {
    const p = isRecord(payload) && typeof payload.status === 'number' ? payload : { type: 'about:blank', title: 'Action failed', status: 422, detail: typeof payload === 'string' ? payload : undefined }
    return { status: (p as Json).status as number, body: p }
  }
  return { status, body: payload }
}

/** `viaOf(action)` names the MCP wrapper (execute | search | coordination) for the action. */
export function createActionsTransport(viaOf: (action: string) => string | undefined): Transport {
  return async (req) => {
    const res = await fetch(`${API_BASE}/coordination/mcp`, {
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
      signal: req.signal,
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'x-requested-with': 'XMLHttpRequest',
        ...req.headers,
      },
      body: JSON.stringify(buildEnvelope(req, viaOf(req.action))),
    })
    if (res.status === 401) throw new SessionExpiredError()
    const text = await res.text()
    let rpc: unknown = text
    try {
      rpc = text === '' ? undefined : JSON.parse(text)
    } catch {
      /* non-JSON stays a string */
    }
    const un = unwrapRpc(res.status, rpc)
    return adaptResponse(req, un.status, un.body)
  }
}
