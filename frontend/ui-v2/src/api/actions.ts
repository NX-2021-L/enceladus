/**
 * DVP-TSK-895: governed transport for the generic action forms. The ONLY place
 * the action layer touches the network (AC-13: fetch lives in src/api).
 *
 * The kit (`@io-kit/schema_form/execute`) never holds credentials; this closure
 * carries the PWA session (cookie, credentials: 'include'). Every action goes
 * through one governed endpoint, which relays to the MCP `execute` tool
 * (dry_run:true for the preview, dry_run:false with an Idempotency-Key for the
 * execute). Server validation and the io-dev-admin gate stay authoritative.
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
    return { status, body: step && isRecord(step.resolved_call) ? step.resolved_call : body }
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

export function buildEnvelope(req: TransportRequest, via: string | undefined): Json {
  const b = req.body as Json
  const args = req.phase === 'dry_run' ? b.arguments : (b.arguments as unknown)
  return {
    via: via ?? 'execute',
    steps: [{ action: req.action, arguments: args }],
    dry_run: req.phase === 'dry_run',
    schema_hash: b.schemaHash,
  }
}

/** `viaOf(action)` names the MCP wrapper (execute | search | coordination) for the action. */
export function createActionsTransport(viaOf: (action: string) => string | undefined): Transport {
  return async (req) => {
    const res = await fetch(`${API_BASE}/actions/execute`, {
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
    let body: unknown = text
    try {
      body = text === '' ? undefined : JSON.parse(text)
    } catch {
      /* non-JSON stays a string */
    }
    return adaptResponse(req, res.status, body)
  }
}
