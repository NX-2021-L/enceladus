/**
 * Escalations API — ENC-FTR-121 Ph3/Ph4 cockpit surface (ENC-TSK-O40).
 *
 * The io approval queue and its two non-delegable decision routes. Backend:
 * backend/lambda/coordination_api/lambda_function.py
 *   GET  /api/v1/coordination/escalations?project_id=&status=
 *        -> { success, project_id, pending[], terminal[], count }
 *        `pending` = status "requested" (each carries a freshly-rendered
 *        `diff` + drift flag); `terminal` = everything already decided.
 *   POST /api/v1/coordination/escalations/{projectId}/{escalationId}/approve
 *   POST /api/v1/coordination/escalations/{projectId}/{escalationId}/deny
 *        body { guidance_note? } — a non-empty note lands the escalation in
 *        `denied_with_guidance` rather than `denied`.
 *
 * THE NON-DELEGABLE BOUNDARY (ENC-ISS-501 lineage, DOC-5B888FCA43B8 §6).
 * Approve/deny deliberately have NO MCP action and no agent path at all. The
 * backend fail-closes through three independent gates before it will decide:
 *   1. _is_cognito_session          — a Cognito session at all;
 *   2. _is_human_cognito_principal  — an *interactive human* ID token
 *      (token_use=id, aud on the human app-client allowlist, email not under
 *      a machine domain such as @enceladus.internal). Access tokens,
 *      client_credentials/M2M grants and machine-operated Cognito users are
 *      rejected here regardless of allowlist contents;
 *   3. _is_allowlisted_escalation_decider — the decider's email present in
 *      the Console-only S3 allowlist document.
 * This module NEVER attempts to satisfy those gates on the caller's behalf:
 * it sends the browser's own Cognito session cookie (credentials: 'include')
 * and surfaces a rejection verbatim. There is deliberately no internal-key,
 * SCI or agent-auth fallback path in this file — adding one would convert a
 * structural control into a conventional one (see ENC-ISS-640's lesson that
 * conventional isolation fails silently).
 */

import { API_BASE, SessionExpiredError } from './client'

/** Escalation lifecycle statuses as written by the coordination API. */
export const ESCALATION_PENDING_STATUS = 'requested'

export interface EscalationDiff {
  mutation_type?: string
  target_record_id?: string
  target_missing?: boolean
  field?: string
  current?: unknown
  requested?: unknown
  field_values?: Record<string, { current: unknown; requested: unknown }>
  target_snapshot?: {
    title?: string
    status?: string
    transition_type?: string
    checkout_state?: string
    sync_version?: number | string
    updated_at?: string
  }
  drift?: {
    expected_version?: string
    current_sync_version?: string
    current_updated_at?: string
    detected?: boolean
  }
}

export interface EscalationItem {
  item_id: string
  project_id?: string
  status: string
  mutation_type?: string
  target_record_id?: string
  justification?: string
  payload?: Record<string, unknown>
  requested_by?: { session_id?: string; agent_type_id?: string }
  approved_by?: { sub?: string; email?: string }
  guidance_note?: string
  created_at: string
  updated_at?: string
  applied_at?: string
  diff?: EscalationDiff
  events?: unknown[]
  [key: string]: unknown
}

export interface EscalationsFeed {
  success: boolean
  project_id: string
  pending: EscalationItem[]
  terminal: EscalationItem[]
  count: number
}

export interface EscalationDecisionResult {
  success: boolean
  escalation_id: string
  status: string
  applied?: boolean
  approved_by?: string
  denied_by?: string
  guidance_note?: string
  /** Present when the approval was durably recorded but applyEscalatedMutation
   *  failed — the approval is NOT lost and `retry` names the idempotent route. */
  apply_error?: string
  retry?: string
  apply_result?: unknown
}

/**
 * A decision rejected by one of the three human-principal gates, or lost to a
 * concurrent decider. Carries the server's own message so the cockpit can
 * render exactly why the boundary refused rather than a generic failure.
 */
export class EscalationDecisionError extends Error {
  readonly status: number
  /** 403 from any of the three non-delegable gates. */
  readonly forbidden: boolean
  /** 409 — already decided, or lost the concurrent-decision race. */
  readonly conflict: boolean

  constructor(status: number, message: string) {
    super(message)
    this.name = 'EscalationDecisionError'
    this.status = status
    this.forbidden = status === 403
    this.conflict = status === 409
  }
}

export const escalationKeys = {
  feed: (projectId: string) => ['coordination', 'escalations', 'feed', projectId] as const,
}

/**
 * Feed read. Returns pending and terminal separately — the split is the
 * backend's, and `pending` is the only bucket carrying a rendered `diff`, so
 * flattening the two loses information the detail view needs.
 */
export async function fetchEscalationsFeed(
  projectId: string,
  init?: { signal?: AbortSignal },
): Promise<EscalationsFeed> {
  const url = `${API_BASE}/coordination/escalations?project_id=${encodeURIComponent(projectId)}`
  const res = await fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new Error(`Failed to load escalations (${res.status})`)
  const body = (await res.json()) as Partial<EscalationsFeed>
  return {
    success: body.success ?? true,
    project_id: body.project_id ?? projectId,
    pending: body.pending ?? [],
    terminal: body.terminal ?? [],
    count: body.count ?? (body.pending?.length ?? 0) + (body.terminal?.length ?? 0),
  }
}

async function postDecision(
  projectId: string,
  escalationId: string,
  decision: 'approve' | 'deny',
  body: Record<string, unknown>,
): Promise<EscalationDecisionResult> {
  const url = `${API_BASE}/coordination/escalations/${encodeURIComponent(projectId)}/${encodeURIComponent(escalationId)}/${decision}`
  const res = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    cache: 'no-store',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    },
    body: JSON.stringify(body),
  })
  if (res.status === 401) throw new SessionExpiredError()
  const payload = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    throw new EscalationDecisionError(
      res.status,
      String(payload.error ?? `Escalation ${decision} failed (${res.status})`),
    )
  }
  return payload as unknown as EscalationDecisionResult
}

/** Approve — drives applyEscalatedMutation server-side. */
export function approveEscalation(
  projectId: string,
  escalationId: string,
): Promise<EscalationDecisionResult> {
  return postDecision(projectId, escalationId, 'approve', {})
}

/**
 * Deny. A non-empty `guidanceNote` is what distinguishes `denied_with_guidance`
 * from a bare `denied` — the note is the channel back to the requesting agent,
 * so the cockpit always offers it.
 */
export function denyEscalation(
  projectId: string,
  escalationId: string,
  guidanceNote?: string,
): Promise<EscalationDecisionResult> {
  const note = (guidanceNote ?? '').trim()
  return postDecision(projectId, escalationId, 'deny', note ? { guidance_note: note } : {})
}
