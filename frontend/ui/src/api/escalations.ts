import { fetchWithAuth } from './client'

// ENC-FTR-121 Ph3 (ENC-TSK-J70): io's escalation approval queue
// (DOC-5B888FCA43B8 §5.7). All calls ride the Cognito session cookie —
// the backend structurally rejects non-human credentials.

export interface EscalationDiff {
  mutation_type: string
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
    expected_version: string
    current_sync_version: string
    current_updated_at: string
    detected: boolean
  }
}

export interface EscalationItem {
  item_id: string
  project_id: string
  status: string
  mutation_type: string
  target_record_id: string
  justification: string
  payload: Record<string, unknown>
  requested_by?: { session_id?: string; agent_type_id?: string }
  approved_by?: { sub?: string; email?: string }
  guidance_note?: string
  created_at: string
  updated_at: string
  applied_at?: string
  diff?: EscalationDiff
}

export interface EscalationsFeedResponse {
  success: boolean
  project_id: string
  pending: EscalationItem[]
  terminal: EscalationItem[]
  count: number
}

export interface EscalationDecisionResponse {
  success: boolean
  escalation_id: string
  status: string
  applied?: boolean
  approved_by?: string
  denied_by?: string
  guidance_note?: string
  apply_error?: string
  retry?: string
}

export const escalationKeys = {
  feed: (projectId: string) => ['escalations', 'feed', projectId] as const,
}

export async function fetchEscalations(
  projectId = 'enceladus',
): Promise<EscalationsFeedResponse> {
  const res = await fetchWithAuth(
    `/api/v1/coordination/escalations?project_id=${encodeURIComponent(projectId)}`,
  )
  if (!res.ok) throw new Error(`Failed to fetch escalations: ${res.status}`)
  return res.json()
}

async function postDecision(
  projectId: string,
  escalationId: string,
  decision: 'approve' | 'deny',
  body?: Record<string, unknown>,
): Promise<EscalationDecisionResponse> {
  const res = await fetchWithAuth(
    `/api/v1/coordination/escalations/${encodeURIComponent(projectId)}/${encodeURIComponent(escalationId)}/${decision}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    },
  )
  const payload = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(payload?.error || `Escalation ${decision} failed: ${res.status}`)
  }
  return payload
}

export function approveEscalation(
  projectId: string,
  escalationId: string,
): Promise<EscalationDecisionResponse> {
  return postDecision(projectId, escalationId, 'approve')
}

export function denyEscalation(
  projectId: string,
  escalationId: string,
  guidanceNote?: string,
): Promise<EscalationDecisionResponse> {
  return postDecision(
    projectId,
    escalationId,
    'deny',
    guidanceNote ? { guidance_note: guidanceNote } : {},
  )
}
