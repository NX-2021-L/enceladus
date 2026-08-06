import { fetchWithAuth } from './client'

// ENC-FTR-121 Ph3 (ENC-TSK-J70): io's escalation approval queue
// (DOC-5B888FCA43B8 §5.7). All calls ride the Cognito session cookie —
// the backend structurally rejects non-human credentials.
//
// ENC-TSK-N81 (ENC-ISS-594): the feed endpoint is single-project by
// construction — it Queries one tracker partition keyed on project_id — so a
// caller that names one project can only ever see that project's escalations.
// Because approval is Cognito-human-only and non-delegable, invisible means
// unapprovable, and non-ENC escalations were wedging at status=requested with
// no UI path to decide them. fetchEscalationsInbox fans the same endpoint out
// across every project and merges the pending queues into one inbox.

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

/** Merged, cross-project pending queue plus the coverage it actually achieved. */
export interface EscalationsInboxResponse {
  pending: EscalationItem[]
  /** Projects whose feed answered successfully. */
  scanned: string[]
  /** Projects whose feed failed; their escalations are NOT in `pending`. */
  failed: string[]
}

export const escalationKeys = {
  feed: (projectId: string) => ['escalations', 'feed', projectId] as const,
  inbox: (projectIds: string[]) =>
    ['escalations', 'inbox', [...projectIds].sort().join(',')] as const,
}

export async function fetchEscalations(
  projectId = 'enceladus',
  status?: string,
): Promise<EscalationsFeedResponse> {
  const query = new URLSearchParams({ project_id: projectId })
  if (status) query.set('status', status)
  const res = await fetchWithAuth(`/api/v1/coordination/escalations?${query}`)
  if (!res.ok) throw new Error(`Failed to fetch escalations: ${res.status}`)
  return res.json()
}

/** Cap on simultaneous feed requests so a 25-project fan-out stays polite. */
const INBOX_CONCURRENCY = 6

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  async function run(): Promise<void> {
    while (next < items.length) {
      const index = next++
      results[index] = await worker(items[index])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run))
  return results
}

/**
 * ENC-TSK-N81 (ENC-ISS-594): io's single approval inbox.
 *
 * Queries each project's pending feed and merges the results newest-first.
 * A project that fails is reported in `failed` rather than rejecting the whole
 * inbox — one bad partition must not hide the escalations that DID load, which
 * is the same silent-invisibility failure this task exists to remove.
 */
export async function fetchEscalationsInbox(
  projectIds: string[],
): Promise<EscalationsInboxResponse> {
  const scanned: string[] = []
  const failed: string[] = []
  const pending: EscalationItem[] = []

  const feeds = await mapWithConcurrency(projectIds, INBOX_CONCURRENCY, async (projectId) => {
    try {
      return { projectId, feed: await fetchEscalations(projectId, 'requested') }
    } catch {
      return { projectId, feed: null }
    }
  })

  for (const { projectId, feed } of feeds) {
    if (!feed) {
      failed.push(projectId)
      continue
    }
    scanned.push(projectId)
    // Trust the item's own project_id, but fall back to the partition we asked
    // for — decision routing depends on this being right for non-ENC items.
    for (const item of feed.pending ?? []) {
      pending.push(item.project_id ? item : { ...item, project_id: projectId })
    }
  }

  pending.sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')))
  return { pending, scanned, failed }
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
