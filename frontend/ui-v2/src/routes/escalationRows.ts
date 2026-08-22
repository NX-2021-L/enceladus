/**
 * Escalation list/detail derivations — ENC-TSK-O40.
 *
 * Pure helpers, split out of EscalationsRoute so they are unit-testable
 * without mounting the route (the ui-v2 convention — see ChangelogRoute.test
 * / homeQueue.test). Nothing here touches the network or React.
 */

import type { EscalationItem, EscalationsFeed } from '../api/escalations'
import { ESCALATION_PENDING_STATUS } from '../api/escalations'

/**
 * Cockpit-facing filter buckets. The backend's own vocabulary is
 * requested / approved / applied / denied / denied_with_guidance; io thinks in
 * "what needs me" vs "what did I decide", so `denied` folds both denial
 * statuses and `approved` folds the post-apply statuses.
 */
export type EscalationBucket = 'pending' | 'approved' | 'denied' | 'all'

export interface EscalationRow {
  /** trackBy key — item_id is the escalation's own id. */
  id: string
  status: string
  bucket: EscalationBucket
  targetRecordId: string
  /** Session that filed it — the agent side of the loop. */
  requestedBySession: string
  mutationSummary: string
  justification: string
  createdAt: string
  ageLabel: string
  /** Only 'requested' escalations can be decided (backend returns 409 otherwise). */
  decidable: boolean
  /** Drift detected between the escalation's expected version and the live record. */
  driftDetected: boolean
  item: EscalationItem
}

const APPROVED_STATUSES = new Set(['approved', 'applying', 'applied'])
const DENIED_STATUSES = new Set(['denied', 'denied_with_guidance'])

export function bucketForStatus(status: string): EscalationBucket {
  const value = (status || '').trim().toLowerCase()
  if (value === ESCALATION_PENDING_STATUS) return 'pending'
  if (APPROVED_STATUSES.has(value)) return 'approved'
  if (DENIED_STATUSES.has(value)) return 'denied'
  // An unrecognized terminal status must never masquerade as pending — it is
  // browsable under "all" but never offered a decision control.
  return 'all'
}

/**
 * Compact, human-readable rendering of what the agent is actually asking for.
 * Falls back through diff -> payload -> mutation_type so a row is never blank:
 * an escalation with no summary is one io cannot triage at a glance.
 */
export function summarizeMutation(item: EscalationItem): string {
  const mutationType = String(item.mutation_type ?? item.diff?.mutation_type ?? '').trim()
  const payload = (item.payload ?? {}) as Record<string, unknown>

  const targetStatus = payload.target_status
  if (typeof targetStatus === 'string' && targetStatus.trim()) {
    const current = item.diff?.target_snapshot?.status
    return current ? `status: ${current} → ${targetStatus}` : `status → ${targetStatus}`
  }

  const field = String(item.diff?.field ?? payload.field ?? '').trim()
  if (field) {
    const requested = item.diff?.requested ?? payload.value
    return `${field} → ${formatScalar(requested)}`
  }

  const fieldValues = item.diff?.field_values
  if (fieldValues && Object.keys(fieldValues).length > 0) {
    const names = Object.keys(fieldValues)
    const head = names.slice(0, 2).join(', ')
    return names.length > 2 ? `${head} +${names.length - 2} more` : head
  }

  return mutationType || '—'
}

function formatScalar(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

/**
 * Age of the request. io's triage question is "how long has this been sitting
 * on me", so this is deliberately coarse and always relative.
 */
export function formatAge(createdAt: string, now: Date = new Date()): string {
  const created = Date.parse(createdAt)
  if (!Number.isFinite(created)) return '—'
  const seconds = Math.max(0, Math.floor((now.getTime() - created) / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h`
  const days = Math.floor(hours / 24)
  return `${days}d`
}

export function toEscalationRow(item: EscalationItem, now?: Date): EscalationRow {
  const status = String(item.status ?? '')
  const bucket = bucketForStatus(status)
  return {
    id: String(item.item_id ?? ''),
    status,
    bucket,
    targetRecordId: String(item.target_record_id ?? '—'),
    requestedBySession: String(item.requested_by?.session_id ?? '—'),
    mutationSummary: summarizeMutation(item),
    justification: String(item.justification ?? ''),
    createdAt: String(item.created_at ?? ''),
    ageLabel: formatAge(String(item.created_at ?? ''), now),
    decidable: bucket === 'pending',
    driftDetected: item.diff?.drift?.detected === true,
    item,
  }
}

/**
 * Flatten the feed into rows, pending first. The backend already sorts each
 * bucket newest-first; pending leads because it is the only actionable bucket.
 */
export function toEscalationRows(feed: EscalationsFeed | undefined, now?: Date): EscalationRow[] {
  if (!feed) return []
  return [...feed.pending, ...feed.terminal].map((item) => toEscalationRow(item, now))
}

export function filterRows(rows: EscalationRow[], bucket: EscalationBucket): EscalationRow[] {
  if (bucket === 'all') return rows
  return rows.filter((row) => row.bucket === bucket)
}

export function countByBucket(rows: EscalationRow[]): Record<EscalationBucket, number> {
  const counts: Record<EscalationBucket, number> = {
    pending: 0,
    approved: 0,
    denied: 0,
    all: rows.length,
  }
  for (const row of rows) {
    if (row.bucket !== 'all') counts[row.bucket] += 1
  }
  return counts
}

/**
 * Turn a decision failure into cockpit guidance. The three 403s from the
 * non-delegable gates are indistinguishable by status code alone, so the
 * server's own message is always surfaced verbatim and this only adds the
 * "what do I do now" line.
 */
export function describeDecisionError(error: unknown): {
  type: 'error' | 'warning'
  header: string
  detail: string
  hint?: string
} {
  const message = error instanceof Error ? error.message : String(error)
  const status = (error as { status?: number } | null)?.status

  if (status === 403) {
    return {
      type: 'error',
      header: 'Decision refused — non-delegable approval boundary',
      detail: message,
      hint:
        'Escalation decisions require an interactive human Cognito session whose email is on the ' +
        'Console-managed approver allowlist. This is a structural control (ENC-ISS-501): it cannot ' +
        'be delegated to an agent, an access token, or an internal-key path.',
    }
  }
  if (status === 409) {
    return {
      type: 'warning',
      header: 'Already decided',
      detail: message,
      hint: 'The queue has been refreshed — only escalations still in "requested" can be decided.',
    }
  }
  if (status === 404) {
    return { type: 'warning', header: 'Escalation not found', detail: message }
  }
  return { type: 'error', header: 'Decision failed', detail: message }
}

/**
 * Success line for a completed decision. Approve has a second failure mode the
 * UI must not hide: the approval is recorded durably but applyEscalatedMutation
 * failed, so the mutation has NOT landed and the idempotent retry route is the
 * next step. That is a warning, not a success.
 */
export function describeDecisionResult(result: {
  status?: string
  applied?: boolean
  apply_error?: string
  retry?: string
  guidance_note?: string
  escalation_id?: string
}): { type: 'success' | 'warning'; header: string; detail: string } {
  const id = result.escalation_id ?? 'escalation'
  if (result.apply_error) {
    return {
      type: 'warning',
      header: `${id} approved — but the mutation did not apply`,
      detail:
        `${result.apply_error} The approval is durable (status=approved); the mutation can be ` +
        `re-driven idempotently${result.retry ? ` via ${result.retry}` : ''}.`,
    }
  }
  if (result.status === 'denied_with_guidance') {
    return {
      type: 'success',
      header: `${id} denied with guidance`,
      detail: result.guidance_note
        ? `Guidance returned to the requesting session: “${result.guidance_note}”`
        : 'Guidance recorded on the escalation.',
    }
  }
  if (result.status === 'denied') {
    return { type: 'success', header: `${id} denied`, detail: 'No guidance note was attached.' }
  }
  return {
    type: 'success',
    header: `${id} approved`,
    detail:
      result.applied === false
        ? 'Approval recorded; apply is still in flight.'
        : 'Approval recorded and the requested mutation was applied to the target record.',
  }
}
