/**
 * Tracker mutation API — If-Match revision contract (ENC-TSK-L47 / K25 AC-3).
 * Offline queue integration (K25 AC-18).
 */

import { API_BASE, SessionExpiredError } from './client'
import {
  enqueueMutation,
  type QueuedMutation,
} from '../offline/mutationQueue'
import { useOfflineStore } from '../store/offlineStore'

export const GOVERNANCE_CRITICAL_FIELDS = [
  'status',
  'priority',
  'transition_type',
  'acceptance_criteria',
] as const

export interface MutationResult {
  success: boolean
  record_id: string
  updated_at: string
  updated_status?: string
  sync_version?: number
}

export interface RevisionConflictDetails {
  code: 'REVISION_CONFLICT'
  field?: string
  record_id: string
  record_type?: string
  expected_revision?: string
  current_revision?: number
  current?: Record<string, unknown>
}

export class RevisionConflictError extends Error {
  readonly status = 409
  readonly details: RevisionConflictDetails

  constructor(message: string, details: RevisionConflictDetails) {
    super(message)
    this.name = 'RevisionConflictError'
    this.details = details
  }
}

export function isRevisionConflictError(error: unknown): error is RevisionConflictError {
  return error instanceof RevisionConflictError
}

export function readSyncVersion(record: unknown): number | undefined {
  if (!record || typeof record !== 'object') return undefined
  const raw = (record as { sync_version?: unknown }).sync_version
  if (typeof raw === 'number' && Number.isFinite(raw)) return raw
  if (typeof raw === 'string' && raw.trim()) {
    const parsed = Number(raw)
    return Number.isFinite(parsed) ? parsed : undefined
  }
  return undefined
}

interface PatchOptions {
  ifMatchRevision?: number
  skipOfflineQueue?: boolean
}

async function parseErrorBody(res: Response): Promise<Record<string, unknown>> {
  try {
    return (await res.json()) as Record<string, unknown>
  } catch {
    return {}
  }
}

async function sendMutationRequest(
  url: string,
  method: 'PATCH' | 'POST' | 'DELETE',
  body: Record<string, unknown>,
  headers: Record<string, string>,
): Promise<MutationResult> {
  const res = await fetch(url, {
    method,
    credentials: 'include',
    headers: {
      'content-type': 'application/json',
      'x-requested-with': 'XMLHttpRequest',
      accept: 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
    cache: 'no-store',
  })

  if (res.status === 401) throw new SessionExpiredError()

  const data = await parseErrorBody(res)

  if (res.status === 409 && data.code === 'REVISION_CONFLICT') {
    throw new RevisionConflictError(
      String(data.error ?? 'Revision conflict'),
      {
        code: 'REVISION_CONFLICT',
        field: typeof data.field === 'string' ? data.field : undefined,
        record_id: String(data.record_id ?? ''),
        record_type: typeof data.record_type === 'string' ? data.record_type : undefined,
        expected_revision:
          typeof data.expected_revision === 'string' ? data.expected_revision : undefined,
        current_revision:
          typeof data.current_revision === 'number' ? data.current_revision : undefined,
        current:
          typeof data.current === 'object' && data.current
            ? (data.current as Record<string, unknown>)
            : undefined,
      },
    )
  }

  if (!res.ok) {
    throw new Error(String(data.error ?? `Mutation failed (${res.status})`))
  }

  return data as MutationResult
}

export async function patchTrackerRecord(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature' | 'plan' | 'lesson',
  recordId: string,
  body: Record<string, unknown>,
  options: PatchOptions = {},
): Promise<MutationResult> {
  const url = `${API_BASE}/tracker/${encodeURIComponent(projectId)}/${recordType}/${encodeURIComponent(recordId)}`
  const headers: Record<string, string> = {}
  if (options.ifMatchRevision !== undefined) {
    headers['If-Match'] = String(options.ifMatchRevision)
  }

  if (typeof navigator !== 'undefined' && !navigator.onLine && !options.skipOfflineQueue) {
    await enqueueMutation({ url, method: 'PATCH', body, headers })
    await useOfflineStore.getState().refreshPendingCount()
    return {
      success: true,
      record_id: recordId,
      updated_at: new Date().toISOString(),
    }
  }

  return sendMutationRequest(url, 'PATCH', body, headers)
}

/**
 * Checkout release/acquire (ENC-TSK-M33 -- "Check In" primary action). Same
 * transport conventions as sendMutationRequest, but hits the `/checkout`
 * sub-resource with no body, matching the legacy PWA's `setCheckout`
 * (frontend/ui/src/api/mutations.ts): POST acquires, DELETE releases.
 */
export async function setCheckout(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature' | 'plan',
  recordId: string,
  checkedOut: boolean,
): Promise<MutationResult> {
  const url = `${API_BASE}/tracker/${encodeURIComponent(projectId)}/${recordType}/${encodeURIComponent(recordId)}/checkout`
  return sendMutationRequest(url, checkedOut ? 'POST' : 'DELETE', {}, {})
}

export async function replayQueuedMutation(entry: QueuedMutation): Promise<boolean> {
  try {
    await sendMutationRequest(entry.url, entry.method, entry.body, entry.headers)
    return true
  } catch (error) {
    if (error instanceof RevisionConflictError) return false
    if (error instanceof SessionExpiredError) return false
    return false
  }
}

export async function closeRecord(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature' | 'plan',
  recordId: string,
  ifMatchRevision?: number,
): Promise<MutationResult> {
  return patchTrackerRecord(projectId, recordType, recordId, { action: 'close' }, { ifMatchRevision })
}

export async function submitNote(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature' | 'plan',
  recordId: string,
  note: string,
  ifMatchRevision?: number,
): Promise<MutationResult> {
  return patchTrackerRecord(projectId, recordType, recordId, { action: 'note', note }, { ifMatchRevision })
}

/**
 * Worklog append (ENC-TSK-M33 -- the "Note" primary-action button). Unlike
 * `submitNote` ('note' action -- queued as a pending update for the next
 * agent session to process, per the legacy PWA's queued-note flow), 'worklog'
 * writes an immediate `history[]` entry the WORKLOG tab renders right away --
 * matching the AC's "Note button appends a worklog entry" requirement and
 * v3's identical "Submit + Close" note-then-status two-step (LifecycleActions
 * .tsx `noteAction = closeImmediately ? 'worklog' : 'note'`).
 */
export async function submitWorklog(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature' | 'plan',
  recordId: string,
  note: string,
  ifMatchRevision?: number,
): Promise<MutationResult> {
  return patchTrackerRecord(projectId, recordType, recordId, { action: 'worklog', note }, { ifMatchRevision })
}

export async function setField(
  projectId: string,
  recordType: 'task' | 'issue' | 'feature' | 'plan' | 'lesson',
  recordId: string,
  field: string,
  value: string,
  ifMatchRevision?: number,
  /** ENC-ISS-092 user-initiated bypass ({user_initiated:true, user_note}) or
   *  a backward revert ({revert_reason}) -- forwarded verbatim as
   *  `transition_evidence` in the PATCH body. */
  transitionEvidence?: Record<string, unknown>,
): Promise<MutationResult> {
  return patchTrackerRecord(
    projectId,
    recordType,
    recordId,
    { field, value, ...(transitionEvidence ? { transition_evidence: transitionEvidence } : {}) },
    { ifMatchRevision },
  )
}

export function mergeConflictFields(
  clientField: string,
  clientValue: unknown,
  serverRecord: Record<string, unknown> | undefined,
): 'server-wins' | 'side-by-side' {
  if (GOVERNANCE_CRITICAL_FIELDS.includes(clientField as (typeof GOVERNANCE_CRITICAL_FIELDS)[number])) {
    return 'server-wins'
  }
  if (!serverRecord) return 'side-by-side'
  const serverValue = serverRecord[clientField]
  if (serverValue === clientValue) return 'server-wins'
  return 'side-by-side'
}
