import type { Task, Issue, Feature, Plan, Lesson, ProjectSummary } from '../types/feeds'
import { fetchWithAuth } from './client'

const BASE = import.meta.env.VITE_MUTATION_BASE_URL ?? '/api/v1/tracker'

/**
 * ENC-FTR-073: NotFoundError distinguishes 404 responses from generic network
 * failures so detail-page fallback consumers can render a "record not found"
 * UX rather than a generic error state. Thrown by `fetchRecord` for HTTP 404.
 */
export class NotFoundError extends Error {
  readonly status: number
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
    this.status = 404
  }
}

export function isNotFoundError(err: unknown): err is NotFoundError {
  if (err instanceof NotFoundError) return true
  // String match fallback for callers that construct generic errors with the
  // legacy " 404" suffix (keeps parity with older fetch helpers until fully
  // migrated).
  if (err instanceof Error && /\b404\b/.test(err.message)) return true
  return false
}

export const trackerKeys = {
  task: (recordId: string) => ['tracker', 'task', recordId] as const,
  issue: (recordId: string) => ['tracker', 'issue', recordId] as const,
  feature: (recordId: string) => ['tracker', 'feature', recordId] as const,
  plan: (recordId: string) => ['tracker', 'plan', recordId] as const,
  lesson: (recordId: string) => ['tracker', 'lesson', recordId] as const,
  document: (recordId: string) => ['tracker', 'document', recordId] as const,
}

type RecordTypeSlug = 'task' | 'issue' | 'feature' | 'plan' | 'lesson'

async function fetchRecord<T>(
  projectId: string,
  recordType: RecordTypeSlug,
  recordId: string,
  init?: { signal?: AbortSignal },
): Promise<T> {
  const url = `${BASE}/${encodeURIComponent(projectId)}/${recordType}/${encodeURIComponent(recordId)}`
  const res = await fetchWithAuth(url, init)
  if (res.status === 404) {
    throw new NotFoundError(`${recordType} ${recordId} not found`)
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch ${recordType} ${recordId}: ${res.status}`)
  }
  const data = await res.json()
  return (data.record ?? data) as T
}

export const fetchTaskById = (
  projectId: string,
  recordId: string,
  init?: { signal?: AbortSignal },
) => fetchRecord<Task>(projectId, 'task', recordId, init)

export const fetchIssueById = (
  projectId: string,
  recordId: string,
  init?: { signal?: AbortSignal },
) => fetchRecord<Issue>(projectId, 'issue', recordId, init)

export const fetchFeatureById = (
  projectId: string,
  recordId: string,
  init?: { signal?: AbortSignal },
) => fetchRecord<Feature>(projectId, 'feature', recordId, init)

export const fetchPlanById = (
  projectId: string,
  recordId: string,
  init?: { signal?: AbortSignal },
) => fetchRecord<Plan>(projectId, 'plan', recordId, init)

export const fetchLessonById = (
  projectId: string,
  recordId: string,
  init?: { signal?: AbortSignal },
) => fetchRecord<Lesson>(projectId, 'lesson', recordId, init)

export function resolveProjectFromRecordId(
  recordId: string,
  projects: ProjectSummary[],
): string | null {
  const prefix = recordId.split('-')[0]
  if (!prefix) return null
  const match = projects.find((p) => p.prefix === prefix)
  return match?.project_id ?? null
}
