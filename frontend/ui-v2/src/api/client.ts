/**
 * HTTP client — the ONLY module permitted to call the platform fetch (see the
 * AC-13 eslint rule). Every network read in the app funnels through here and is
 * ultimately invoked from a TanStack Query `queryFn`.
 *
 * Conventions mirror the existing app's frontend/ui/src/api/client.ts:
 *   - credentials: 'include' so the enceladus_id_token cookie (SameSite=None)
 *     is sent for Lambda@Edge auth.
 *   - cache: 'no-store' — reads are always fresh at the transport layer;
 *     freshness is managed by TanStack Query staleTime, not the HTTP cache.
 *   - accept + x-requested-with default headers.
 *   - 401 -> SessionExpiredError, 404 -> NotFoundError.
 */

import type { HybridGraphsearchResponse, HybridSearchParams } from '../types/search'
import type { UserPreferences } from '../types/userPreferences'

/**
 * Read API base URL. Defaults to `/api/v1`, matching the existing app's
 * `normalizeApiBaseUrl(import.meta.env.VITE_API_BASE_URL)` default in
 * frontend/ui/src/api/projects.ts. The tracker/document sub-paths are derived
 * from this base below.
 */
export const API_BASE = normalizeApiBase(import.meta.env.VITE_API_BASE)

function normalizeApiBase(value: string | undefined): string {
  const raw = (value ?? '/api/v1').trim()
  if (!raw) return '/api/v1'
  const withLeadingSlash = raw.startsWith('/') || /^https?:\/\//.test(raw) ? raw : `/${raw}`
  return withLeadingSlash.replace(/\/+$/, '')
}

export class SessionExpiredError extends Error {
  constructor(message = 'Session expired') {
    super(message)
    this.name = 'SessionExpiredError'
  }
}

export class NotFoundError extends Error {
  readonly status = 404
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

/** Graph index unavailable (503 GRAPH_UNAVAILABLE) — fall back to local/tracker reads. */
export class GraphUnavailableError extends Error {
  readonly status = 503
  readonly fallbackHint?: string
  constructor(message: string, fallbackHint?: string) {
    super(message)
    this.name = 'GraphUnavailableError'
    this.fallbackHint = fallbackHint
  }
}

function withDefaultHeaders(input: HeadersInit | undefined): Headers {
  const headers = new Headers(input)
  if (!headers.has('accept')) headers.set('accept', 'application/json')
  if (!headers.has('x-requested-with')) headers.set('x-requested-with', 'XMLHttpRequest')
  return headers
}

interface FetchInit {
  signal?: AbortSignal
  headers?: HeadersInit
}

async function requestJson<T>(url: string, init?: FetchInit): Promise<T> {
  const res = await fetch(url, {
    signal: init?.signal,
    headers: withDefaultHeaders(init?.headers),
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`Not found: ${url}`)
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`)
  return (await res.json()) as T
}

/**
 * Tracker record fetch — task / issue / feature / plan / lesson.
 * Path convention (from frontend/ui/src/api/tracker.ts):
 *   `${API_BASE}/tracker/{projectId}/{recordType}/{recordId}`.
 * The backend envelopes the record as `{ record: T }`; unwrap with a fallback
 * to the raw body for parity with the legacy fetcher.
 */
export async function fetchTrackerRecord<T>(
  recordType: 'task' | 'issue' | 'feature' | 'plan' | 'lesson',
  projectId: string,
  recordId: string,
  init?: FetchInit,
): Promise<T> {
  const url = `${API_BASE}/tracker/${encodeURIComponent(projectId)}/${recordType}/${encodeURIComponent(recordId)}`
  const body = await requestJson<{ record?: T } & Record<string, unknown>>(url, init)
  return (body.record ?? (body as unknown)) as T
}

/**
 * Session probe (ENC-TSK-K98 — hard auth gate). Hits an authenticated read
 * route purely for its auth status so the app can gate on load: a live session
 * resolves, a 401 throws SessionExpiredError. `/projects` is a lightweight
 * authed list endpoint; the body is intentionally ignored. Any non-401 failure
 * still throws (the gate fails closed — no session confirmed, no app).
 */
export async function probeSession(init?: FetchInit): Promise<void> {
  await requestJson<unknown>(`${API_BASE}/projects`, init)
}

/**
 * Document fetch. Path convention (from frontend/ui/src/api/documents.ts):
 *   `${API_BASE}/documents/{documentId}`.
 * Backend envelopes as `{ document: T }`.
 */
export async function fetchDocumentRecord<T>(
  documentId: string,
  init?: FetchInit,
): Promise<T> {
  const url = `${API_BASE}/documents/${encodeURIComponent(documentId)}`
  const body = await requestJson<{ document?: T } & Record<string, unknown>>(url, init)
  return (body.document ?? (body as unknown)) as T
}

/**
 * User preferences (FTR-127 AC-10/16/17 / ENC-TSK-L25). GET/PUT
 * /api/v1/user/preferences, Cognito-session-authed, server canonical for
 * cross-device sync (offline mirror lives in src/sync/userPreferencesCache.ts).
 */
export async function fetchUserPreferences(init?: FetchInit): Promise<UserPreferences> {
  return requestJson<UserPreferences>(`${API_BASE}/user/preferences`, init)
}

export async function saveUserPreferences(
  preferences: UserPreferences,
  init?: FetchInit,
): Promise<UserPreferences> {
  const res = await fetch(`${API_BASE}/user/preferences`, {
    method: 'PUT',
    signal: init?.signal,
    headers: withDefaultHeaders({ ...init?.headers, 'content-type': 'application/json' }),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(preferences),
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${API_BASE}/user/preferences`)
  return (await res.json()) as UserPreferences
}

/**
 * Hybrid graphsearch (FTR-127 / ENC-TSK-L22). Live gamma endpoint:
 * GET /api/v1/tracker/graphsearch?search_type=hybrid&project_id=...
 */
export async function fetchHybridGraphsearch(
  params: HybridSearchParams,
  init?: FetchInit,
): Promise<HybridGraphsearchResponse> {
  const qs = new URLSearchParams({
    search_type: 'hybrid',
    project_id: params.projectId,
  })
  if (params.query?.trim()) qs.set('query', params.query.trim())
  if (params.anchorRecordId?.trim()) qs.set('anchor_record_id', params.anchorRecordId.trim())
  if (params.recordType) qs.set('record_type', params.recordType)
  if (params.topN != null) qs.set('top_n', String(params.topN))
  if (params.includeBelowThreshold) qs.set('include_below_threshold', 'true')

  const url = `${API_BASE}/tracker/graphsearch?${qs.toString()}`
  const res = await fetch(url, {
    signal: init?.signal,
    headers: withDefaultHeaders(init?.headers),
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`Not found: ${url}`)
  if (res.status === 503) {
    const body = (await res.json().catch(() => ({}))) as { message?: string; fallback_hint?: string }
    throw new GraphUnavailableError(
      body.message ?? 'Graph index temporarily unavailable',
      body.fallback_hint,
    )
  }
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`)
  return (await res.json()) as HybridGraphsearchResponse
}
