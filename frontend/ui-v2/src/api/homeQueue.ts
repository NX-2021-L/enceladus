/**
 * Home "Requires io" queue + actionable-counts data (ENC-TSK-M19 / UX-B1 /
 * FND-HOME). Consumes existing backend surfaces only -- no new endpoints:
 *
 *  - Escalations: reuses `fetchEscalations` (src/api/coordination.ts), the
 *    same fetcher the Escalations tab on /coordination already calls.
 *  - "Open P0/P1": GET /api/v1/feed/corpus (ENC-TSK-L23) already accepts
 *    `status` + `priority` querystring filters server-side
 *    (backend/lambda/feed_query/corpus.py::parse_corpus_query /
 *    _matches_filters) and returns `total_matches` computed over the full
 *    filtered set *before* the `limit` slice -- so a `limit:1` request is an
 *    exact, cheap count. Mirrors the pattern already used by
 *    api/feedCorpusQueryOptions.ts's `feedCorpusByTypeQueryOptions`.
 *  - "Awaiting checkout": reuses the generic tracker list route
 *    (GET /api/v1/tracker/{project}?type=...&status=...) that
 *    api/coordination.ts's `fetchLessons` already calls with a different
 *    `type`. Scoped to record_type=task (the dominant checkoutable type) and
 *    one 200-row page -- a known, intentional undercount rather than N extra
 *    per-type list requests for a single dashboard tile.
 *
 * Paused v3-prod GitHub Environment approvals and stale-lock/backfill flags
 * (ENC-TSK-M27 / ENC-FTR-130): now live, via the two read-only routes added
 * to coordination_api --
 *   GET /api/v1/coordination/queue/paused-approvals
 *   GET /api/v1/coordination/queue/stale-locks
 * Both are Cognito-session-gated, same as the escalations feed. See
 * backend/lambda/coordination_api/lambda_function.py::
 * _handle_queue_paused_approvals / _handle_queue_stale_locks.
 */

import { API_BASE } from './client'
import type { FeedCorpusPage } from '../sync/types'

async function getJson<T>(url: string, init?: { signal?: AbortSignal }): Promise<T> {
  const res = await fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
  })
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`)
  return (await res.json()) as T
}

/** Exact count of open P0/P1 tracker records across all projects. */
export async function fetchOpenP0P1Count(init?: { signal?: AbortSignal }): Promise<number> {
  const qs = new URLSearchParams({ status: 'open', priority: 'p0,p1', limit: '1' })
  const page = await getJson<FeedCorpusPage>(`${API_BASE}/feed/corpus?${qs.toString()}`, init)
  return page.total_matches ?? 0
}

interface AwaitingCheckoutRecord {
  checkout_state?: string
  [key: string]: unknown
}

interface TrackerListResponse {
  success: boolean
  records: AwaitingCheckoutRecord[]
  count: number
}

/** Open tasks not currently checked out by any agent session (i.e. eligible
 * to be picked up), capped at one 200-row page. See module docstring for the
 * task-only-type / single-page scope note. */
export async function fetchAwaitingCheckoutCount(
  projectId: string,
  init?: { signal?: AbortSignal },
): Promise<number> {
  const body = await getJson<TrackerListResponse>(
    `${API_BASE}/tracker/${encodeURIComponent(projectId)}?type=task&status=open&page_size=200`,
    init,
  )
  const records = body.records ?? []
  return records.filter((r) => r.checkout_state !== 'checked_out').length
}

/** ENC-TSK-M27 AC1: a GitHub Actions run paused on the v3-prod Environment's
 * required-reviewer gate. */
export interface PausedApprovalRun {
  id: number | string
  run_url?: string
  requesting_workflow?: string
  environments?: string[]
  head_sha?: string
  created_at?: string
}

interface PausedApprovalsResponse {
  success: boolean
  runs: PausedApprovalRun[]
  count: number
  note?: string
}

/** Paused v3-prod Environment approval runs, live from GitHub Actions via the
 * coordination_api GitHub App installation-token path (ENC-FTR-021 reuse). */
export async function fetchPausedApprovals(
  init?: { signal?: AbortSignal },
): Promise<PausedApprovalRun[]> {
  const body = await getJson<PausedApprovalsResponse>(
    `${API_BASE}/coordination/queue/paused-approvals`,
    init,
  )
  return body.runs ?? []
}

/** ENC-TSK-M27 AC1: a checkout lock held past the stale-checkout threshold. */
export interface StaleLockEntry {
  record_id?: string
  holder_session?: string
  held_since?: string
  age_minutes?: number
}

interface StaleLocksResponse {
  success: boolean
  locks: StaleLockEntry[]
  count: number
  threshold_minutes?: number
}

/** Stale checkout-lock entries, live from the same projects-table scan the
 * scheduled stale_checkout_monitor Lambda already runs. */
export async function fetchStaleLocks(
  init?: { signal?: AbortSignal },
): Promise<StaleLockEntry[]> {
  const body = await getJson<StaleLocksResponse>(
    `${API_BASE}/coordination/queue/stale-locks`,
    init,
  )
  return body.locks ?? []
}
