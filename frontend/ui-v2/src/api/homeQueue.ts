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
 * have NO PWA-reachable data source today: GitHub Actions Environment
 * protection state and worktree/session-lock bookkeeping (ENC-ISS-071) are
 * not exposed by any Enceladus HTTP API. HomeRoute renders those two queue
 * rows as static gap notices (see routes/homeQueue.ts::GAP_QUEUE_ROWS)
 * instead of fabricating a fetch or a backend endpoint.
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
