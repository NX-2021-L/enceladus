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
 *    `type`, in `mode=census` (ENC-TSK-Q17-0A / DOC-4408ED194817 §8). Scoped
 *    to record_type=task (the dominant checkoutable type), with
 *    `checkout_state_ne=checked_out` applied server-side inside the walk so
 *    the tile count and the Feed's OPEN_TASKS_SEARCH destination filter
 *    (HomeRoute.tsx) share the exact same checkout_state != checked_out
 *    exclusion -- the M36 tile-count == Feed-rows invariant. The census walk
 *    is bounded (CENSUS_MAX_RAW_PAGES / CENSUS_WALL_CLOCK_MS server-side) --
 *    `count_truncated` on the response surfaces a real undercount instead of
 *    the old silent one-page cap.
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

interface CensusResponse {
  success: boolean
  mode?: string
  count: number
  count_truncated?: boolean
  [key: string]: unknown
}

/** Exact-or-truncated count, per DOC-4408ED194817 §8 D3: a bounded
 * synchronous walk that reports honestly when it hits its page/wall-clock
 * budget instead of silently under-reporting. */
export interface CensusCount {
  count: number
  truncated: boolean
}

/** Open tasks not currently checked out by any agent session (i.e. eligible
 * to be picked up), via one bounded census call. See module docstring for
 * the task-only-type scope note.
 *
 * ENC-TSK-Q17-0A review fix (M36 invariant): the census walk now carries
 * `checkout_state_ne=checked_out` (applied server-side inside the walk, not
 * as a client-side post-filter), so the tile count and the Feed's
 * `OPEN_TASKS_SEARCH` destination filter (HomeRoute.tsx) apply the exact
 * same checkout_state != checked_out exclusion. Without this param the
 * bounded census counted checked-out tasks too, so the tile could show a
 * higher number than the Feed rows it links to. */
export async function fetchAwaitingCheckoutCount(
  projectId: string,
  init?: { signal?: AbortSignal },
): Promise<CensusCount> {
  const body = await getJson<CensusResponse>(
    `${API_BASE}/tracker/${encodeURIComponent(projectId)}?type=task&status=open&checkout_state_ne=checked_out&mode=census&page_size=100`,
    init,
  )
  return { count: body.count ?? 0, truncated: body.count_truncated === true }
}

/** ENC-TSK-P59 (ENC-ISS-725): cross-project awaiting-checkout count.
 *
 * The Home tile used to count ONE project (whichever sorted first in the
 * registry — agentharmony) while looking like a global number. The corpus
 * endpoint has no checkout_state filter, so exact truth is a per-project
 * fan-out over the tracker API, summed. Failed projects count 0 rather than
 * failing the whole tile. `truncated` is true when ANY project's census hit
 * its bound, so the tile can surface a real, honest undercount marker
 * (ENC-TSK-Q17-0A) instead of staying silent about one. */
export async function fetchAwaitingCheckoutCountAll(
  projectIds: string[],
  init?: { signal?: AbortSignal },
): Promise<CensusCount> {
  const counts = await Promise.all(
    projectIds.map((id) =>
      fetchAwaitingCheckoutCount(id, init).catch<CensusCount>(() => ({
        count: 0,
        truncated: false,
      })),
    ),
  )
  return counts.reduce(
    (acc, c) => ({ count: acc.count + c.count, truncated: acc.truncated || c.truncated }),
    { count: 0, truncated: false },
  )
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
