/**
 * Plan-scoped read — GET /api/v1/feed/plan-scope (ENC-TSK-T05, ENC-PLN-108 W2.6).
 *
 * Ruling D-26 keeps the three lifecycle TIMESTAMPS off the corpus row: on 12,576 rows they were about 89 percent of
 * the widening's cost. They ride this route instead, which serves the newest twenty plans (decision D-9) and the
 * task rows of their trees THROUGH the same `build_tracker_entry` the corpus uses, at `scope=plan`. One row
 * contract, two scopes — a row from here and a row from the corpus have the same shape, which is the whole point of
 * P-4 and why the slim-corpus option was refused.
 *
 * Called ONCE per Plans page open, by `usePlansLens`, and by no other route (ENC-TSK-T05 AC-4). `parent` and
 * `objectives_set` are already on corpus rows (D-28), so the page draws complete wave STRUCTURE before this read
 * lands; this read only fills in the time scale.
 */

import { API_BASE, SessionExpiredError } from './client'

/** One row as the route returns it: the corpus row shape, at plan scope. */
export interface PlanScopeItem {
  record_id: string
  record_type: string
  project_id?: string | null
  title?: string | null
  updated_at?: string | null
  attrs?: Record<string, unknown> | null
}

export interface PlanScopeResponse {
  success: boolean
  generated_at?: string
  scope?: string
  page_size?: number
  total_plans?: number
  plan_count?: number
  task_count?: number
  /** The tree walk hit a bound (depth or task count) and the answer is partial. */
  truncated?: boolean
  items?: PlanScopeItem[]
}

export class PlanScopeFetchError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'PlanScopeFetchError'
    this.status = status
  }
}

/** The three facts this route exists to deliver, keyed by record id. */
export interface PlanScopeTimes {
  created_at?: string | null
  first_checked_out_at?: string | null
  closed_at?: string | null
}

export interface PlanScopeResult {
  times: ReadonlyMap<string, PlanScopeTimes>
  truncated: boolean
  generatedAt: string | null
  totalPlans: number | null
}

const text = (v: unknown): string | null => {
  if (typeof v !== 'string') return null
  const t = v.trim()
  return t ? t : null
}

/**
 * Fetch the plan-scoped read and reduce it to the timestamp overlay the lens needs.
 *
 * Only the three timestamps are taken. Everything else on these rows — title, status, parent, wave, objectives_set —
 * is deliberately ignored in favour of the corpus copy, so there is exactly one source of truth for structure and
 * this route cannot drift the page's wave resolution.
 */
export async function fetchPlanScope(init?: { signal?: AbortSignal; project?: string }): Promise<PlanScopeResult> {
  const qs = init?.project ? `?project=${encodeURIComponent(init.project)}` : ''
  const res = await fetch(`${API_BASE}/feed/plan-scope${qs}`, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new PlanScopeFetchError(res.status, `Failed to read plan scope (${res.status})`)
  const body = (await res.json()) as PlanScopeResponse

  const times = new Map<string, PlanScopeTimes>()
  for (const item of body.items ?? []) {
    const id = text(item.record_id)
    if (!id) continue
    const attrs = item.attrs ?? {}
    const entry: PlanScopeTimes = {}
    const created = text(attrs.created_at)
    const firstOut = text(attrs.first_checked_out_at)
    const closed = text(attrs.closed_at)
    if (created) entry.created_at = created
    if (firstOut) entry.first_checked_out_at = firstOut
    if (closed) entry.closed_at = closed
    // An empty entry still records "this row was in scope", which is not useful; skip it so the overlay stays small.
    if (Object.keys(entry).length > 0) times.set(id, entry)
  }

  return {
    times,
    truncated: body.truncated === true,
    generatedAt: text(body.generated_at),
    totalPlans: typeof body.total_plans === 'number' ? body.total_plans : null,
  }
}
