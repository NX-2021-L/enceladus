/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): selectPlans, DOC-5E1E205FA664 section 5.6 item 1.
 *
 * Returns plan rows ordered by created_at descending (R5), the newest page first and older pages on demand (decision D-9).
 * Pure: no I/O, no clock. One filter in version 1, the project (decision D-8).
 *
 * A plan with no usable created_at sorts after every dated plan, and ties break on item_id descending (numeric-aware), so the
 * order is total and the same input always gives the same page. `updated_at` is deliberately not a fallback: R5 is creation
 * order, and a recently touched old plan must not jump to the top.
 */
import type { LensRow } from './types'

/** Decision D-9: the newest 20 plans, older pages on demand. */
export const PLAN_PAGE_SIZE = 20

export interface PlanFilter {
  /** Project id; null, undefined and the empty string all mean All projects. */
  project?: string | null
  /** How many plans to show: the first page is PLAN_PAGE_SIZE, and each older page adds PLAN_PAGE_SIZE. */
  count?: number
}

export interface PlanSelection {
  /** The visible plans, newest first. */
  plans: LensRow[]
  /** Plans matching the filter, shown or not. */
  total: number
  /** Matching plans not yet shown. */
  remaining: number
  hasMore: boolean
}

const createdMs = (row: LensRow): number => {
  const t = row.created_at ? Date.parse(row.created_at) : Number.NaN
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t
}

const byNewest = (a: LensRow, b: LensRow): number => {
  const ta = createdMs(a)
  const tb = createdMs(b)
  if (ta !== tb) return ta === Number.NEGATIVE_INFINITY ? 1 : tb === Number.NEGATIVE_INFINITY ? -1 : tb - ta
  return b.item_id.localeCompare(a.item_id, 'en', { numeric: true })
}

/** The next visible count after a click on "show older plans". */
export const nextPlanCount = (count: number | undefined): number => (count ?? PLAN_PAGE_SIZE) + PLAN_PAGE_SIZE

export function selectPlans(corpus: readonly LensRow[], filter: PlanFilter = {}): PlanSelection {
  const project = filter.project ? filter.project : null
  const count = Math.max(0, Math.floor(filter.count ?? PLAN_PAGE_SIZE))
  const matching = corpus
    .filter((row) => row.record_type.toLowerCase() === 'plan' && (project === null || row.project_id === project))
    .sort(byNewest)
  const plans = matching.slice(0, count)
  return { plans, total: matching.length, remaining: matching.length - plans.length, hasMore: matching.length > plans.length }
}
