/**
 * ENC-TSK-S99-0B (ENC-PLN-108 W4.2): recompute only the plans whose rows actually changed.
 *
 * DOC-5E1E205FA664 sections 5.6 and 5.8. `buildPlanView` is pure and reasonably cheap for one plan, but the page
 * draws twenty of them and hands each the WHOLE corpus, and the corpus array gets a new identity on every heal --
 * so a single delta carrying one changed task rebuilt twenty cards over about ten thousand rows each. That is the
 * cost that criteria 4, 5 and 12 are really about: a checkout has to land on an open page in seconds without the
 * page doing a full rebuild every time any row anywhere moves.
 *
 * Two pieces make that possible:
 *
 *   1. An AFFECTED-ROW INDEX, built in one pass: for each plan, the ids of the rows that can change its card -- its
 *      own row, its objectives, and their descendants by `parent`. A row outside that set cannot reach the card, so
 *      it cannot invalidate it.
 *   2. A CONTENT SIGNATURE over exactly the fields the lens reads, so a cache hit means "this card would be drawn
 *      identically", not "the array happens to be the same object".
 *
 * Why the signature is not simply the row's `version`, which would be the obvious choice: a live AppSync event is
 * applied to the stored row as a headline overlay and DELIBERATELY KEEPS the existing version token (corpusSource:
 * "unchanged version token: the event is a headline overlay, not a newer server version"), while changing `status`.
 * A version-keyed cache would therefore swallow the one update the page exists to show -- the live checkout of
 * criterion 4 -- and a page fed by events would drift from a cold load, which is criterion 14. So the signature
 * names the fields instead, and they are the fields `buildPlanView`, `resolveWaves` and `waveState` actually read.
 *
 * The cache is module-level and keyed on content, which is the one kind of memo the React Compiler cannot do for us:
 * it memoises on input identity, and the input identity changes on every heal. It is also why this is safe under a
 * double render or a discarded concurrent render -- a hit and a miss produce the same value.
 */

import { buildPlanView, type PlanView, type PlansRow } from './planView'
import { toMs } from './format'
import type { TimeInput } from './lens/layoutTime'

/** Three pages of plans (PLAN_PAGE_SIZE is 20), so paging back and forth does not thrash. */
export const PLAN_VIEW_CACHE_MAX = 64

/**
 * Every field of a row that the lens reads, in a fixed order.
 *
 * Kept deliberately explicit rather than hashing the whole row: a field added to the corpus that the lens ignores
 * must NOT invalidate a card, and a field the lens starts reading must be added here in the same change. The unit
 * test pins that correspondence.
 */
export function rowSignature(row: PlansRow): string {
  return [
    row.item_id,
    row.record_type,
    row.title ?? '',
    row.project_id ?? '',
    row.status ?? '',
    row.checkout_state ?? '',
    row.parent ?? '',
    row.wave ?? '',
    (row.objectives_set ?? []).join(','),
    row.created_at ?? '',
    row.first_checked_out_at ?? '',
    row.closed_at ?? '',
  ].join('\u001f')
}

export interface AffectedIndex {
  byId: ReadonlyMap<string, PlansRow>
  /** Plan id -> the ids of every row that can affect that plan's card, including the plan itself. */
  affects: ReadonlyMap<string, readonly string[]>
}

/**
 * One pass over the corpus: the id map, the children map, then the closure under `parent` from each plan's
 * objectives.
 *
 * The closure is NOT depth-capped at the resolver's three levels. It is a superset on purpose: including a row the
 * resolver would have ignored only costs a cache miss that was not strictly necessary, while missing one would mean
 * drawing a stale card. Correctness buys the asymmetry.
 */
export function buildAffectedIndex(rows: readonly PlansRow[]): AffectedIndex {
  const byId = new Map<string, PlansRow>()
  const children = new Map<string, string[]>()
  const plans: PlansRow[] = []

  for (const row of rows) {
    if (!byId.has(row.item_id)) byId.set(row.item_id, row)
    const parent = row.parent
    if (parent && parent !== row.item_id) {
      const kids = children.get(parent)
      if (kids) kids.push(row.item_id)
      else children.set(parent, [row.item_id])
    }
    if (row.record_type.toLowerCase() === 'plan') plans.push(row)
  }

  const affects = new Map<string, readonly string[]>()
  for (const plan of plans) {
    const seen = new Set<string>([plan.item_id])
    // Breadth-first from the plan itself and each of its objectives; a cycle terminates because `seen` grows.
    const queue: string[] = [plan.item_id, ...(plan.objectives_set ?? [])]
    for (const id of queue) seen.add(id)
    for (let i = 0; i < queue.length; i += 1) {
      for (const kid of children.get(queue[i] as string) ?? []) {
        if (seen.has(kid)) continue
        seen.add(kid)
        queue.push(kid)
      }
    }
    affects.set(plan.item_id, [...seen].sort())
  }

  return { byId, affects }
}

/**
 * The signature of one card: the now edge, then every affecting row in a stable order.
 *
 * An affecting id with no row still contributes (as an empty signature), because an objective appearing or
 * disappearing from the corpus changes the card -- that is the `missing` count on the plan header.
 */
export function planSignature(planId: string, index: AffectedIndex, nowMs: number | null): string {
  const ids = index.affects.get(planId) ?? [planId]
  const parts: string[] = [`now=${nowMs ?? ''}`]
  for (const id of ids) {
    const row = index.byId.get(id)
    parts.push(row ? rowSignature(row) : `${id}\u001f-`)
  }
  return parts.join('\u001e')
}

interface Entry {
  sig: string
  view: PlanView
}

const cache = new Map<string, Entry>()

/** Test seam: the cache is module state, so a test that measures rebuilds has to be able to start from empty. */
export function resetPlanViewCache(): void {
  cache.clear()
}

/**
 * `buildPlanView`, memoised on content.
 *
 * `rows` is still passed whole and unsliced. Handing the builder a pre-filtered slice would be faster still, but the
 * resolver's membership rules are exactly what the slice would have to re-implement, and a slice that got them
 * subtly wrong would show up as a wrong card rather than a slow one. The index decides WHETHER to rebuild; it does
 * not decide what the rebuild sees.
 */
export function planViewOf(plan: PlansRow, rows: readonly PlansRow[], now: TimeInput, index: AffectedIndex): PlanView {
  const sig = planSignature(plan.item_id, index, toMs(now))
  const hit = cache.get(plan.item_id)
  if (hit && hit.sig === sig) return hit.view

  const view = buildPlanView(plan, rows, now)
  cache.set(plan.item_id, { sig, view })
  if (cache.size > PLAN_VIEW_CACHE_MAX) {
    // Map iterates in insertion order, so the first key is the least recently rebuilt.
    const oldest = cache.keys().next()
    if (!oldest.done) cache.delete(oldest.value)
  }
  return view
}

/**
 * The cards for the plans on screen.
 *
 * Not a hook: it reads no React state, holds nothing per component, and is called from render. Keeping it a plain
 * function is what lets the recompute behaviour be tested by counting rebuilds rather than by rendering.
 */
export function planViewsOf(plans: readonly PlansRow[], rows: readonly PlansRow[], now: TimeInput): PlanView[] {
  const index = buildAffectedIndex(rows)
  return plans.map((plan) => planViewOf(plan, rows, now, index))
}
