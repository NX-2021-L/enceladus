/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): diff, DOC-5E1E205FA664 section 5.6 item 5.
 *
 * The corpus store notifies without saying what changed (section 4 item 6), so the lens keeps the previous snapshot of
 * what it has drawn and computes the change set itself. `diff(previous, next)` returns that change set, typed: plan
 * added, task added, checkout, close, reopen, wave state change, wave hot change, reorder. It is the only input the
 * animation layer accepts (W4), and it is pure: equal snapshots give an empty set.
 *
 * Output order is deterministic: plans in `next` order; inside a plan the task events in `next` task order (task-added, then
 * checkout, close, reopen for each), then each wave in `next` order (state change, hot change, reorder).
 */
import { resolveWaves } from './resolveWaves'
import type { LensRow, ResolverRow } from './types'
import { isCheckedOut, waveStatus, type WaveState, type WaveTaskFacts } from './waveState'

export interface TaskSnapshot {
  id: string
  status: string | null
  /** The task has been checked out: first_checked_out_at, or the pre-backfill fallback of section 5.5. */
  checkedOut: boolean
}

export interface WaveSnapshot {
  key: string
  state: WaveState
  hot: boolean
  /** Member ids in drawn order. */
  members: readonly string[]
}

export interface PlanSnapshot {
  id: string
  waves: readonly WaveSnapshot[]
  /** Every task row of the plan: wave parents, members and Unassigned. */
  tasks: readonly TaskSnapshot[]
}

/** What the lens drew, per plan. */
export type LensSnapshot = readonly PlanSnapshot[]

export type LensChange =
  | { type: 'plan-added'; planId: string }
  | { type: 'task-added'; planId: string; taskId: string; /** The wave of `next` that holds it; null when it is a wave parent or Unassigned. */ waveKey: string | null }
  | { type: 'checkout'; planId: string; taskId: string }
  | { type: 'close'; planId: string; taskId: string }
  | { type: 'reopen'; planId: string; taskId: string }
  | { type: 'wave-state-change'; planId: string; waveKey: string; from: WaveState; to: WaveState }
  | { type: 'wave-hot-change'; planId: string; waveKey: string; hot: boolean }
  | { type: 'reorder'; planId: string; waveKey: string; /** The wave's members in their new order. */ order: readonly string[] }

export type LensChangeType = LensChange['type']

export const LENS_CHANGE_TYPES: readonly LensChangeType[] = [
  'plan-added',
  'task-added',
  'checkout',
  'close',
  'reopen',
  'wave-state-change',
  'wave-hot-change',
  'reorder',
]

const isClosed = (status: string | null | undefined): boolean => (status ?? '').trim().toLowerCase() === 'closed'

/** What `snapshotPlan` reads of a row: the resolver's fields plus the task facts of waveState. */
export type SnapshotRow = ResolverRow & WaveTaskFacts

/**
 * The Unassigned group's wave key. It must equal `UNASSIGNED_KEY` in planView.ts, which is what the page keys the
 * group with; diff.ts cannot import it without a cycle, so the two are pinned equal by a test.
 *
 * ENC-TSK-S99-0A: the Unassigned group is drawn as a wave -- its own header, tally, collapse and done role -- so it
 * has to BEHAVE as one. Before this it was snapshotted only as loose tasks, so it never produced a
 * wave-state-change, wave-hot-change or reorder, and the completion hold could never fire for it. That is not an
 * edge case: the gamma corpus is mostly plans whose objectives carry no wave label and no parent (ENC-TSK-T15), so
 * Unassigned is the common wave, not the rare one.
 */
export const UNASSIGNED_WAVE_KEY = 'unassigned'

/** Resolves a plan and derives the per-wave state the page draws, as a snapshot to diff against the next one. */
export function snapshotPlan(plan: Pick<LensRow, 'item_id' | 'objectives_set'>, rows: readonly SnapshotRow[]): PlanSnapshot {
  const resolved = resolveWaves(plan, rows)
  const byId = new Map<string, SnapshotRow>()
  for (const row of rows) if (!byId.has(row.item_id)) byId.set(row.item_id, row)
  const facts = (id: string): WaveTaskFacts => byId.get(id) ?? {}

  const waves: WaveSnapshot[] = resolved.waves.map((w) => {
    const status = waveStatus({ parent: w.parent_id ? facts(w.parent_id) : null, members: w.members.map(facts) })
    return { key: w.key, state: status.state, hot: status.hot, members: w.members }
  })

  if (resolved.unassigned.length > 0) {
    const status = waveStatus({ parent: null, members: resolved.unassigned.map(facts) })
    waves.push({ key: UNASSIGNED_WAVE_KEY, state: status.state, hot: status.hot, members: resolved.unassigned })
  }

  const ids: string[] = []
  const seen = new Set<string>()
  const add = (id: string): void => {
    if (!seen.has(id)) {
      seen.add(id)
      ids.push(id)
    }
  }
  for (const w of resolved.waves) {
    if (w.parent_id) add(w.parent_id)
    w.members.forEach(add)
  }
  resolved.unassigned.forEach(add)

  return {
    id: plan.item_id,
    waves,
    tasks: ids.map((id) => ({ id, status: facts(id).status ?? null, checkedOut: isCheckedOut(facts(id)) })),
  }
}

const sameOrder = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i])

/** The typed change set from `previous` to `next`. Plans and tasks that disappear produce no change: nothing animates them. */
export function diff(previous: LensSnapshot, next: LensSnapshot): LensChange[] {
  const before = new Map(previous.map((p) => [p.id, p]))
  const changes: LensChange[] = []

  for (const plan of next) {
    const was = before.get(plan.id)
    // A new plan enters as a card; its tasks and waves arrive with it and raise no events of their own.
    if (!was) {
      changes.push({ type: 'plan-added', planId: plan.id })
      continue
    }

    const wasTasks = new Map(was.tasks.map((t) => [t.id, t]))
    const waveOf = new Map<string, string>()
    for (const w of plan.waves) for (const m of w.members) waveOf.set(m, w.key)

    for (const task of plan.tasks) {
      const old = wasTasks.get(task.id)
      if (!old) {
        changes.push({ type: 'task-added', planId: plan.id, taskId: task.id, waveKey: waveOf.get(task.id) ?? null })
        continue
      }
      if (!old.checkedOut && task.checkedOut) changes.push({ type: 'checkout', planId: plan.id, taskId: task.id })
      if (!isClosed(old.status) && isClosed(task.status)) changes.push({ type: 'close', planId: plan.id, taskId: task.id })
      if (isClosed(old.status) && !isClosed(task.status)) changes.push({ type: 'reopen', planId: plan.id, taskId: task.id })
    }

    const wasWaves = new Map(was.waves.map((w) => [w.key, w]))
    for (const wave of plan.waves) {
      const old = wasWaves.get(wave.key)
      if (!old) continue
      if (old.state !== wave.state) changes.push({ type: 'wave-state-change', planId: plan.id, waveKey: wave.key, from: old.state, to: wave.state })
      if (old.hot !== wave.hot) changes.push({ type: 'wave-hot-change', planId: plan.id, waveKey: wave.key, hot: wave.hot })
      // Reorder is the relative order of the rows present on both sides: a row that joined or left is not a move.
      const now = new Set(wave.members)
      const before2 = new Set(old.members)
      const keptBefore = old.members.filter((m) => now.has(m))
      const keptNow = wave.members.filter((m) => before2.has(m))
      if (!sameOrder(keptBefore, keptNow)) changes.push({ type: 'reorder', planId: plan.id, waveKey: wave.key, order: wave.members })
    }
  }
  return changes
}
