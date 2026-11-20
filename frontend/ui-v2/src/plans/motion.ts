/**
 * ENC-TSK-S99-0A (ENC-PLN-108 W4.1): the change set drives the motion.
 *
 * DOC-5E1E205FA664 section 5.7 and the canvas motion table. The transitions themselves are already declared in
 * plans.css with design-system durations and easing and no keyframes, and one `prefers-reduced-motion` rule there
 * removes every one of them. This module supplies only what CSS cannot derive: the parts that depend on what
 * CHANGED rather than on what the state now is.
 *
 * Most of the motion list needs nothing here, and saying why matters more than code:
 *
 *   - Checkout expanding a collapsed wave (criterion 8) already falls out of the lens. A checkout makes the wave
 *     hot, `expandedDefault` opens a hot, not-done wave of a started plan, and `.pl-body` animates its
 *     grid-template-rows. A stale manual override cannot pin it shut because D-3 discards an override once the
 *     state or hotness it was made under has changed.
 *   - Re-entering a closed task (criterion 11) is the same rule running backwards: the wave leaves `done`, becomes
 *     hot again, and reopens.
 *
 * What does NOT fall out is the completion hold. The moment a wave's last task closes it becomes `done`, and
 * `expandedDefault` would collapse it in the same frame that its header turns to the done role -- so the one thing
 * io asked to see, the wave finishing, would never be visible. Ruling D-10 gives it a one second hold. That is a
 * fact about a transition, not about state, so it has to be held here.
 */

import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { diff, snapshotPlan, type LensChange, type LensSnapshot, type SnapshotRow } from './lens/diff'
import type { PlansRow } from './planView'

/** Ruling D-10: a wave that has just finished stays open this long before it collapses. */
export const COMPLETION_HOLD_MS = 1000

export interface PlanMotion {
  /** Wave keys held open by the completion hold; the card ORs this with its own open rule. */
  heldOpen: ReadonlySet<string>
  /** The latest change set. Exposed so a view can react to a reorder, and so tests can assert the wiring. */
  changes: readonly LensChange[]
}

const EMPTY: ReadonlySet<string> = new Set<string>()

/**
 * `key` is the wave key as `diff` reports it (plan-local). `PlanView` keys waves as `<plan id>/<wave key>`, so the
 * hold is recorded under the same composite the card asks with.
 */
const holdKey = (planId: string, waveKey: string): string => `${planId}/${waveKey}`

export interface UsePlanMotionArgs {
  /** The plans currently on screen, in display order. */
  plans: readonly Pick<PlansRow, 'item_id' | 'objectives_set'>[]
  /** Every row the page may draw; snapshots are taken from these. */
  rows: readonly PlansRow[]
  /** Injected in tests. Production passes nothing and gets the real timers. */
  now?: () => number
  holdMs?: number
}

export function usePlanMotion({ plans, rows, now = Date.now, holdMs = COMPLETION_HOLD_MS }: UsePlanMotionArgs): PlanMotion {
  // No useMemo: the React Compiler is active and memoizes this on [plans, rows] (eslint AC-16). The identity still
  // has to be stable, because the effect below keys on it to decide what CHANGED -- motion.test.tsx covers that.
  const snapshot: LensSnapshot = plans.map((p) => snapshotPlan(p, rows as readonly SnapshotRow[]))

  const previous = useRef<LensSnapshot | null>(null)
  const [changes, setChanges] = useState<readonly LensChange[]>([])
  // waveKey -> the instant the hold expires.
  const [holds, setHolds] = useState<ReadonlyMap<string, number>>(() => new Map())

  useEffect(() => {
    const before = previous.current
    previous.current = snapshot
    // The first snapshot is the baseline, not a change: a cold load must not animate the whole page.
    if (before === null) return
    const next = diff(before, snapshot)
    if (next.length === 0) return
    setChanges(next)

    const finished: string[] = []
    for (const c of next) {
      if (c.type === 'wave-state-change' && c.to === 'done') finished.push(holdKey(c.planId, c.waveKey))
    }
    if (finished.length === 0) return
    const until = now() + holdMs
    setHolds((prev) => {
      const out = new Map(prev)
      for (const k of finished) out.set(k, until)
      return out
    })
  }, [snapshot, now, holdMs])

  // One timer per expiry, cleared on unmount. A wave that finishes again while held simply extends its own entry.
  useEffect(() => {
    if (holds.size === 0) return
    const soonest = Math.min(...holds.values())
    const delay = Math.max(0, soonest - now())
    const t = setTimeout(() => {
      const cutoff = now()
      setHolds((prev) => {
        const out = new Map<string, number>()
        for (const [k, at] of prev) if (at > cutoff) out.set(k, at)
        return out.size === prev.size ? prev : out
      })
    }, delay)
    return () => clearTimeout(t)
  }, [holds, now])

  const heldOpen: ReadonlySet<string> = holds.size === 0 ? EMPTY : new Set(holds.keys())

  return { heldOpen, changes }
}

/** Rows carry this so FLIP can follow one across a reorder. */
export const FLIP_KEY_ATTR = 'data-flip-key'

const prefersReducedMotion = (): boolean => {
  try {
    return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    // jsdom and older engines have no matchMedia; treat that as "motion allowed" and let the CSS rule decide.
    return false
  }
}

/**
 * FLIP reorder for the task rows of a wave (ENC-TSK-S99-0A).
 *
 * CSS cannot transition a reflow: when `order` changes the rows jump to their new places in one frame. FLIP takes
 * the First position, lets the DOM land on the Last, Inverts the difference as a transform and plays it back, so
 * the row appears to travel.
 *
 * Deliberately matched to the rest of the page's motion:
 *   - it reads the design system's own duration and easing from the element, so it cannot drift from plans.css;
 *   - it does nothing at all under prefers-reduced-motion, which is criterion 16 -- the row still MOVES, it simply
 *     arrives without the travel;
 *   - it animates only rows that actually moved, so a re-render that changes nothing costs one measurement pass.
 */
export function useFlipRows(container: { current: HTMLElement | null }, order: readonly string[]): void {
  const previous = useRef<Map<string, DOMRect> | null>(null)

  useLayoutEffect(() => {
    const root = container.current
    if (!root) return

    const rows = Array.from(root.querySelectorAll<HTMLElement>(`[${FLIP_KEY_ATTR}]`))
    const current = new Map<string, DOMRect>()
    for (const row of rows) {
      const key = row.getAttribute(FLIP_KEY_ATTR)
      if (key) current.set(key, row.getBoundingClientRect())
    }

    const before = previous.current
    previous.current = current
    if (!before || prefersReducedMotion()) return

    for (const row of rows) {
      const key = row.getAttribute(FLIP_KEY_ATTR)
      if (!key) continue
      const from = before.get(key)
      const to = current.get(key)
      if (!from || !to) continue
      const dy = from.top - to.top
      // Sub-pixel noise is not a move; animating it would fight the layout on every render.
      if (Math.abs(dy) < 1) continue

      row.style.transition = 'none'
      row.style.transform = `translateY(${dy}px)`
      // Force the inverted position to be the one the browser starts from.
      void row.offsetHeight
      row.style.transition = ''
      row.style.transform = ''
    }
  }, [container, order])
}
