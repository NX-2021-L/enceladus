import { act, useEffect } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { COMPLETION_HOLD_MS, usePlanMotion, type PlanMotion } from './motion'
import type { PlansRow } from './planView'

/**
 * ENC-TSK-S99-0A (ENC-PLN-108 W4.1). The transitions live in plans.css; this pins the one piece of motion that
 * cannot be derived from state — ruling D-10's completion hold.
 *
 * The rest of the motion list is deliberately NOT re-tested here, because it is not this module's behaviour:
 * checkout expanding a wave (criterion 8) and re-entry reopening one (criterion 11) are `expandedDefault` running
 * forwards and backwards, and reduced motion (criterion 16) is a single CSS rule removing every transition.
 */

const task = (id: string, status: string, extra: Partial<PlansRow> = {}): PlansRow => ({
  item_id: id,
  record_type: 'task',
  title: `${id} title`,
  project_id: 'enceladus',
  status,
  checkout_state: 'checked_in',
  created_at: '2026-11-01T00:00:00Z',
  ...extra,
})

const PLAN = { item_id: 'ENC-PLN-900', objectives_set: ['ENC-TSK-A', 'ENC-TSK-B'] }

/** Both objectives open: the wave is live. */
const OPEN_ROWS: PlansRow[] = [task('ENC-TSK-A', 'open'), task('ENC-TSK-B', 'open')]
/** Both closed: the wave is done, which is what starts the hold. */
const DONE_ROWS: PlansRow[] = [
  task('ENC-TSK-A', 'closed', { closed_at: '2026-11-02T00:00:00Z' }),
  task('ENC-TSK-B', 'closed', { closed_at: '2026-11-02T01:00:00Z' }),
]

let host: HTMLDivElement
let root: Root
let clock = 0
const now = () => clock

/**
 * The probe publishes through a stable outer box rather than reassigning an outer binding: the React Compiler lint
 * rejects a component that writes to a variable declared outside it, and a box keeps every assertion below unchanged.
 */
/**
 * The probe publishes through a module-level setter called from an effect, not by assigning an outer binding from the
 * component body: react-hooks/immutability and the React Compiler lint both reject the latter. Every assertion below
 * is unchanged -- `act()` flushes the effect, so the value is in place by the time the test reads it.
 */
let seen: PlanMotion | null = null
const publish = (v: PlanMotion): void => {
  seen = v
}

function Probe({ rows }: { rows: readonly PlansRow[] }) {
  const motion = usePlanMotion({ plans: [PLAN], rows, now })
  useEffect(() => {
    publish(motion)
  }, [motion])
  return null
}

const render = async (rows: readonly PlansRow[]) => {
  await act(async () => {
    root.render(<Probe rows={rows} />)
  })
}

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.useFakeTimers()
  clock = 1_000_000
  seen = null
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})

afterEach(async () => {
  await act(async () => root.unmount())
  host.remove()
  vi.useRealTimers()
})

describe('usePlanMotion: the completion hold (ruling D-10)', () => {
  it('treats the first snapshot as a baseline, so a cold load animates nothing', async () => {
    await render(DONE_ROWS)
    expect(seen!.changes).toEqual([])
    expect(seen!.heldOpen.size).toBe(0)
  })

  it('holds a wave open when it finishes, so the finish is visible at all', async () => {
    await render(OPEN_ROWS)
    expect(seen!.heldOpen.size).toBe(0)

    await render(DONE_ROWS)

    const kinds = seen!.changes.map((c) => c.type)
    expect(kinds).toContain('wave-state-change')
    // Keyed as PlanView keys its waves, `<plan id>/<wave key>`, which is what the card asks with.
    expect([...seen!.heldOpen].every((k) => k.startsWith('ENC-PLN-900/'))).toBe(true)
    expect(seen!.heldOpen.size).toBeGreaterThan(0)
  })

  it('releases the hold after one second, and not before', async () => {
    await render(OPEN_ROWS)
    await render(DONE_ROWS)
    expect(seen!.heldOpen.size).toBeGreaterThan(0)

    // Just short of the hold: still open.
    clock += COMPLETION_HOLD_MS - 1
    await act(async () => {
      vi.advanceTimersByTime(COMPLETION_HOLD_MS - 1)
    })
    expect(seen!.heldOpen.size).toBeGreaterThan(0)

    // Past it: the wave is released and collapses by the ordinary rule.
    clock += 2
    await act(async () => {
      vi.advanceTimersByTime(2)
    })
    expect(seen!.heldOpen.size).toBe(0)
  })

  it('does not hold anything when a task is merely checked out', async () => {
    await render(OPEN_ROWS)
    await render([task('ENC-TSK-A', 'open', { checkout_state: 'checked_out', first_checked_out_at: '2026-11-01T06:00:00Z' }), task('ENC-TSK-B', 'open')])

    expect(seen!.changes.map((c) => c.type)).toContain('checkout')
    // A checkout opens its wave through expandedDefault, not through a hold.
    expect(seen!.heldOpen.size).toBe(0)
  })

  it('a re-entered task produces a reopen change and no hold', async () => {
    await render(DONE_ROWS)
    await render([task('ENC-TSK-A', 'open'), DONE_ROWS[1] as PlansRow])

    expect(seen!.changes.map((c) => c.type)).toContain('reopen')
    expect(seen!.heldOpen.size).toBe(0)
  })
})
