import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { NOW_TICK_MS, useNowTick } from './clock'

/**
 * ENC-TSK-S99-0B (ENC-PLN-108 W4.2): the now edge moves on a sixty second tick and does arithmetic only.
 *
 * The last test is the one that matters for criterion 12: the timer must issue no request. It is asserted by
 * stubbing `fetch` and showing it is never touched, which is the same property the ten-minute idle capture checks on
 * the live page -- here it is pinned where a future change would trip it immediately.
 */

let host: HTMLDivElement
let root: Root
let seen: number | null = null

function Probe({ periodMs }: { periodMs?: number }) {
  seen = useNowTick(periodMs)
  return null
}

const render = async (periodMs?: number) => {
  await act(async () => {
    root.render(<Probe periodMs={periodMs} />)
  })
}

beforeEach(() => {
  vi.useFakeTimers()
  seen = null
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})

afterEach(async () => {
  await act(async () => root.unmount())
  host.remove()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('useNowTick', () => {
  it('is one minute, per section 5.8', () => {
    expect(NOW_TICK_MS).toBe(60_000)
  })

  it('starts at the current instant', async () => {
    vi.setSystemTime(new Date('2026-11-19T22:00:00Z'))
    await render()
    expect(seen).toBe(Date.parse('2026-11-19T22:00:00Z'))
  })

  // Vitest's fake timers move the mocked Date with them, so advancing is both the clock and the tick.
  it('moves the edge on each period, and not between periods', async () => {
    const start = Date.parse('2026-11-19T22:00:00Z')
    vi.setSystemTime(new Date(start))
    await render()

    await act(async () => {
      vi.advanceTimersByTime(NOW_TICK_MS - 1)
    })
    expect(seen).toBe(start)

    await act(async () => {
      vi.advanceTimersByTime(1)
    })
    expect(seen).toBe(start + NOW_TICK_MS)

    await act(async () => {
      vi.advanceTimersByTime(NOW_TICK_MS)
    })
    expect(seen).toBe(start + 2 * NOW_TICK_MS)
  })

  it('clears its interval on unmount, so a navigation away leaves nothing running', async () => {
    const clear = vi.spyOn(globalThis, 'clearInterval')
    await render()
    await act(async () => root.unmount())
    expect(clear).toHaveBeenCalled()
    // Re-rendered in afterEach's unmount; make that a no-op.
    root = createRoot(document.createElement('div'))
  })

  /** Criterion 12: an idle Plans page issues only the application's heal deltas. This timer issues nothing. */
  it('does no I/O: ten minutes of ticks touch no fetch', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    await render()
    await act(async () => {
      vi.advanceTimersByTime(10 * 60_000)
    })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
