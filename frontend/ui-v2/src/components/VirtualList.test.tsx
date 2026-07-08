import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { VirtualList } from './VirtualList'
import { VIRTUALIZE_ROW_THRESHOLD } from './virtualListThreshold'

/**
 * No @testing-library/react in this package (see SessionPrimitive.test.tsx)
 * — createRoot + act smoke tests only. jsdom has no real layout engine
 * (clientHeight/scrollTop are always 0), so this deliberately does NOT
 * assert exact visible-row counts from @tanstack/react-virtual's windowing
 * math — it asserts the two behaviors ENC-TSK-M18 AC-3 actually cares
 * about: (1) small lists render every row untouched, (2) large lists engage
 * the windowed scroll container instead of mounting every row's DOM node.
 */

type Row = { id: string; label: string }

function makeRows(count: number): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: `row-${i}`, label: `Row ${i}` }))
}

describe('VirtualList', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('renders every row directly when at/under the threshold (no scroll container)', () => {
    const rows = makeRows(VIRTUALIZE_ROW_THRESHOLD)
    act(() => {
      root.render(
        <VirtualList
          items={rows}
          getKey={(r) => r.id}
          renderItem={(r) => <span data-testid="row">{r.label}</span>}
        />,
      )
    })

    expect(container.querySelectorAll('[data-testid="row"]').length).toBe(
      VIRTUALIZE_ROW_THRESHOLD,
    )
    expect(container.querySelector('[data-testid="virtual-list-scroll"]')).toBeNull()
  })

  it('engages the windowed scroll container above the threshold (AC-3: >30 rows)', () => {
    const rows = makeRows(200)
    act(() => {
      root.render(
        <VirtualList
          items={rows}
          getKey={(r) => r.id}
          renderItem={(r) => <span data-testid="row">{r.label}</span>}
        />,
      )
    })

    const scrollEl = container.querySelector('[data-testid="virtual-list-scroll"]')
    expect(scrollEl).not.toBeNull()

    // The whole point of AC-3: the DOM must not hold all 200 rows at once.
    const renderedRows = container.querySelectorAll('[data-testid="row"]').length
    expect(renderedRows).toBeLessThan(rows.length)
  })
})
