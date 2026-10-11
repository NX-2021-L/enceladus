import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { countGridTracks, findScrollParent, laneStyle, parsePx, VirtualList } from './VirtualList'
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
    // jsdom has no layout: give windowed rows a height (else every row measures 0 and the whole list "fits") and the
    // scroller a viewport. Rect height is keyed off the test ids / data-index below.
    // @tanstack/virtual-core reads an element scroller's viewport from offsetWidth/offsetHeight.
    for (const [prop, value] of [['offsetHeight', (el: HTMLElement) => (el.dataset.testid === 'scroller' ? 600 : el.hasAttribute('data-index') ? 100 : 0)], ['offsetWidth', () => 600]] as const) {
      vi.spyOn(HTMLElement.prototype, prop, 'get').mockImplementation(function (this: HTMLElement) {
        return value(this)
      })
    }
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      const height = this.hasAttribute('data-index') ? 100 : this.dataset.testid === 'scroller' ? 600 : 0
      const top = this.dataset.testid === 'virtual-list-scroll' ? 40 : 0
      return { x: 0, y: top, top, left: 0, right: 600, bottom: top + height, width: 600, height, toJSON: () => ({}) }
    })
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    vi.restoreAllMocks()
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

  it('renders above the threshold as the same list in the page: no nested scroller, no fixed height', () => {
    act(() => {
      root.render(
        <VirtualList items={makeRows(200)} getKey={(r) => r.id} renderItem={(r) => <span data-testid="row">{r.label}</span>} />,
      )
    })
    const list = container.querySelector('[data-testid="virtual-list-scroll"]') as HTMLElement
    expect(list).not.toBeNull()
    expect(window.getComputedStyle(list).overflowY).not.toMatch(/auto|scroll/)
    expect(list.style.overflow).toBe('')
    expect(list.style.height).not.toBe('640px')
    expect(list.style.maxHeight).toBe('')
    // it spans every column of the parent grid and positions its rows itself
    expect(list.style.gridColumn).toBe('1 / -1')
    // (jsdom has no scroll parent here, so this is the window-scroll fallback: asserted structurally only)
    expect(list.querySelectorAll('[data-index]').length).toBeLessThan(200)
  })

  it('windows against the nearest scrolling ancestor and takes lanes from the parent grid', () => {
    const realStyle = window.getComputedStyle.bind(window)
    vi.spyOn(window, 'getComputedStyle').mockImplementation(((el: Element, pseudo?: string | null) =>
      el.getAttribute('data-testid') === 'grid'
        ? ({ display: 'grid', gridTemplateColumns: '300px 300px', columnGap: '16px', rowGap: '12px', overflowY: 'visible' } as unknown as CSSStyleDeclaration)
        : realStyle(el, pseudo)) as typeof window.getComputedStyle)
    act(() => {
      root.render(
        <div data-testid="scroller" style={{ overflowY: 'auto' }}>
          <div data-testid="grid">
            <VirtualList items={makeRows(200)} getKey={(r) => r.id} renderItem={(r) => <span data-testid="row">{r.label}</span>} />
          </div>
        </div>,
      )
    })
    const list = container.querySelector('[data-testid="virtual-list-scroll"]') as HTMLElement
    expect(list.getAttribute('data-lanes')).toBe('2')
    const lanes = new Set([...list.querySelectorAll('[data-index]')].map((n) => n.getAttribute('data-lane')))
    expect(lanes).toEqual(new Set(['0', '1']))
    // the 600px scroller shows ~6 rows of 100px (x2 lanes) plus overscan, not the 200 rows
    expect(list.querySelectorAll('[data-index]').length).toBeLessThan(40)
    // scrollMargin = the list's offset in the scroller (40px): the first row is translated by start - margin = 0
    expect((list.querySelector('[data-index="0"]') as HTMLElement).getAttribute('style')).toContain('translateY(0px)')
    // the only scroller is the host's
    expect(container.querySelectorAll('[style*="overflow"]')).toHaveLength(1)
  })

  it('keeps one lane in a non-grid parent', () => {
    act(() => {
      root.render(
        <VirtualList items={makeRows(200)} getKey={(r) => r.id} renderItem={(r) => <span data-testid="row">{r.label}</span>} />,
      )
    })
    expect(container.querySelector('[data-testid="virtual-list-scroll"]')?.getAttribute('data-lanes')).toBe('1')
  })
})

describe('virtual list geometry helpers', () => {
  it('counts the tracks of a computed or unresolved grid-template-columns', () => {
    expect(countGridTracks('491px 491px')).toBe(2)
    expect(countGridTracks('491px')).toBe(1)
    expect(countGridTracks('none')).toBe(1)
    expect(countGridTracks('')).toBe(1)
    expect(countGridTracks(undefined)).toBe(1)
    expect(countGridTracks('minmax(0px, 1fr) minmax(0px, 1fr)')).toBe(2)
    expect(countGridTracks('repeat(3, minmax(0, 1fr))')).toBe(3)
    expect(countGridTracks('repeat(2, 1fr 2fr)')).toBe(4)
    expect(countGridTracks('[a] 100px [b] 200px [c]')).toBe(2)
  })
  it('reads gaps as px and treats "normal" as 0', () => {
    expect(parsePx('16px')).toBe(16)
    expect(parsePx('normal')).toBe(0)
    expect(parsePx('')).toBe(0)
  })
  it('places lane n at (100% + gap) / lanes * n with width (100% - gaps) / lanes', () => {
    expect(laneStyle(1, 12, 0)).toEqual({ left: '0px', width: '100%' })
    expect(laneStyle(2, 16, 1)).toEqual({ left: 'calc((100% + 16px) / 2 * 1)', width: 'calc((100% - 16px) / 2)' })
    expect(laneStyle(3, 10, 2).width).toBe('calc((100% - 20px) / 3)')
  })
  it('finds the nearest overflow-y auto/scroll ancestor, none when only the window scrolls', () => {
    const outer = document.createElement('div')
    outer.style.overflowY = 'scroll'
    const inner = document.createElement('div')
    const leaf = document.createElement('div')
    outer.appendChild(inner)
    inner.appendChild(leaf)
    document.body.appendChild(outer)
    expect(findScrollParent(leaf)).toBe(outer)
    outer.style.overflowY = 'visible'
    expect(findScrollParent(leaf)).toBeNull()
    outer.remove()
  })
})
