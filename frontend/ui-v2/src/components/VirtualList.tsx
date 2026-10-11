import { useCallback, useEffect, useLayoutEffect, useRef, type ReactNode, type RefObject } from 'react'
import { useState } from 'react'
import { useVirtualizer, useWindowVirtualizer, type VirtualItem } from '@tanstack/react-virtual'
import { shouldVirtualize } from './virtualListThreshold'

export interface VirtualListProps<T> {
  items: readonly T[]
  /** Stable key for a row — required so windowed re-renders don't remount. */
  getKey: (item: T, index: number) => string
  renderItem: (item: T, index: number) => ReactNode
  /** Estimated row height in px (AC-3 windowing math); tune per call site. */
  estimateSize?: number
  /** Rows rendered above/below the visible window, to smooth fast scrolls. */
  overscan?: number
  /** Applied to the (non-scrolling) list container. */
  className?: string
}

/**
 * Generic windowed list (ENC-TSK-M18 / UX-A4 AC-3: "Lists >30 rows
 * virtualized"). Lists at or under the threshold render every row directly
 * — no container, no virtualizer bookkeeping — which keeps the common case
 * exactly as cheap as a plain `.map()`.
 *
 * DVP-TSK-A09 (R16, one scroll owner per region): above the threshold the rows are windowed against the NEAREST
 * SCROLLING ANCESTOR (computed overflow-y auto/scroll: on every route that is the page scroller
 * `.ev2-al__content`; with none, the window). The list owns no scroller and no fixed height, so it never nests a
 * second scroll box inside the page one. It sits in a parent grid (`.ev2-rc-grid--2col`) as one full-width item
 * (`grid-column: 1 / -1`) and keeps the parent's columns itself: the virtualizer `lanes` is the number of tracks in
 * the parent's computed `grid-template-columns`, each row is absolutely positioned at its lane's left with the
 * parent's column-gap between lanes (and its row-gap between rows in a lane).
 */
export function VirtualList<T>({
  items,
  getKey,
  renderItem,
  estimateSize = 88,
  overscan = 6,
  className,
}: VirtualListProps<T>) {
  if (!shouldVirtualize(items.length)) {
    return (
      <>
        {items.map((item, index) => (
          <div key={getKey(item, index)}>{renderItem(item, index)}</div>
        ))}
      </>
    )
  }

  return (
    <VirtualizedWindow
      items={items}
      getKey={getKey}
      renderItem={renderItem}
      estimateSize={estimateSize}
      overscan={overscan}
      {...(className ? { className } : {})}
    />
  )
}

// ---- geometry: scroller, offset within it, and the parent grid's lanes --------------------------------------------

function splitTopLevel(value: string): string[] {
  const out: string[] = []
  let depth = 0
  let cur = ''
  for (const ch of value) {
    if (ch === '(') depth += 1
    if (ch === ')') depth -= 1
    if (depth === 0 && /\s/.test(ch)) {
      if (cur) out.push(cur)
      cur = ''
      continue
    }
    cur += ch
  }
  if (cur) out.push(cur)
  return out
}

/** Number of tracks in a `grid-template-columns` value (computed px lists, or an unresolved repeat()/minmax() list). */
export function countGridTracks(template: string | null | undefined): number {
  if (!template || template === 'none') return 1
  let count = 0
  for (const token of splitTopLevel(template.replace(/\[[^\]]*\]/g, ' '))) {
    const repeat = /^repeat\(\s*(\d+)\s*,([\s\S]*)\)$/i.exec(token)
    count += repeat ? Number(repeat[1]) * Math.max(1, splitTopLevel(repeat[2] ?? '').length) : 1
  }
  return Math.max(1, count)
}

export function parsePx(value: string | null | undefined): number {
  const n = Number.parseFloat(value ?? '')
  return Number.isFinite(n) ? n : 0
}

/** Left offset and width of a row in `lane` of `lanes` lanes separated by `columnGap` px, as CSS (percent of the list width). */
export function laneStyle(lanes: number, columnGap: number, lane: number): { left: string; width: string } {
  if (lanes <= 1) return { left: '0px', width: '100%' }
  return {
    left: `calc((100% + ${columnGap}px) / ${lanes} * ${lane})`,
    width: `calc((100% - ${columnGap * (lanes - 1)}px) / ${lanes})`,
  }
}

/** The nearest ancestor that scrolls vertically (computed overflow-y auto/scroll); null means the window scrolls. */
export function findScrollParent(el: HTMLElement | null): HTMLElement | null {
  for (let node = el?.parentElement ?? null; node; node = node.parentElement) {
    if (node === document.body || node === document.documentElement) return null
    const overflowY = window.getComputedStyle(node).overflowY
    if (overflowY === 'auto' || overflowY === 'scroll' || overflowY === 'overlay') return node
  }
  return null
}

interface ListGeometry {
  measured: boolean
  scroller: HTMLElement | null
  /** Offset of the list's top within the scroller's content (the window's document when there is no scroller). */
  scrollMargin: number
  lanes: number
  columnGap: number
  rowGap: number
}

const UNMEASURED: ListGeometry = { measured: false, scroller: null, scrollMargin: 0, lanes: 1, columnGap: 0, rowGap: 0 }

function measureGeometry(container: HTMLElement): ListGeometry {
  const scroller = findScrollParent(container)
  let lanes = 1
  let columnGap = 0
  let rowGap = 0
  const parent = container.parentElement
  if (parent) {
    const cs = window.getComputedStyle(parent)
    if (cs.display === 'grid' || cs.display === 'inline-grid') {
      lanes = countGridTracks(cs.gridTemplateColumns)
      columnGap = parsePx(cs.columnGap)
    }
    rowGap = parsePx(cs.rowGap)
  }
  const top = container.getBoundingClientRect().top
  const scrollMargin = scroller
    ? Math.round(top - scroller.getBoundingClientRect().top - scroller.clientTop + scroller.scrollTop)
    : Math.round(top + window.scrollY)
  return { measured: true, scroller, scrollMargin, lanes, columnGap, rowGap }
}

const sameGeometry = (a: ListGeometry, b: ListGeometry) =>
  a.measured === b.measured &&
  a.scroller === b.scroller &&
  a.scrollMargin === b.scrollMargin &&
  a.lanes === b.lanes &&
  a.columnGap === b.columnGap &&
  a.rowGap === b.rowGap

/** Re-measured after every render (cheap, bails out when unchanged) and on resize of the list, its grid and its scroller. */
function useListGeometry(containerRef: RefObject<HTMLDivElement | null>): ListGeometry {
  const [geometry, setGeometry] = useState<ListGeometry>(UNMEASURED)
  const measure = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const next = measureGeometry(el)
    setGeometry((prev) => (sameGeometry(prev, next) ? prev : next))
  }, [containerRef])

  // eslint-disable-next-line react-hooks/exhaustive-deps -- runs after every render on purpose; setGeometry bails out when unchanged
  useLayoutEffect(() => {
    measure()
  })

  const { measured, scroller } = geometry
  useEffect(() => {
    const el = containerRef.current
    if (!el || !measured) return undefined
    window.addEventListener('resize', measure)
    let observer: ResizeObserver | undefined
    if (typeof ResizeObserver !== 'undefined') {
      observer = new ResizeObserver(() => measure())
      observer.observe(el)
      if (el.parentElement) observer.observe(el.parentElement)
      if (scroller) observer.observe(scroller)
    }
    return () => {
      window.removeEventListener('resize', measure)
      observer?.disconnect()
    }
  }, [containerRef, measure, measured, scroller])

  return geometry
}

// ---- windowed rows ------------------------------------------------------------------------------------------------

type WindowProps<T> = Required<Omit<VirtualListProps<T>, 'className'>> & { className?: string }

/** Split out so the virtualizer hooks are only ever called on the above-threshold path (hooks can't be conditional). */
function VirtualizedWindow<T>(props: WindowProps<T>) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const geometry = useListGeometry(containerRef)
  if (!geometry.measured) {
    // First render: only the container, so the layout effect can read the scroller and the parent grid before any row.
    return <div ref={containerRef} className={props.className} data-testid="virtual-list-scroll" style={{ gridColumn: '1 / -1' }} />
  }
  return geometry.scroller ? (
    <ScrollerRows {...props} containerRef={containerRef} geometry={geometry} scroller={geometry.scroller} />
  ) : (
    <PageRows {...props} containerRef={containerRef} geometry={geometry} />
  )
}

type RowsProps<T> = WindowProps<T> & { containerRef: RefObject<HTMLDivElement | null>; geometry: ListGeometry }

function ScrollerRows<T>({ scroller, ...props }: RowsProps<T> & { scroller: HTMLElement }) {
  const { items, getKey, estimateSize, overscan, geometry } = props
  const virtualizer = useVirtualizer<HTMLElement, HTMLElement>({
    count: items.length,
    getScrollElement: () => scroller,
    estimateSize: () => estimateSize,
    overscan,
    lanes: geometry.lanes,
    gap: geometry.rowGap,
    scrollMargin: geometry.scrollMargin,
    getItemKey: (index) => getKey(items[index] as T, index),
  })
  return (
    <Rows
      {...props}
      virtualItems={virtualizer.getVirtualItems()}
      totalSize={virtualizer.getTotalSize()}
      measureElement={virtualizer.measureElement}
    />
  )
}

function PageRows<T>(props: RowsProps<T>) {
  const { items, getKey, estimateSize, overscan, geometry } = props
  const virtualizer = useWindowVirtualizer<HTMLElement>({
    count: items.length,
    estimateSize: () => estimateSize,
    overscan,
    lanes: geometry.lanes,
    gap: geometry.rowGap,
    scrollMargin: geometry.scrollMargin,
    getItemKey: (index) => getKey(items[index] as T, index),
  })
  return (
    <Rows
      {...props}
      virtualItems={virtualizer.getVirtualItems()}
      totalSize={virtualizer.getTotalSize()}
      measureElement={virtualizer.measureElement}
    />
  )
}

function Rows<T>({
  items,
  getKey,
  renderItem,
  className,
  containerRef,
  geometry,
  virtualItems,
  totalSize,
  measureElement,
}: RowsProps<T> & { virtualItems: VirtualItem[]; totalSize: number; measureElement: (node: HTMLElement | null) => void }) {
  const { lanes, columnGap, scrollMargin } = geometry
  return (
    <div
      ref={containerRef}
      className={className}
      data-testid="virtual-list-scroll"
      data-lanes={lanes}
      // Not a scroller: a positioned spacer as tall as the whole list, spanning every column of the parent grid.
      style={{ gridColumn: '1 / -1', position: 'relative', width: '100%', height: totalSize }}
    >
      {virtualItems.map((virtualRow) => {
        const item = items[virtualRow.index] as T
        const { left, width } = laneStyle(lanes, columnGap, virtualRow.lane)
        return (
          <div
            key={getKey(item, virtualRow.index)}
            data-index={virtualRow.index}
            data-lane={virtualRow.lane}
            ref={measureElement}
            style={{
              position: 'absolute',
              top: 0,
              left,
              width,
              transform: `translateY(${virtualRow.start - scrollMargin}px)`,
            }}
          >
            {renderItem(item, virtualRow.index)}
          </div>
        )
      })}
    </div>
  )
}
