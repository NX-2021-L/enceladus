import { useRef, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
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
  /** Scroll container max-height in px. */
  maxHeight?: number
  className?: string
}

/**
 * Generic windowed list (ENC-TSK-M18 / UX-A4 AC-3: "Lists >30 rows
 * virtualized"). Lists at or under the threshold render every row directly
 * — no scroll container, no virtualizer bookkeeping — which keeps the
 * common case (most Feed/Coordination/Projects views today) exactly as
 * cheap as a plain `.map()`. Once a list crosses the threshold, rows are
 * windowed via @tanstack/react-virtual so the DOM only ever holds the
 * visible slice + overscan, regardless of how many records the list logically
 * holds (Coordination's session/lesson/escalation tabs are documented as
 * "<=200 row" datasets rendered with a bare `.map()` before this task).
 */
export function VirtualList<T>({
  items,
  getKey,
  renderItem,
  estimateSize = 88,
  overscan = 6,
  maxHeight = 640,
  className,
}: VirtualListProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null)

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
      maxHeight={maxHeight}
      className={className}
      parentRef={parentRef}
    />
  )
}

/** Split out so the `useVirtualizer` hook is only ever called on the
 * above-threshold path — hooks can't be called conditionally in
 * `VirtualList` itself. */
function VirtualizedWindow<T>({
  items,
  getKey,
  renderItem,
  estimateSize,
  overscan,
  maxHeight,
  className,
  parentRef,
}: Required<Omit<VirtualListProps<T>, 'className'>> & {
  className?: string
  parentRef: React.RefObject<HTMLDivElement | null>
}) {
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateSize,
    overscan,
  })

  const virtualItems = virtualizer.getVirtualItems()

  return (
    <div
      ref={parentRef}
      className={className}
      data-testid="virtual-list-scroll"
      style={{ height: maxHeight, overflow: 'auto', position: 'relative' }}
    >
      <div style={{ height: virtualizer.getTotalSize(), width: '100%', position: 'relative' }}>
        {virtualItems.map((virtualRow) => {
          const item = items[virtualRow.index]
          return (
            <div
              key={getKey(item, virtualRow.index)}
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                transform: `translateY(${virtualRow.start}px)`,
              }}
            >
              {renderItem(item, virtualRow.index)}
            </div>
          )
        })}
      </div>
    </div>
  )
}
