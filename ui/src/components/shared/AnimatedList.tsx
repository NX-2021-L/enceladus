import { useRef, useLayoutEffect, type ReactNode } from 'react'

/**
 * AnimatedList — FLIP-based animated list for live-updating feed items.
 *
 * Provides smooth visual transitions when items reorder, enter, or exit:
 *   • Existing items slide to new positions (transform translateY)
 *   • New items fade-in with a subtle scale
 *   • Removed items are not animated (they simply disappear on next render)
 *
 * Uses the FLIP technique (First-Last-Invert-Play) with CSS transitions.
 * Zero external dependencies — pure DOM measurement + CSS transforms.
 *
 * DVP-TSK-208
 */

interface AnimatedListProps<T extends { _id: string }> {
  items: T[]
  renderItem: (item: T) => ReactNode
  className?: string
}

const TRANSITION_MS = 300

export function AnimatedList<T extends { _id: string }>({
  items,
  renderItem,
  className,
}: AnimatedListProps<T>) {
  const containerRef = useRef<HTMLDivElement>(null)
  // Map of item _id → previous top offset (for FLIP)
  const prevTops = useRef<Map<string, number>>(new Map())
  // Set of _ids present in the previous render (to detect new items)
  const prevIds = useRef<Set<string>>(new Set())

  // After React commits the new DOM, compute position deltas and animate
  useLayoutEffect(() => {
    const container = containerRef.current
    if (!container) return

    const oldTops = prevTops.current
    const oldIds = prevIds.current

    // "Last" — measure new positions
    const children = Array.from(container.children) as HTMLElement[]
    const newIds = new Set<string>()

    for (const child of children) {
      const id = child.dataset.itemId
      if (!id) continue
      newIds.add(id)

      const newTop = child.getBoundingClientRect().top
      const oldTop = oldTops.get(id)

      if (oldTop !== undefined && oldTop !== newTop) {
        // FLIP: Invert + Play for moved items
        const delta = oldTop - newTop
        child.style.transform = `translateY(${delta}px)`
        child.style.transition = 'none'
        // Force reflow so the browser registers the starting position
        child.getBoundingClientRect()
        child.style.transition = `transform ${TRANSITION_MS}ms ease`
        child.style.transform = ''
      } else if (!oldIds.has(id)) {
        // New item — fade in
        child.style.opacity = '0'
        child.style.transform = 'scale(0.97)'
        child.style.transition = 'none'
        child.getBoundingClientRect()
        child.style.transition = `opacity ${TRANSITION_MS}ms ease, transform ${TRANSITION_MS}ms ease`
        child.style.opacity = '1'
        child.style.transform = 'scale(1)'
      }
    }

    // Update refs for next render
    prevIds.current = newIds

    // Snapshot current positions for the next update
    const map = new Map<string, number>()
    for (const child of children) {
      const id = child.dataset.itemId
      if (id) map.set(id, child.getBoundingClientRect().top)
    }
    prevTops.current = map
  })

  // Clean up inline styles after transitions complete
  useLayoutEffect(() => {
    const container = containerRef.current
    if (!container) return

    const cleanup = () => {
      for (const child of Array.from(container.children) as HTMLElement[]) {
        child.style.transform = ''
        child.style.transition = ''
        child.style.opacity = ''
      }
    }

    const timer = setTimeout(cleanup, TRANSITION_MS + 50)
    return () => clearTimeout(timer)
  })

  return (
    <div ref={containerRef} className={className}>
      {items.map((item) => (
        <div key={item._id} data-item-id={item._id}>
          {renderItem(item)}
        </div>
      ))}
    </div>
  )
}
