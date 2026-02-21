import { useState, useCallback, useRef } from 'react'

const PAGE_SIZE = 20

export function useInfiniteList<T>(items: T[], pageSize = PAGE_SIZE, maxItems?: number) {
  const [page, setPage] = useState(1)
  const observerRef = useRef<IntersectionObserver | null>(null)

  // No auto-reset on items.length change — live polling can add/remove
  // individual items and resetting the page causes the list to jump.
  // Use resetPage() explicitly when the user changes filters.

  const resetPage = useCallback(() => setPage(1), [])

  const visible = items.slice(0, Math.min(page * pageSize, maxItems ?? Infinity))
  const hasMore = visible.length < items.length && (!maxItems || visible.length < maxItems)

  const sentinelRef = useCallback(
    (node: HTMLElement | null) => {
      if (observerRef.current) {
        observerRef.current.disconnect()
        observerRef.current = null
      }
      if (!node || !hasMore) return
      observerRef.current = new IntersectionObserver(
        (entries) => {
          if (entries[0]?.isIntersecting) {
            setPage((p) => p + 1)
          }
        },
        { rootMargin: '200px' },
      )
      observerRef.current.observe(node)
    },
    [hasMore],
  )

  return { visible, sentinelRef, hasMore, total: items.length, resetPage }
}
