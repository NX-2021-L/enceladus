import { useEffect, useRef } from 'react'
import type { RefObject } from 'react'

export function useFeedScrollRestore(
  scroll: number,
  isWide: boolean,
  listRef: RefObject<HTMLDivElement | null>,
  onScrollPersist: (nextScroll: number) => void,
  ready: boolean,
) {
  const restoredFor = useRef<number | null>(null)
  const persistTimer = useRef<number | null>(null)

  useEffect(() => {
    if (!ready || scroll <= 0) {
      restoredFor.current = null
      return
    }
    if (restoredFor.current === scroll) return

    const restore = () => {
      if (isWide && listRef.current) {
        listRef.current.scrollTop = scroll
      } else {
        window.scrollTo({ top: scroll, behavior: 'auto' })
      }
      restoredFor.current = scroll
    }

    requestAnimationFrame(() => requestAnimationFrame(restore))
  }, [scroll, isWide, listRef, ready])

  useEffect(() => {
    const persist = (value: number) => {
      if (persistTimer.current !== null) window.clearTimeout(persistTimer.current)
      persistTimer.current = window.setTimeout(() => onScrollPersist(Math.round(value)), 120)
    }

    if (isWide) {
      const node = listRef.current
      if (!node) return
      const onScroll = () => persist(node.scrollTop)
      node.addEventListener('scroll', onScroll, { passive: true })
      return () => node.removeEventListener('scroll', onScroll)
    }

    const onScroll = () => persist(window.scrollY)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [isWide, listRef, onScrollPersist])
}
