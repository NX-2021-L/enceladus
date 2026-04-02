import { useMemo } from 'react'
import { useLiveFeed } from '../contexts/LiveFeedContext'
import type { Lesson } from '../types/feeds'

/**
 * Returns all lessons from the live feed.
 * Lessons are a new record type (ENC-FTR-052) surfaced in ENC-FTR-055.
 */
export function useLessons() {
  const { lessons, generatedAt } = useLiveFeed()
  const isLoading = generatedAt === null

  const sorted = useMemo(() => {
    return [...lessons].sort((a, b) => {
      const aDate = a.updated_at ?? a.created_at ?? ''
      const bDate = b.updated_at ?? b.created_at ?? ''
      return bDate.localeCompare(aDate)
    })
  }, [lessons])

  return { lessons: sorted, isLoading }
}
