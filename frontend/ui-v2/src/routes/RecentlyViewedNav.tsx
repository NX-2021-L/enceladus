import { Pagination } from '../design-system'
import type { RecentlyViewedEntry } from '../search/recentlyViewed'

/** Arrows-only stepper through recently viewed records (FTR-128 AC-18). */
export function RecentlyViewedNav({
  items,
  currentRecordId,
  onSelect,
}: {
  items: RecentlyViewedEntry[]
  currentRecordId: string | null
  onSelect: (entry: RecentlyViewedEntry) => void
}) {
  if (items.length <= 1) return null

  const currentIndex = items.findIndex((row) => row.recordId === currentRecordId)
  const pageIndex = currentIndex >= 0 ? currentIndex + 1 : 1

  return (
    <div className="feed-recent-nav" aria-label="Recently viewed">
      <span className="feed-recent-nav__label">Recently viewed</span>
      <Pagination
        currentPageIndex={pageIndex}
        pagesCount={items.length}
        onChange={(event) => {
          const next = items[event.detail.currentPageIndex - 1]
          if (next) onSelect(next)
        }}
      />
    </div>
  )
}
