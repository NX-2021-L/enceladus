import type { SortOption } from '@io-kit/search-ui'

/**
 * DVP-TSK-995: sort ids stay the legacy FeedSort values so old `?sort=` links keep working. The label is the
 * METHOD only (R15: the Sort cell shows "Updated", not "Sort: Last Updated"). 'tier' is relevance
 * (hybrid order, then newest first).
 */
export const DEFAULT_SORT_ID = 'updated'

export const SORT_OPTIONS: SortOption[] = [
  { id: 'updated', label: 'Updated', sort: { key: 'updated_at', dir: 'desc' } },
  { id: 'tier', label: 'Relevance' },
  { id: 'id', label: 'Record ID', sort: { key: 'id', dir: 'asc' } },
  { id: 'title', label: 'Title', sort: { key: 'title', dir: 'asc' } },
  { id: 'status', label: 'Status', sort: { key: 'status', dir: 'asc' } },
]

export function resolveSortId(raw: string | undefined | null): string {
  return SORT_OPTIONS.some((o) => o.id === raw) ? (raw as string) : DEFAULT_SORT_ID
}
