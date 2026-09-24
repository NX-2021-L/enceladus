import type { PropertyFilterQuery } from './applyPropertyFilter'

export interface SavedSearch {
  id: string
  name: string
  query: string
  filterQuery: PropertyFilterQuery
}

const STORAGE_KEY = 'enceladus-ui-v2:saved-searches'

export function loadSavedSearches(): SavedSearch[] {
  if (typeof localStorage === 'undefined') return []
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as SavedSearch[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

export function persistSavedSearches(searches: SavedSearch[]): void {
  if (typeof localStorage === 'undefined') return
  localStorage.setItem(STORAGE_KEY, JSON.stringify(searches))
}

export function saveCurrentSearch(
  searches: SavedSearch[],
  name: string,
  query: string,
  filterQuery: PropertyFilterQuery,
): SavedSearch[] {
  const trimmed = name.trim()
  if (!trimmed) return searches
  const next: SavedSearch = {
    id: `ss-${Date.now()}`,
    name: trimmed,
    query,
    filterQuery: {
      tokens: [...(filterQuery.tokens ?? [])],
      operation: filterQuery.operation ?? 'and',
    },
  }
  const updated = [next, ...searches.filter((s) => s.name !== trimmed)]
  persistSavedSearches(updated)
  return updated
}

export function deleteSavedSearch(searches: SavedSearch[], id: string): SavedSearch[] {
  const updated = searches.filter((s) => s.id !== id)
  persistSavedSearches(updated)
  return updated
}
