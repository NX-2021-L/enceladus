import { createUrlCodecV2, type SavedFilter } from '@io-kit/search'
import type { KeyValueStore } from '@io-kit/search/react'

export interface SyncStore {
  get(key: string): string | null
  set(key: string, value: string): void
}
import { ENCELADUS_PROPERTIES } from './propertyDefs'
import { serializeFilterQuery, type PropertyFilterQuery } from './feedUrl'

/**
 * DVP-TSK-995: saved searches move from localStorage `enceladus-ui-v2:saved-searches` ({id,name,query,filterQuery})
 * into the kit's useSavedFilters store (`io-kit.search.filters.feed`) exactly once. The legacy value is left in
 * place as a rollback copy; a marker key records that the move happened so a later delete is not undone.
 */
export const LEGACY_SAVED_SEARCHES_KEY = 'enceladus-ui-v2:saved-searches'
export const SAVED_FILTERS_FEED_KEY = 'io-kit.search.filters.feed'
export const MIGRATED_MARKER_KEY = 'enceladus-ui-v2:saved-searches:migrated'

interface LegacySavedSearch {
  id: string
  name: string
  query: string
  filterQuery: PropertyFilterQuery
}

const codec = createUrlCodecV2({ properties: ENCELADUS_PROPERTIES })

export function legacyToSavedFilter(s: LegacySavedSearch): SavedFilter {
  const params = new URLSearchParams()
  if (s.query) params.set('q', s.query)
  const f = serializeFilterQuery(s.filterQuery ?? { tokens: [] })
  if (f) params.set('f', f)
  if (s.filterQuery?.operation === 'or') params.set('op', 'or')
  const { query } = codec.decode(params)
  return { id: s.id, name: s.name, query: { ...query, tokens: query.tokens.map((t) => (t.propertyKey === 'record_id' ? { ...t, propertyKey: 'id' } : t)) } }
}

export function migrateLegacySavedSearches(store: SyncStore): number {
  try {
    if (store.get(MIGRATED_MARKER_KEY)) return 0
    const raw = store.get(LEGACY_SAVED_SEARCHES_KEY)
    store.set(MIGRATED_MARKER_KEY, '1')
    if (!raw) return 0
    const legacy = JSON.parse(raw) as LegacySavedSearch[]
    if (!Array.isArray(legacy) || legacy.length === 0) return 0
    let existing: SavedFilter[] = []
    try {
      const cur = store.get(SAVED_FILTERS_FEED_KEY)
      const parsed = cur ? (JSON.parse(cur) as SavedFilter[]) : []
      existing = Array.isArray(parsed) ? parsed : []
    } catch {
      existing = []
    }
    const names = new Set(existing.map((s) => s.name))
    const moved = legacy.filter((s) => s?.name && !names.has(s.name)).map(legacyToSavedFilter)
    store.set(SAVED_FILTERS_FEED_KEY, JSON.stringify([...existing, ...moved]))
    return moved.length
  } catch {
    return 0
  }
}

/** localStorage-shaped store for the kit hooks; every access is guarded (private mode, SSR, tests). */
export const localSavedFilterStore: KeyValueStore & SyncStore = {
  get(key) {
    try {
      return window.localStorage.getItem(key)
    } catch {
      return null
    }
  },
  set(key, value) {
    try {
      window.localStorage.setItem(key, value)
    } catch {
      /* quota / private mode */
    }
  },
}
