import { describe, expect, it } from 'vitest'
import {
  LEGACY_SAVED_SEARCHES_KEY,
  MIGRATED_MARKER_KEY,
  migrateLegacySavedSearches,
  SAVED_FILTERS_FEED_KEY,
  type SyncStore,
} from './savedSearchMigration'

const memory = (seed: Record<string, string> = {}): SyncStore & { data: Record<string, string> } => {
  const data = { ...seed }
  return { data, get: (k) => data[k] ?? null, set: (k, v) => void (data[k] = v) }
}
const legacy = [
  { id: 'ss-1', name: 'Open P0/P1', query: 'feed', filterQuery: { tokens: [{ propertyKey: 'status', operator: '=', value: 'open' }, { propertyKey: 'priority', operator: 'in', value: 'p0,p1' }], operation: 'and' } },
  { id: 'ss-2', name: 'By id', query: '', filterQuery: { tokens: [{ propertyKey: 'record_id', operator: '=', value: 'ENC-TSK-1' }], operation: 'or' } },
]

describe('saved searches -> useSavedFilters (once)', () => {
  it('converts legacy entries into kit SavedFilters under the feed surface key', () => {
    const store = memory({ [LEGACY_SAVED_SEARCHES_KEY]: JSON.stringify(legacy) })
    expect(migrateLegacySavedSearches(store)).toBe(2)
    const saved = JSON.parse(store.data[SAVED_FILTERS_FEED_KEY]!)
    expect(saved.map((s: { name: string }) => s.name)).toEqual(['Open P0/P1', 'By id'])
    expect(saved[0].query.tokens).toEqual([
      { operator: ':', value: 'feed' },
      { propertyKey: 'status', operator: '=', value: 'open' },
      { propertyKey: 'priority', operator: 'in', value: ['p0', 'p1'] },
    ])
    expect(saved[1].query).toMatchObject({ operation: 'or', tokens: [{ propertyKey: 'id', value: 'ENC-TSK-1' }] })
    expect(store.data[LEGACY_SAVED_SEARCHES_KEY]).toBeDefined() // rollback copy stays
  })

  it('runs once: a later delete in the kit store is not undone, and existing names are not duplicated', () => {
    const store = memory({ [LEGACY_SAVED_SEARCHES_KEY]: JSON.stringify(legacy), [SAVED_FILTERS_FEED_KEY]: JSON.stringify([{ id: 'k', name: 'By id', query: { operation: 'and', tokens: [] } }]) })
    expect(migrateLegacySavedSearches(store)).toBe(1)
    expect(JSON.parse(store.data[SAVED_FILTERS_FEED_KEY]!)).toHaveLength(2)
    store.data[SAVED_FILTERS_FEED_KEY] = '[]'
    expect(migrateLegacySavedSearches(store)).toBe(0)
    expect(store.data[SAVED_FILTERS_FEED_KEY]).toBe('[]')
    expect(store.data[MIGRATED_MARKER_KEY]).toBe('1')
  })

  it('is a no-op without legacy data or with a corrupt value', () => {
    expect(migrateLegacySavedSearches(memory())).toBe(0)
    expect(migrateLegacySavedSearches(memory({ [LEGACY_SAVED_SEARCHES_KEY]: '{oops' }))).toBe(0)
  })
})
