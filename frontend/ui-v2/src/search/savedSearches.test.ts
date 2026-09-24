import { beforeEach, describe, expect, it } from 'vitest'
import {
  deleteSavedSearch,
  loadSavedSearches,
  persistSavedSearches,
  saveCurrentSearch,
  type SavedSearch,
} from './savedSearches'

describe('savedSearches', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('persists and loads saved searches locally', () => {
    const sample: SavedSearch[] = [
      {
        id: 'ss-1',
        name: 'Open issues',
        query: 'ENC',
        filterQuery: { tokens: [{ propertyKey: 'status', operator: '=', value: 'open' }] },
      },
    ]
    persistSavedSearches(sample)
    expect(loadSavedSearches()).toEqual(sample)
  })

  it('saves current search by name', () => {
    const next = saveCurrentSearch([], 'My search', 'ENC', {
      tokens: [{ propertyKey: 'status', operator: '=', value: 'open' }],
    })
    expect(next).toHaveLength(1)
    expect(next[0]?.name).toBe('My search')
    expect(loadSavedSearches()[0]?.query).toBe('ENC')
  })

  it('deletes a saved search by id', () => {
    const seeded = saveCurrentSearch([], 'Temp', '', { tokens: [] })
    const updated = deleteSavedSearch(seeded, seeded[0]!.id)
    expect(updated).toHaveLength(0)
  })
})
