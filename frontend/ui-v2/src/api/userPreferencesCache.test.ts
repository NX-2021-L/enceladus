import { beforeEach, describe, expect, it } from 'vitest'
import { readCachedPreferences, writeCachedPreferences } from './userPreferencesCache'
import type { UserPreferences } from '../types/userPreferences'

describe('userPreferencesCache', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('returns empty preferences when nothing is cached', () => {
    expect(readCachedPreferences()).toEqual({
      saved_searches: [],
      recently_viewed: {},
      prefs: {},
    })
  })

  it('round-trips a written preferences object', () => {
    const prefs: UserPreferences = {
      saved_searches: [{ name: 'my tasks', query: 'status:open', filters: {}, sort: 'recent' }],
      recently_viewed: { task: [{ record_id: 'ENC-TSK-1', project_id: 'enceladus', viewed_at: '2026-07-05T00:00:00Z' }] },
      prefs: { theme: 'dark' },
    }
    writeCachedPreferences(prefs)
    expect(readCachedPreferences()).toEqual(prefs)
  })

  it('fails open to empty preferences on corrupt storage', () => {
    localStorage.setItem('enceladus.userPreferences.v1', '{not json')
    expect(readCachedPreferences()).toEqual({
      saved_searches: [],
      recently_viewed: {},
      prefs: {},
    })
  })

  it('coerces a malformed cached shape to safe defaults per field', () => {
    localStorage.setItem(
      'enceladus.userPreferences.v1',
      JSON.stringify({ saved_searches: 'not-an-array', recently_viewed: null, prefs: 42 }),
    )
    expect(readCachedPreferences()).toEqual({
      saved_searches: [],
      recently_viewed: {},
      prefs: {},
    })
  })
})
