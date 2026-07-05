import { beforeEach, describe, expect, it } from 'vitest'
import {
  FEED_SEARCH_DEFAULTS,
  FEED_RETURN_STORAGE_KEY,
  buildFeedPath,
  loadFeedReturnSearch,
  parseFeedSearch,
  parseFilterQuery,
  persistFeedReturnSearch,
  serializeFilterQuery,
} from './feedSearchParams'

describe('feedSearchParams', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('parses defaults from empty search', () => {
    expect(parseFeedSearch({})).toEqual(FEED_SEARCH_DEFAULTS)
  })

  it('round-trips query, filters, sort, and scroll', () => {
    const parsed = parseFeedSearch({
      q: 'ENC',
      f: 'status|%3D|open',
      op: 'or',
      sort: 'title',
      scroll: '240',
    })
    expect(parsed.q).toBe('ENC')
    expect(parsed.sort).toBe('title')
    expect(parsed.scroll).toBe(240)
    expect(parseFilterQuery(parsed.f, parsed.op).tokens).toEqual([
      { propertyKey: 'status', operator: '=', value: 'open' },
    ])
    expect(buildFeedPath(parsed)).toContain('q=ENC')
    expect(buildFeedPath(parsed)).toContain('scroll=240')
  })

  it('serializes and parses multi-token filters', () => {
    const serialized = serializeFilterQuery({
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'open' },
        { propertyKey: 'priority', operator: '!=', value: 'P0' },
      ],
      operation: 'and',
    })
    expect(parseFilterQuery(serialized, 'and').tokens).toEqual([
      { propertyKey: 'status', operator: '=', value: 'open' },
      { propertyKey: 'priority', operator: '!=', value: 'P0' },
    ])
  })

  it('persists feed return search for breadcrumb navigation', () => {
    persistFeedReturnSearch({
      q: 'hybrid',
      f: '',
      op: 'and',
      sort: 'tier',
      scroll: 88,
    })
    expect(sessionStorage.getItem(FEED_RETURN_STORAGE_KEY)).toContain('scroll=88')
    expect(loadFeedReturnSearch().q).toBe('hybrid')
    expect(loadFeedReturnSearch().scroll).toBe(88)
  })
})
