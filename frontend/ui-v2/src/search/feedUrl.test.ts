import { describe, expect, it } from 'vitest'
import { createLocalEngine } from '@io-kit/search'
import { decodeFeedSearch, encodeFeedSearch, FEED_SEARCH_DEFAULTS, parseFeedSearch, serializeFilterQuery } from './feedUrl'
import { ENCELADUS_PROPERTIES } from './propertyDefs'
import { resolveSortId, SORT_OPTIONS } from './sortOptions'

describe('URL v2 keeps pre-v2 /feed links working', () => {
  it('decodes ?q=&f=key|op|value;...&op=&sort= (the old grammar)', () => {
    const { query, sortId } = decodeFeedSearch(
      parseFeedSearch({ q: 'feed engine', f: 'status|=|open;priority|in|p0,p1;checkout_state|!=|checked_out', op: 'and', sort: 'title', scroll: '240' }),
    )
    expect(query.operation).toBe('and')
    expect(query.tokens).toEqual([
      { operator: ':', value: 'feed engine' },
      { propertyKey: 'status', operator: '=', value: 'open' },
      { propertyKey: 'priority', operator: 'in', value: ['p0', 'p1'] },
      { propertyKey: 'checkout_state', operator: '!=', value: 'checked_out' },
    ])
    expect(sortId).toBe('title')
  })

  it('re-keys the legacy record_id property and honours op=or', () => {
    const { query } = decodeFeedSearch({ q: '', f: 'record_id|=|ENC-TSK-1;title|:|a%7Cb', op: 'or', sort: 'updated' })
    expect(query.operation).toBe('or')
    expect(query.tokens[0]).toMatchObject({ propertyKey: 'id', value: 'ENC-TSK-1' })
    expect(query.tokens[1]).toMatchObject({ propertyKey: 'title', value: 'a|b' })
  })

  it('Home / Projects deep links (serializeFilterQuery) filter the local engine as before', () => {
    const f = serializeFilterQuery({
      tokens: [
        { propertyKey: 'status', operator: '=', value: 'open' },
        { propertyKey: 'record_type', operator: '=', value: 'task' },
        { propertyKey: 'checkout_state', operator: '!=', value: 'checked_out' },
      ],
      operation: 'and',
    })
    const mk = (id: string, fields: Record<string, string | undefined>) => ({ id, type: 'task', title: id, fields: { record_type: 'task', ...fields } })
    const engine = createLocalEngine(
      [mk('a', { status: 'open' }), mk('b', { status: 'open', checkout_state: 'checked_out' }), mk('c', { status: 'closed' })],
      ENCELADUS_PROPERTIES,
    )
    const { query } = decodeFeedSearch({ ...FEED_SEARCH_DEFAULTS, f })
    expect(engine.filter(query).hits.map((r) => r.id)).toEqual(['a']) // a row without the field is "not checked_out"
  })

  it('round-trips through encode, omitting defaults, and falls back to the default sort', () => {
    const search = { q: 'feed', f: 'status|=|open', op: 'and' as const, sort: 'tier', scroll: 0 }
    const { query, sortId } = decodeFeedSearch(search)
    expect(encodeFeedSearch(query, sortId)).toEqual({ ...search, f: expect.stringContaining('status') })
    expect(decodeFeedSearch(encodeFeedSearch(query, sortId)).query).toEqual(query)
    expect(encodeFeedSearch({ operation: 'and', tokens: [] }, 'updated')).toEqual(FEED_SEARCH_DEFAULTS)
    expect(resolveSortId('nonsense')).toBe('updated')
    expect(SORT_OPTIONS.map((o) => o.id)).toEqual(['updated', 'tier', 'id', 'title', 'status'])
  })
})
