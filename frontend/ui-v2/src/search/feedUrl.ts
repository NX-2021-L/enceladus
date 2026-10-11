import { createUrlCodecV2, type Query, type QueryUrlCodec } from '@io-kit/search'
import { ENCELADUS_PROPERTIES } from './propertyDefs'
import { DEFAULT_SORT_ID, resolveSortId } from './sortOptions'

/**
 * DVP-TSK-995: URL v2 for /feed. The route search stays a bag of strings (`q`, `f`, `op`, `sort`, `scroll`) so every
 * pre-v2 link keeps working: `?q=&f=key|op|value;...&op=&sort=` is exactly the grammar the kit codec reads. The only
 * re-keying is the legacy `record_id` property, which the kit exposes as `id`.
 */
export type FeedSort = 'tier' | 'id' | 'status' | 'title' | 'updated'

export interface FeedRouteSearch {
  /** DVP-TSK-995: the header SearchLauncher navigates with focus=1; the page focuses its search input on mount. */
  focus?: 1
  q: string
  f: string
  op: 'and' | 'or'
  sort: string
  scroll: number
}

export const FEED_SEARCH_DEFAULTS: FeedRouteSearch = { q: '', f: '', op: 'and', sort: DEFAULT_SORT_ID, scroll: 0 }
export const FEED_RETURN_STORAGE_KEY = 'enc.feed.returnSearch'

export const feedCodec: QueryUrlCodec = createUrlCodecV2({ properties: ENCELADUS_PROPERTIES, defaultSort: DEFAULT_SORT_ID })

export function parseFeedSearch(raw: Record<string, unknown>): FeedRouteSearch {
  const scrollRaw = raw.scroll
  const scroll = typeof scrollRaw === 'number' ? scrollRaw : typeof scrollRaw === 'string' ? Number.parseInt(scrollRaw, 10) : 0
  return {
    q: typeof raw.q === 'string' ? raw.q : '',
    f: typeof raw.f === 'string' ? raw.f : '',
    op: raw.op === 'or' ? 'or' : 'and',
    sort: typeof raw.sort === 'string' && raw.sort ? raw.sort : DEFAULT_SORT_ID,
    scroll: Number.isFinite(scroll) && scroll > 0 ? Math.round(scroll) : 0,
    ...(parseFocus(raw) ? { focus: 1 as const } : {}),
  }
}

/** `focus=1` (string from a launcher URL, number from a parsed one, or true) means: focus the search input on mount. */
export function parseFocus(raw: Record<string, unknown>): boolean {
  return raw.focus === 1 || raw.focus === '1' || raw.focus === true
}

function rekey(query: Query): Query {
  const fix = <T extends { propertyKey?: string }>(t: T): T => (t.propertyKey === 'record_id' ? { ...t, propertyKey: 'id' } : t)
  return {
    ...query,
    tokens: query.tokens.map(fix),
    ...(query.tokenGroups ? { tokenGroups: query.tokenGroups.map((g) => ({ ...g, tokens: g.tokens.map(fix) })) } : {}),
  }
}

/** Route search -> kit query + sort id. Accepts both old links and links this module wrote. */
export function decodeFeedSearch(search: Pick<FeedRouteSearch, 'q' | 'f' | 'op' | 'sort'>): { query: Query; sortId: string } {
  const params = new URLSearchParams()
  if (search.q) params.set('q', search.q)
  if (search.f) params.set('f', search.f)
  if (search.op === 'or') params.set('op', 'or')
  const state = feedCodec.decode(params)
  return { query: rekey(state.query), sortId: resolveSortId(search.sort) }
}

/** Kit query + sort id -> route search (scroll resets: a new query starts at the top). */
export function encodeFeedSearch(query: Query, sortId: string): FeedRouteSearch {
  const params = new URLSearchParams(feedCodec.encode({ query, sort: sortId }))
  return {
    q: params.get('q') ?? '',
    f: params.get('f') ?? '',
    op: params.get('op') === 'or' ? 'or' : 'and',
    sort: resolveSortId(params.get('sort') ?? DEFAULT_SORT_ID),
    scroll: 0,
  }
}

// --- legacy token grammar, kept only so Home / Projects can build deep links (`f=key|op|value;...`) ---
export interface PropertyFilterQuery {
  tokens: { propertyKey: string; operator: string; value: string }[]
  operation?: 'and' | 'or'
}

export function serializeFilterQuery(query: PropertyFilterQuery): string {
  return query.tokens
    .map((t) => `${encodeURIComponent(t.propertyKey)}|${encodeURIComponent(t.operator)}|${encodeURIComponent(t.value)}`)
    .join(';')
}

export function parseFilterQuery(f: string, op: 'and' | 'or'): PropertyFilterQuery {
  if (!f.trim()) return { tokens: [], operation: op }
  const tokens = f
    .split(';')
    .map((part) => {
      const [propertyKey, operator, ...rest] = part.split('|')
      if (!propertyKey || !operator || rest.length === 0) return null
      return { propertyKey: decodeURIComponent(propertyKey), operator: decodeURIComponent(operator), value: decodeURIComponent(rest.join('|')) }
    })
    .filter((t): t is PropertyFilterQuery['tokens'][number] => t !== null)
  return { tokens, operation: op }
}

export function feedSearchToParams(search: FeedRouteSearch): URLSearchParams {
  const params = new URLSearchParams()
  if (search.q) params.set('q', search.q)
  if (search.f) params.set('f', search.f)
  if (search.op !== 'and') params.set('op', search.op)
  if (search.sort !== DEFAULT_SORT_ID) params.set('sort', search.sort)
  if (search.scroll > 0) params.set('scroll', String(search.scroll))
  return params
}

export function persistFeedReturnSearch(search: FeedRouteSearch): void {
  try {
    const qs = feedSearchToParams(search).toString()
    sessionStorage.setItem(FEED_RETURN_STORAGE_KEY, qs ? `?${qs}` : '')
  } catch {
    // sessionStorage unavailable (SSR/tests)
  }
}

export function loadFeedReturnSearch(): FeedRouteSearch {
  try {
    const stored = sessionStorage.getItem(FEED_RETURN_STORAGE_KEY)
    if (!stored) return FEED_SEARCH_DEFAULTS
    const params = new URLSearchParams(stored.startsWith('?') ? stored.slice(1) : stored)
    return parseFeedSearch(Object.fromEntries(params.entries()))
  } catch {
    return FEED_SEARCH_DEFAULTS
  }
}
