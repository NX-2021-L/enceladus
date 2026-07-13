import type { PropertyFilterQuery } from './applyPropertyFilter'

export type FeedSort = 'tier' | 'id' | 'status' | 'title' | 'updated'

export interface FeedRouteSearch {
  q: string
  f: string
  op: 'and' | 'or'
  sort: FeedSort
  scroll: number
}

export const FEED_SEARCH_DEFAULTS: FeedRouteSearch = {
  q: '',
  f: '',
  op: 'and',
  // ENC-TSK-N56 (ENC-TSK-N45 UAT follow-up): the feed defaults to most-recently
  // updated first, matching the N45 intent that every feed defaults to
  // time-last-updated, newest to oldest.
  sort: 'updated',
  scroll: 0,
}

export const FEED_RETURN_STORAGE_KEY = 'enc.feed.returnSearch'

const FEED_SORTS: FeedSort[] = ['tier', 'id', 'status', 'title', 'updated']

function isFeedSort(value: unknown): value is FeedSort {
  return typeof value === 'string' && FEED_SORTS.includes(value as FeedSort)
}

export function parseFeedSearch(raw: Record<string, unknown>): FeedRouteSearch {
  const q = typeof raw.q === 'string' ? raw.q : ''
  const f = typeof raw.f === 'string' ? raw.f : ''
  const op = raw.op === 'or' ? 'or' : 'and'
  const sort = isFeedSort(raw.sort) ? raw.sort : 'updated'
  const scrollRaw = raw.scroll
  const scroll =
    typeof scrollRaw === 'number'
      ? scrollRaw
      : typeof scrollRaw === 'string'
        ? Number.parseInt(scrollRaw, 10)
        : 0

  return {
    q,
    f,
    op,
    sort,
    scroll: Number.isFinite(scroll) && scroll > 0 ? Math.round(scroll) : 0,
  }
}

export function serializeFilterQuery(query: PropertyFilterQuery): string {
  if (query.tokens.length === 0) return ''
  return query.tokens
    .map(
      (token) =>
        `${encodeURIComponent(token.propertyKey)}|${encodeURIComponent(token.operator)}|${encodeURIComponent(token.value)}`,
    )
    .join(';')
}

export function parseFilterQuery(f: string, op: 'and' | 'or'): PropertyFilterQuery {
  if (!f.trim()) return { tokens: [], operation: op }
  const tokens = f
    .split(';')
    .map((part) => {
      const segments = part.split('|')
      if (segments.length < 3) return null
      const [propertyKey, operator, ...rest] = segments
      const value = rest.join('|')
      return {
        propertyKey: decodeURIComponent(propertyKey ?? ''),
        operator: decodeURIComponent(operator ?? ''),
        value: decodeURIComponent(value),
      }
    })
    .filter(
      (token): token is PropertyFilterQuery['tokens'][number] =>
        Boolean(token?.propertyKey && token.operator),
    )

  return { tokens, operation: op }
}

export function feedSearchToParams(search: FeedRouteSearch): URLSearchParams {
  const params = new URLSearchParams()
  if (search.q) params.set('q', search.q)
  if (search.f) params.set('f', search.f)
  if (search.op !== 'and') params.set('op', search.op)
  if (search.sort !== 'updated') params.set('sort', search.sort)
  if (search.scroll > 0) params.set('scroll', String(search.scroll))
  return params
}

export function buildFeedPath(search: FeedRouteSearch): string {
  const qs = feedSearchToParams(search).toString()
  return qs ? `/feed?${qs}` : '/feed'
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
