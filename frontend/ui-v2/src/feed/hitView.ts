import type { Feed, FeedState } from '@io-kit/feed'
import type { SearchResultHit } from '../types/search'

/**
 * DVP-TSK-931: a Feed whose items are the host's search hits. The kit owns paging, deltas, realtime and scroll
 * anchors on the base feed; the host owns search, property filters and sort over the loaded corpus. FeedList
 * (which renders feed.getState().items) is pointed at this view, so one component windows exactly the rows the
 * legacy list shows. Everything but getState/subscribe/source delegates to the base feed.
 */
export interface HitView extends Feed<SearchResultHit, unknown> {
  setHits(hits: SearchResultHit[]): void
}

const sig = (h: SearchResultHit) => `${h.recordId}|${h.updatedAt ?? ''}|${h.status ?? ''}|${h.priority ?? ''}|${h.checkoutState ?? ''}|${h.title}`

export function createHitView<T>(base: Feed<T, never>): HitView {
  let hits: SearchResultHit[] = []
  let hitsSig = ''
  let cache: { base: FeedState<T>; hits: SearchResultHit[]; out: FeedState<SearchResultHit> } | null = null
  const own = new Set<() => void>()
  const view = Object.create(base) as HitView
  view.getState = () => {
    const b = base.getState()
    if (!cache || cache.base !== b || cache.hits !== hits) {
      cache = { base: b, hits, out: { ...(b as unknown as FeedState<SearchResultHit>), items: hits } }
    }
    return cache.out
  }
  view.subscribe = (listener) => {
    own.add(listener)
    const off = base.subscribe(listener)
    return () => {
      own.delete(listener)
      off()
    }
  }
  Object.defineProperty(view, 'source', { value: { getId: (h: SearchResultHit) => h.recordId } })
  view.setHits = (next) => {
    const s = next.map(sig).join('\n')
    if (s === hitsSig && next.length === hits.length) return
    hitsSig = s
    hits = next
    for (const l of [...own]) l()
  }
  return view
}

/**
 * DVP-TSK-931: the meta-line count. The legacy route searches the fully seeded warm cache, so with no query and
 * no property filter its count equals the corpus size. The kit pages the corpus in, so in that case the count is
 * the server corpus total instead of the number of rows loaded so far.
 */
export function feedHitCount(loaded: number, serverCorpusTotal: number | null, q: string, f: string): number {
  if (q.trim() || f.trim() || serverCorpusTotal === null) return loaded
  return Math.max(loaded, serverCorpusTotal)
}
