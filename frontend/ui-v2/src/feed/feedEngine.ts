/**
 * DVP-TSK-919 / DVP-TSK-924 / DVP-TSK-930 / DVP-TSK-931: which feed engine /feed uses. 'kit' (@io-kit/feed 1.1:
 * keyset paging, deltas, measured-height virtualization) is the default again now that KitFeedPanel renders the
 * original page (header, toolbar, record cards, filters, reading pane). '?feed=legacy' (or localStorage
 * ev2.feed.engine=legacy) keeps the src/sync engine for one release as the rollback path.
 */
export type FeedEngine = 'kit' | 'legacy'
export const FEED_ENGINE_STORAGE_KEY = 'ev2.feed.engine'
export const DEFAULT_FEED_ENGINE: FeedEngine = 'kit'

const parse = (v: string | null | undefined): FeedEngine | null => {
  const s = v?.trim().toLowerCase()
  return s === 'kit' || s === 'legacy' ? s : null
}

export function resolveFeedEngine(
  search: string = typeof window === 'undefined' ? '' : window.location.search,
  preference?: string | null,
): FeedEngine {
  let pref = preference
  if (pref === undefined) {
    try {
      pref = typeof window === 'undefined' ? null : window.localStorage.getItem(FEED_ENGINE_STORAGE_KEY)
    } catch {
      pref = null
    }
  }
  return parse(new URLSearchParams(search).get('feed')) ?? parse(pref) ?? DEFAULT_FEED_ENGINE
}
