/**
 * DVP-TSK-919 / DVP-TSK-924 / DVP-TSK-930: which feed engine /feed uses. 'legacy' (the original feed design on the
 * src/sync cache engine) is the default again: the kit panel's fixed-height rows overlapped two-line titles and it
 * lacks the original cards, chips, search and reading pane (regression on prod 0e2116b). '?feed=kit' (or
 * localStorage ev2.feed.engine=kit) opts into the @io-kit/feed panel until its design-parity follow-on lands.
 */
export type FeedEngine = 'kit' | 'legacy'
export const FEED_ENGINE_STORAGE_KEY = 'ev2.feed.engine'
export const DEFAULT_FEED_ENGINE: FeedEngine = 'legacy'

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
