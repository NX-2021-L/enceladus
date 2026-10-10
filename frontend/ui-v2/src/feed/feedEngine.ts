/**
 * DVP-TSK-919: which feed engine /feed uses. 'legacy' (src/sync cache engine + search) is the default this
 * release; '?feed=kit' (or localStorage ev2.feed.engine=kit) mounts the @io-kit/feed panel. The flip and the
 * removal of src/sync's feed paging are the follow-on once the kit engine is verified live.
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
