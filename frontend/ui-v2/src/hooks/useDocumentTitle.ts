import { useEffect } from 'react'

/**
 * Sets `document.title` for the current route (ENC-TSK-M25 / FTR-130 Band B).
 *
 * Titles are a UX navigation aid — browser tab-search, history, and
 * bookmarks — not an SEO surface, so callers must NOT include any shared
 * branding token ("Enceladus", etc.) in the string passed here.
 *
 * Two call sites cover the two ACs:
 *   - List/landing routes call this once with a static short page name
 *     ("Home", "Feed", "Coordination", …).
 *   - Record/document detail routes call this from a component that only
 *     renders after the record's data has resolved (e.g. inside the
 *     `useSuspenseQuery` consumer, past the route's Suspense boundary), so
 *     the title reflects loaded content immediately — never a stale
 *     placeholder — and re-fires on every client-side navigation because the
 *     effect dependency changes with the derived title string.
 */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    if (!title) return
    document.title = title
  }, [title])
}
