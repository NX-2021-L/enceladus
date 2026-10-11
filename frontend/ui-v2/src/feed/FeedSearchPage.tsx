import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearch } from '@tanstack/react-router'
import type { IndexRow, Query } from '@io-kit/search'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { Alert } from '../design-system'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { FeedReadingPane } from '../routes/FeedReadingPane'
import { RecentlyViewedNav } from '../routes/RecentlyViewedNav'
import { useUiStore } from '../store/uiStore'
import { SearchSplitPage } from '../search/SearchSplitPage'
import { useEnceladusCorpus } from '../search/CorpusProvider'
import { decodeFeedSearch, encodeFeedSearch, persistFeedReturnSearch, type FeedRouteSearch } from '../search/feedUrl'
import { hostSearchSource } from '../search/enceladusSearchSource'
import { ENCELADUS_PROPERTIES } from '../search/propertyDefs'
import { getRecentlyViewed, hitFromRecent, trackRecentlyViewed } from '../search/recentlyViewed'
import { ENCELADUS_SIGNAL_AVAILABILITY, rowToHit } from '../search/rowHit'
import { localSavedFilterStore, migrateLegacySavedSearches } from '../search/savedSearchMigration'
import { SORT_OPTIONS } from '../search/sortOptions'
import type { SearchResultHit } from '../types/search'
import { renderFeedRow } from './FeedRowCard'
// DVP-TSK-995: the kit search skin loads with this (lazy) route chunk, never with the initial route.
import '@io-kit/search-ui/theme.css'
import '@io-kit/search-ui/components.css'
import '@io-kit/search-ui/themes/enceladus.css'
import '../routes/feed.css'

// R16: the split (and the reading pane) starts at the kit's 960px switch.
const WIDE_MEDIA = '(min-width: 960px)'
const HYBRID_CAP_MS = 15_000
const DATE_PRESETS = [
  { key: '1d', days: 1 },
  { key: '7d', days: 7 },
  { key: '30d', days: 30 },
]

/**
 * DVP-TSK-995 (kit search 1.0): /feed on the kit `CollectionSearch`. Two rows before the results (the search input;
 * Filter / Sort / Clear), 10-character pills, the count in the header and no header action. The corpus index
 * (`useCorpusIndex` in CorpusProvider) feeds `useCollectionSearch` inside the component; the existing record cards and
 * reading pane render through `renderRow`.
 */
export default function FeedSearchPage() {
  useDocumentTitle('Feed')
  const feedSearch = useSearch({ from: '/feed' })
  const navigate = useNavigate({ from: '/feed' })
  const corpus = useEnceladusCorpus()
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const { query, sortId } = decodeFeedSearch(feedSearch)
  // focus=1 (header SearchLauncher) is a one-shot mount hint; it never enters the persisted return search.
  const autoFocus = feedSearch.focus === 1
  // React Compiler memoizes this by its inputs; the effect below only re-runs when a persisted field changes.
  const persistable: FeedRouteSearch = { q: feedSearch.q, f: feedSearch.f, op: feedSearch.op, sort: feedSearch.sort, scroll: feedSearch.scroll }
  // The legacy saved searches move into the kit store once, before the component reads it.
  const [store] = useState(() => {
    migrateLegacySavedSearches(localSavedFilterStore)
    return localSavedFilterStore
  })

  const patch = (nextQuery: Query, nextSortId: string) => {
    const next = encodeFeedSearch(nextQuery, nextSortId)
    persistFeedReturnSearch(next)
    void navigate({ search: next, replace: true })
  }

  const [isWide, setIsWide] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia(WIDE_MEDIA)
    const sync = () => setIsWide(mq.matches)
    sync()
    mq.addEventListener('change', sync)
    return () => mq.removeEventListener('change', sync)
  }, [])
  useEffect(() => {
    persistFeedReturnSearch(persistable)
  }, [persistable])

  const [chosen, setChosen] = useState<SearchResultHit | null>(null)
  const [firstHit, setFirstHit] = useState<SearchResultHit | null>(null)
  const firstRef = useRef<SearchResultHit | null>(null)
  // The first visible row is the reading pane's default; rows report it while they render.
  // eslint-disable-next-line react-hooks/exhaustive-deps -- runs after every render on purpose; setFirstHit bails out when the id is unchanged
  useEffect(() => {
    const next = firstRef.current
    setFirstHit((prev) => (prev?.recordId === next?.recordId ? prev : next))
  })
  const selectedHit = isWide ? (chosen ?? firstHit) : null
  const recentItems = useUiStore((s) => s.recentItems)
  const setRecentItems = useUiStore((s) => s.setRecentItems)
  const selectedId = selectedHit?.recordId ?? null
  const selectedType = selectedHit?.recordType
  useEffect(() => {
    if (!selectedHit) return
    trackRecentlyViewed(selectedHit)
    setRecentItems(getRecentlyViewed(selectedHit.recordType))
    // keyed on the selection identity, not the hit object (rebuilt every render)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, selectedType])

  const renderRow = (row: IndexRow, ctx: { index: number; hybrid: boolean; evidence?: import('@io-kit/search').SignalEvidence[] }) => {
    const hit = rowToHit(row, ctx.hybrid)
    if (ctx.index === 0) firstRef.current = hit
    return renderFeedRow(hit, {
      projects,
      isWide,
      selectedHit,
      onSelect: setChosen,
      onLeave: () => persistFeedReturnSearch(persistable),
      evidenceFor: (id) => (id === hit.recordId ? ctx.evidence : undefined),
      availability: ENCELADUS_SIGNAL_AVAILABILITY,
    })
  }

  const projectId = projects[0]?.project_id ?? 'enceladus'
  const stale = corpus.staleNotice ? (
    <div className="feed-route__stale">
      <Alert type="warning" header="Results may be out of date">
        {corpus.staleNotice}
      </Alert>
    </div>
  ) : null

  // R16: header across both columns (count from the search state), pinned search rows + scrolling results on the left,
  // the record detail hub as its own scroller on the right; below 960px a single column in the page scroll.
  return (
    <SearchSplitPage
      className="feed-route"
      engine="kit-search"
      above={stale}
      {...(isWide
        ? {
            actions: (
              <RecentlyViewedNav
                items={recentItems}
                currentRecordId={selectedHit?.recordId ?? null}
                onSelect={(entry) => setChosen(hitFromRecent(entry))}
              />
            ),
            secondary: (
              <div className="feed-route__pane">
                <FeedReadingPane hit={selectedHit} />
              </div>
            ),
          }
        : {})}
      search={{
        title: 'Feed',
        things: 'records',
        rows: corpus.rows,
        properties: ENCELADUS_PROPERTIES,
        query,
        onQueryChange: (next) => patch(next, sortId),
        sortOptions: SORT_OPTIONS,
        sortId,
        onSortChange: (id) => patch(query, id),
        dateRange: { propertyKey: 'updated_at', presets: DATE_PRESETS },
        savedFilters: { store, surface: 'feed' },
        hybrid: { source: hostSearchSource, filters: { project_id: projectId }, hardCapMs: HYBRID_CAP_MS },
        corpusPending: corpus.status === 'seeding' && corpus.rows.length === 0,
        error: corpus.status === 'error' ? corpus.error : null,
        placeholder: 'Search records',
        pageSize: 50,
        restoreKey: 'feed',
        autoFocus,
        renderRow,
      }}
    />
  )
}
