import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { relateRecords } from '../api/actions'
import { resolveFeedEngine } from '../feed/feedEngine'
import { Alert } from '../design-system'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { feedCorpusQueryOptions } from '../api/feedCorpusQueryOptions'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { useRealtimeFeed, useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { applyPropertyFilter } from '../search/applyPropertyFilter'
import { FeedPropertyFilter } from '../search/FeedPropertyFilter'
import {
  parseFilterQuery,
  persistFeedReturnSearch,
  serializeFilterQuery,
  type FeedRouteSearch,
} from '../search/feedSearchParams'
import {
  getRecentlyViewed,
  hitFromRecent,
  trackRecentlyViewed,
} from '../search/recentlyViewed'
import { buildSearchCorpus, mergeEventRowOntoCache } from '../search/searchCorpus'
import { excludeRecordType } from '../search/recordTypeScope'
import { sortSearchHits } from '../search/sortSearchHits'
import { useTieredSearch } from '../search/useTieredSearch'
import { getCacheEngine } from '../sync/cacheEngine'
import { useCacheEngineState } from '../sync/CacheEngineProvider'
import { staleCorpusNotice } from '../sync/staleNotice'
import {
  useKeystrokeSuggestionTelemetry,
  useRequestFirstPageTelemetry,
} from '../search/useSearchTelemetry'
import { useUiStore } from '../store/uiStore'
import type { SearchResultHit } from '../types/search'
import { FeedHeader, FeedMeta, FeedToolbar, useSavedSearches } from '../feed/FeedChrome'
import { renderFeedRow, type PinState } from '../feed/FeedRowCard'
import { FeedReadingPane } from './FeedReadingPane'
import { RecentlyViewedNav } from './RecentlyViewedNav'
import { useFeedScrollRestore } from './useFeedScrollRestore'
import './feed.css'

const LIST_CHUNK = 24
const WIDE_MEDIA = '(min-width: 64rem)'
// DVP-TSK-931: the @io-kit/feed panel is the default engine; ?feed=legacy keeps LegacyFeedRoute for one release.
const KitFeedPanel = lazy(() => import('../feed/KitFeedPanel'))

export function FeedRoute() {
  const [engine] = useState(() => resolveFeedEngine())
  if (engine === 'kit') {
    return (
      <Suspense fallback={null}>
        <KitFeedPanel />
      </Suspense>
    )
  }
  return <LegacyFeedRoute />
}

function LegacyFeedRoute() {
  useDocumentTitle('Feed')
  const feedSearch = useSearch({ from: '/feed' })
  const navigate = useNavigate({ from: '/feed' })
  const { q, f, op, sort, scroll } = feedSearch

  const [isWide, setIsWide] = useState(false)
  const [selectedHit, setSelectedHit] = useState<SearchResultHit | null>(null)
  const [visibleCount, setVisibleCount] = useState(LIST_CHUNK)
  const recentItems = useUiStore((s) => s.recentItems)
  const setRecentItems = useUiStore((s) => s.setRecentItems)
  const listRef = useRef<HTMLDivElement>(null)

  const filterQuery = parseFilterQuery(f, op)

  // AC-16: React Compiler owns memoization -- no manual useCallback.
  const patchFeedSearch = (patch: Partial<FeedRouteSearch>, replace = true) => {
    navigate({
      search: (prev) => {
        const next = { ...prev, ...patch }
        persistFeedReturnSearch(next)
        return next
      },
      replace,
    })
  }

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const { isHydrating, refetchSnapshot } = useRealtimeFeed()
  const events = useRealtimeFeedEvents()
  const { isWarm, indexRows, seedError, lastSeededAt } = useCacheEngineState()
  const staleNotice = staleCorpusNotice(seedError, lastSeededAt)
  const corpus = (() => {
    const fromEvents = buildSearchCorpus(events, projects)
    if (!isWarm) return fromEvents
    // ENC-TSK-P60 (ENC-ISS-718/719): events used to REPLACE the warm cache
    // row wholesale, stomping governed status/priority/updatedAt with the
    // thin event projection and reshuffling counts on every batch. The cache
    // row is the base; the event contributes only the fields it truly has.
    // ENC-TSK-Q33: indexRows is provider state, so a completed seed repaints.
    const byId = new Map(indexRows.map((row) => [row.recordId, row]))
    for (const row of fromEvents) {
      const existing = byId.get(row.recordId)
      byId.set(row.recordId, existing ? mergeEventRowOntoCache(existing, row) : row)
    }
    return [...byId.values()]
  })()
  // ENC-TSK-P60 (ENC-ISS-718): documents are part of the searchable corpus —
  // the page promises "every governed record type" and the record_type=
  // document filter must agree with the server facets. (Supersedes the
  // ENC-TSK-L32 reciprocal exclusion; /docs remains the doc-first surface
  // and keeps the suggestion stream to itself below.)
  const feedCorpus = corpus
  const projectId = projects[0]?.project_id ?? 'enceladus'

  const tiered = useTieredSearch({ projectId, query: q }, feedCorpus)
  // DVP-TSK-921: onPin -> tracker.relate. Pins the row to the record open in the reading pane.
  const [pins, setPins] = useState<Record<string, PinState>>({})
  function pinToSelected(sourceId: string, targetId: string) {
    setPins((p) => ({ ...p, [targetId]: 'pending' }))
    relateRecords(sourceId, targetId).then(
      () => setPins((p) => ({ ...p, [targetId]: 'done' })),
      () => setPins((p) => ({ ...p, [targetId]: 'error' })),
    )
  }
  // ENC-TSK-P60: one limit-1 corpus request — the backend computes
  // total_matches over the whole set before slicing.
  const serverCorpusQuery = useQuery(feedCorpusQueryOptions({ limit: 1 }))
  const serverCorpusTotal = serverCorpusQuery.data?.total_matches ?? null
  const filteredHits = sortSearchHits(applyPropertyFilter(tiered.hits, filterQuery), sort)
  const visibleHits = filteredHits.slice(0, visibleCount)

  const hybridEnabled = Boolean(q.trim())
  const requestKey = `${q}|${f}|${op}|${sort}`
  useRequestFirstPageTelemetry(requestKey, hybridEnabled, tiered.hybridPending)

  const searchSuggestions = isWarm
    ? excludeRecordType(getCacheEngine().searchIndex.suggest(q, 12), 'document').map((row) => ({
        value: row.recordId,
        description: row.title,
        tag: row.recordType,
      }))
    : feedCorpus
        .filter((row) => {
          const needle = q.trim().toLowerCase()
          if (!needle) return true
          return row.recordId.toLowerCase().includes(needle) || row.title.toLowerCase().includes(needle)
        })
        .slice(0, 12)
        .map((row) => ({
          value: row.recordId,
          description: row.title,
          tag: row.recordType,
        }))

  const suggestionsKey = searchSuggestions.map((row) => row.value).join(',')
  const { markKeystroke } = useKeystrokeSuggestionTelemetry(suggestionsKey)

  const selectHit = (hit: SearchResultHit) => {
    setSelectedHit(hit)
    trackRecentlyViewed(hit)
    setRecentItems(getRecentlyViewed(hit.recordType))
  }

  useFeedScrollRestore(scroll, isWide, listRef, (nextScroll) => patchFeedSearch({ scroll: nextScroll }), filteredHits.length > 0)

  useEffect(() => {
    persistFeedReturnSearch(feedSearch)
  }, [feedSearch])

  useEffect(() => {
    const mq = window.matchMedia(WIDE_MEDIA)
    const sync = () => setIsWide(mq.matches)
    sync()
    mq.addEventListener('change', sync)
    return () => mq.removeEventListener('change', sync)
  }, [])

  useEffect(() => {
    setVisibleCount(LIST_CHUNK)
  }, [q, f, op, sort, filteredHits.length])

  useEffect(() => {
    if (!isWide) {
      setSelectedHit(null)
      return
    }
    if (filteredHits.length === 0) {
      setSelectedHit(null)
      return
    }
    if (selectedHit && filteredHits.some((h) => h.recordId === selectedHit.recordId)) {
      return
    }
    const first = filteredHits[0]!
    setSelectedHit(first)
    trackRecentlyViewed(first)
    setRecentItems(getRecentlyViewed(first.recordType))
  }, [isWide, filteredHits, selectedHit, setRecentItems])

  useEffect(() => {
    if (isWide) return
    const onScroll = () => {
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 160) {
        setVisibleCount((count) => Math.min(filteredHits.length, count + LIST_CHUNK))
      }
    }
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [isWide, filteredHits.length])

  useEffect(() => {
    const node = listRef.current
    if (!node || !isWide) return
    const onScroll = () => {
      if (node.scrollTop + node.clientHeight >= node.scrollHeight - 120) {
        setVisibleCount((count) => Math.min(filteredHits.length, count + LIST_CHUNK))
      }
    }
    node.addEventListener('scroll', onScroll)
    return () => node.removeEventListener('scroll', onScroll)
  }, [filteredHits.length, isWide])

  const { savedItems, handleSavedClick } = useSavedSearches(q, filterQuery, patchFeedSearch)

  // ENC-TSK-M35: one dense feed-row rendering for every viewport (Feed.dc.html
  // §pixel-contract, Enceladus-v4-Feed-Review.md §3 PAR-08) — v4 previously
  // forked mobile (RecordCard grid) from desktop (Cloudscape Cards), and the
  // desktop fork showed only STATUS/TIER/PROJECT with no priority/CCI/accent.
  // Narrow viewports link straight to the full record page; wide viewports
  // select in place (no navigation) so the row list and reading pane stay in
  // sync (FTR-128 AC-18).
  const renderRow = (hit: SearchResultHit) =>
    renderFeedRow(hit, {
      projects,
      isWide,
      selectedHit,
      onSelect: selectHit,
      onLeave: () => persistFeedReturnSearch(feedSearch),
      tiered,
      pins,
      onPin: pinToSelected,
    })

  const resultsBody =
    isWide && filteredHits.length > 0 ? (
      <div className="feed-route__split">
        <div className="feed-route__list-scroll" ref={listRef}>
          {visibleHits.map(renderRow)}
          {visibleCount < filteredHits.length && (
            <p className="feed-route__scroll-hint">Scroll for more results…</p>
          )}
        </div>
        <div className="feed-route__pane">
          <RecentlyViewedNav
            items={recentItems}
            currentRecordId={selectedHit?.recordId ?? null}
            onSelect={(entry) => selectHit(hitFromRecent(entry))}
          />
          <FeedReadingPane hit={selectedHit} />
        </div>
      </div>
    ) : (
      <div className="ev2-rc-grid">{visibleHits.map(renderRow)}</div>
    )

  return (
    <div className="feed-route">
      <FeedHeader />

      {staleNotice && (
        <div className="feed-route__stale">
          <Alert type="warning" header="Results may be out of date">
            {staleNotice}
          </Alert>
        </div>
      )}

      <FeedToolbar
        q={q}
        sort={sort}
        suggestions={searchSuggestions}
        savedItems={savedItems}
        onSavedItemClick={handleSavedClick}
        onQueryChange={(value) => {
          markKeystroke()
          patchFeedSearch({ q: value, scroll: 0 })
        }}
        onSortChange={(next) => {
          // ENC-TSK-N56: switch the sort immediately (client-side reorder) AND re-trigger the realtime feed
          // snapshot fetch so the corpus is refreshed and re-flattened.
          patchFeedSearch({ sort: next, scroll: 0 })
          refetchSnapshot()
        }}
      />

      <FeedPropertyFilter
        query={filterQuery}
        corpus={feedCorpus}
        onChange={(next) =>
          patchFeedSearch({
            f: serializeFilterQuery(next),
            op: next.operation ?? 'and',
            scroll: 0,
          })
        }
      />

      <FeedMeta count={filteredHits.length} serverCorpusTotal={serverCorpusTotal} tiered={tiered} />

      {isHydrating && filteredHits.length === 0 && (
        <p className="feed-route__empty">Loading feed snapshot…</p>
      )}
      {!isHydrating && filteredHits.length === 0 && (
        <p className="feed-route__empty">
          No results — adjust search or filters.
          {(q || f) && (
            <button
              type="button"
              className="feed-route__empty-action"
              onClick={() => patchFeedSearch({ q: '', f: '' })}
            >
              Clear filters
            </button>
          )}
        </p>
      )}

      {filteredHits.length > 0 ? resultsBody : null}
    </div>
  )
}
