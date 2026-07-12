import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import { Autosuggest, ButtonDropdown } from '../design-system'
import { projectRegistryQueryOptions, resolveProjectFromRecordId } from '../api/projectRegistry'
import { Badge } from '../components/Badge'
import { RecordCard } from '../components/RecordCard'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { formatRelativeTime } from '../format/relativeTime'
import { useRealtimeFeed, useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { applyPropertyFilter } from '../search/applyPropertyFilter'
import { FeedPropertyFilter } from '../search/FeedPropertyFilter'
import {
  feedRowAccent,
  priorityBadgeColor,
  sessionStateBadge,
} from '../search/feedRowPresentation'
import {
  parseFilterQuery,
  persistFeedReturnSearch,
  serializeFilterQuery,
  type FeedRouteSearch,
  type FeedSort,
} from '../search/feedSearchParams'
import {
  deleteSavedSearch,
  loadSavedSearches,
  saveCurrentSearch,
  type SavedSearch,
} from '../search/savedSearches'
import {
  getRecentlyViewed,
  hitFromRecent,
  trackRecentlyViewed,
} from '../search/recentlyViewed'
import { buildSearchCorpus } from '../search/searchCorpus'
import { excludeRecordType } from '../search/recordTypeScope'
import { sortSearchHits } from '../search/sortSearchHits'
import { useTieredSearch } from '../search/useTieredSearch'
import { getCacheEngine } from '../sync/cacheEngine'
import { useCacheEngineState } from '../sync/CacheEngineProvider'
import {
  useKeystrokeSuggestionTelemetry,
  useRequestFirstPageTelemetry,
} from '../search/useSearchTelemetry'
import { useFeedConnectionStore } from '../store/feedConnectionStore'
import { useUiStore } from '../store/uiStore'
import { documentHref, recordHrefForType } from '../routes/recordLink'
import type { SearchResultHit } from '../types/search'
import { FeedReadingPane } from './FeedReadingPane'
import { RecentlyViewedNav } from './RecentlyViewedNav'
import { useFeedScrollRestore } from './useFeedScrollRestore'
import './feed.css'

const LIST_CHUNK = 24
const WIDE_MEDIA = '(min-width: 64rem)'
const SORT_OPTIONS: { value: FeedSort; label: string }[] = [
  { value: 'tier', label: 'Tier (default)' },
  { value: 'id', label: 'Record ID' },
  { value: 'title', label: 'Title' },
  { value: 'status', label: 'Status' },
]

export function FeedRoute() {
  useDocumentTitle('Feed')
  const feedSearch = useSearch({ from: '/feed' })
  const navigate = useNavigate({ from: '/feed' })
  const { q, f, op, sort, scroll } = feedSearch

  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(() => loadSavedSearches())
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
  const { isHydrating } = useRealtimeFeed()
  const events = useRealtimeFeedEvents()
  const { isWarm } = useCacheEngineState()
  const corpus = (() => {
    const fromEvents = buildSearchCorpus(events, projects)
    if (!isWarm) return fromEvents
    const byId = new Map(getCacheEngine().searchIndex.all().map((row) => [row.recordId, row]))
    for (const row of fromEvents) byId.set(row.recordId, row)
    return [...byId.values()]
  })()
  // ENC-TSK-L32: feed search is reciprocally scoped to exclude document
  // records — the Docs page (DocsRoute) owns document-scoped search.
  const feedCorpus = excludeRecordType(corpus, 'document')
  const projectId = projects[0]?.project_id ?? 'enceladus'

  const tiered = useTieredSearch({ projectId, query: q }, feedCorpus)
  const filteredHits = excludeRecordType(sortSearchHits(applyPropertyFilter(tiered.hits, filterQuery), sort), 'document')
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

  const keystrokeP50 = useFeedConnectionStore((s) => s.keystrokeSuggestion.p50Ms)
  const keystrokeP95 = useFeedConnectionStore((s) => s.keystrokeSuggestion.p95Ms)
  const localP50 = useFeedConnectionStore((s) => s.requestFirstPageLocal.p50Ms)
  const localP95 = useFeedConnectionStore((s) => s.requestFirstPageLocal.p95Ms)
  const serverP50 = useFeedConnectionStore((s) => s.requestFirstPageServer.p50Ms)
  const serverP95 = useFeedConnectionStore((s) => s.requestFirstPageServer.p95Ms)

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

  const savedItems = [
    ...savedSearches.map((s) => ({
      id: s.id,
      text: s.name,
      description: s.query || `${s.filterQuery.tokens.length} filters`,
    })),
    ...(savedSearches.length > 0 ? [{ id: '__divider', type: 'divider' as const }] : []),
    { id: '__save', text: 'Save current search…' },
    ...savedSearches.map((s) => ({
      id: `__delete:${s.id}`,
      text: `Delete “${s.name}”`,
      danger: true,
    })),
  ]

  const handleSavedClick = (id: string | undefined) => {
    if (!id) return
    if (id === '__save') {
      const name = window.prompt('Name this search')
      if (!name) return
      setSavedSearches(saveCurrentSearch(savedSearches, name, q, filterQuery))
      return
    }
    if (id.startsWith('__delete:')) {
      const target = id.slice('__delete:'.length)
      setSavedSearches(deleteSavedSearch(savedSearches, target))
      return
    }
    const saved = savedSearches.find((s) => s.id === id)
    if (!saved) return
    patchFeedSearch({
      q: saved.query,
      f: serializeFilterQuery(saved.filterQuery),
      op: saved.filterQuery.operation ?? 'and',
      scroll: 0,
    })
  }

  // ENC-TSK-M35: one dense feed-row rendering for every viewport (Feed.dc.html
  // §pixel-contract, Enceladus-v4-Feed-Review.md §3 PAR-08) — v4 previously
  // forked mobile (RecordCard grid) from desktop (Cloudscape Cards), and the
  // desktop fork showed only STATUS/TIER/PROJECT with no priority/CCI/accent.
  // Narrow viewports link straight to the full record page; wide viewports
  // select in place (no navigation) so the row list and reading pane stay in
  // sync (FTR-128 AC-18).
  const renderFeedRow = (hit: SearchResultHit) => {
    const project =
      hit.projectId || resolveProjectFromRecordId(hit.recordId, projects) || 'enceladus'
    const href =
      hit.recordType === 'document'
        ? documentHref(hit.recordId)
        : recordHrefForType(project, hit.recordType, hit.recordId)
    const cci = sessionStateBadge(hit.checkoutState)

    return (
      <RecordCard
        key={hit.recordId}
        recordId={hit.recordId}
        recordType={hit.recordType}
        title={hit.title}
        status={hit.status}
        priority={hit.priority}
        variant="feed"
        projectLabel={project}
        timestamp={formatRelativeTime(hit.updatedAt) ?? undefined}
        accentColor={feedRowAccent(hit)}
        badges={
          <>
            {hit.priority ? <Badge color={priorityBadgeColor(hit.priority)}>{hit.priority}</Badge> : null}
            {cci ? <Badge color={cci.color}>{cci.label}</Badge> : null}
          </>
        }
        {...(isWide
          ? { selected: selectedHit?.recordId === hit.recordId, onSelect: () => selectHit(hit) }
          : { href, onSelect: () => persistFeedReturnSearch(feedSearch) })}
      />
    )
  }

  const resultsBody =
    isWide && filteredHits.length > 0 ? (
      <div className="feed-route__split">
        <div className="feed-route__list-scroll" ref={listRef}>
          {visibleHits.map(renderFeedRow)}
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
      <div className="ev2-rc-grid">{visibleHits.map(renderFeedRow)}</div>
    )

  return (
    <div className="feed-route">
      <header className="feed-route__header">
        <p className="feed-route__eyebrow">FEED · LIVE</p>
        <h1 className="feed-route__title">Results</h1>
        <p className="feed-route__subtitle">
          Search across every governed record type. Filters and scroll position are preserved on
          your way back.
        </p>
      </header>

      <div className="feed-route__toolbar">
        <div className="feed-route__search">
          <Autosuggest
            value={q}
            options={searchSuggestions}
            placeholder="Search records or saved name…"
            ariaLabel="Feed search"
            onChange={(event) => {
              markKeystroke()
              patchFeedSearch({ q: event.detail.value, scroll: 0 })
            }}
          />
        </div>
        <label className="feed-route__sort">
          <span>Sort</span>
          <select
            value={sort}
            onChange={(event) =>
              patchFeedSearch({ sort: event.target.value as FeedSort, scroll: 0 })
            }
          >
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <ButtonDropdown items={savedItems} onItemClick={(event) => handleSavedClick(event.detail.id)}>
          Saved searches
        </ButtonDropdown>
      </div>

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

      <div className="feed-route__meta">
        <span>
          {filteredHits.length} hit{filteredHits.length === 1 ? '' : 's'}
          {tiered.hybridPending ? ' · hybrid loading…' : ''}
        </span>
        {tiered.hybridError && (
          <span className="feed-route__meta-error">{tiered.hybridError.message}</span>
        )}
        {(keystrokeP50 !== null || localP50 !== null || serverP50 !== null) && (
          // ENC-ISS-513 / FND-01: this used to render inline, unconditionally
          // visible, AND duplicated verbatim in the always-open Feed rail.
          // It's the only copy now, and it's tucked behind a disclosure so
          // the timing detail doesn't compete with the results themselves.
          <details className="feed-route__telemetry">
            <summary>Timing</summary>
            {keystrokeP50 !== null && (
              <div>
                keystroke→suggest p50 {Math.round(keystrokeP50)}ms
                {keystrokeP95 !== null ? ` / p95 ${Math.round(keystrokeP95)}ms` : ''}
              </div>
            )}
            {localP50 !== null && (
              <div>
                request→page (local) p50 {Math.round(localP50)}ms
                {localP95 !== null ? ` / p95 ${Math.round(localP95)}ms` : ''}
              </div>
            )}
            {serverP50 !== null && (
              <div>
                request→page (server) p50 {Math.round(serverP50)}ms
                {serverP95 !== null ? ` / p95 ${Math.round(serverP95)}ms` : ''}
              </div>
            )}
          </details>
        )}
      </div>

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
