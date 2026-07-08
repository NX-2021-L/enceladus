import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Autosuggest, ButtonDropdown, Cards, ColumnLayout } from '../design-system'
import { projectRegistryQueryOptions, resolveProjectFromRecordId } from '../api/projectRegistry'
import { SearchTierBadge } from '../components/SearchTierBadge'
import { StatusChip } from '../components/StatusChip'
import { RecordCard } from '../components/RecordCard'
import { useRealtimeFeed } from '../realtime/RealtimeFeedProvider'
import { applyPropertyFilter } from '../search/applyPropertyFilter'
import { FeedPropertyFilter } from '../search/FeedPropertyFilter'
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
  type RecentlyViewedEntry,
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
  const feedSearch = useSearch({ from: '/feed' })
  const navigate = useNavigate({ from: '/feed' })
  const { q, f, op, sort, scroll } = feedSearch

  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(() => loadSavedSearches())
  const [isWide, setIsWide] = useState(false)
  const [selectedHit, setSelectedHit] = useState<SearchResultHit | null>(null)
  const [visibleCount, setVisibleCount] = useState(LIST_CHUNK)
  const [recentItems, setRecentItems] = useState<RecentlyViewedEntry[]>([])
  const listRef = useRef<HTMLDivElement>(null)

  const filterQuery = useMemo(() => parseFilterQuery(f, op), [f, op])

  const patchFeedSearch = useCallback(
    (patch: Partial<FeedRouteSearch>, replace = true) => {
      navigate({
        search: (prev) => {
          const next = { ...prev, ...patch }
          persistFeedReturnSearch(next)
          return next
        },
        replace,
      })
    },
    [navigate],
  )

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const { events, isHydrating } = useRealtimeFeed()
  const { isWarm } = useCacheEngineState()
  const corpus = useMemo(() => {
    const fromEvents = buildSearchCorpus(events, projects)
    if (!isWarm) return fromEvents
    const byId = new Map(getCacheEngine().searchIndex.all().map((row) => [row.recordId, row]))
    for (const row of fromEvents) byId.set(row.recordId, row)
    return [...byId.values()]
  }, [events, projects, isWarm])
  // ENC-TSK-L32: feed search is reciprocally scoped to exclude document
  // records — the Docs page (DocsRoute) owns document-scoped search.
  const feedCorpus = useMemo(() => excludeRecordType(corpus, 'document'), [corpus])
  const projectId = projects[0]?.project_id ?? 'enceladus'

  const tiered = useTieredSearch({ projectId, query: q }, feedCorpus)
  const filteredHits = useMemo(
    () => excludeRecordType(sortSearchHits(applyPropertyFilter(tiered.hits, filterQuery), sort), 'document'),
    [tiered.hits, filterQuery, sort],
  )
  const visibleHits = filteredHits.slice(0, visibleCount)

  const hybridEnabled = Boolean(q.trim())
  const requestKey = `${q}|${f}|${op}|${sort}`
  useRequestFirstPageTelemetry(requestKey, hybridEnabled, tiered.hybridPending)

  const searchSuggestions = useMemo(() => {
    if (isWarm) {
      return excludeRecordType(getCacheEngine().searchIndex.suggest(q, 12), 'document')
        .map((row) => ({
          value: row.recordId,
          description: row.title,
          tag: row.recordType,
        }))
    }
    return feedCorpus
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
  }, [feedCorpus, q, isWarm])

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
  }, [isWide, filteredHits, selectedHit])

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

  const cardDefinition = {
    header: (hit: SearchResultHit) => (
      <FeedCardTitle hit={hit} projects={projects} mobile={!isWide} feedSearch={feedSearch} />
    ),
    sections: [
      {
        id: 'status',
        header: 'Status',
        content: (hit: SearchResultHit) => (hit.status ? <StatusChip status={hit.status} /> : '—'),
      },
      {
        id: 'tier',
        header: 'Tier',
        content: (hit: SearchResultHit) => <SearchTierBadge tier={hit.tier} />,
      },
      {
        id: 'project',
        header: 'Project',
        content: (hit: SearchResultHit) => hit.projectId,
      },
    ],
  }

  const resultsBody =
    isWide && filteredHits.length > 0 ? (
      <ColumnLayout columns={2} borders="vertical">
        <div className="feed-route__list-scroll" ref={listRef}>
          <Cards
            items={visibleHits}
            trackBy="recordId"
            columns={1}
            selectionType="single"
            selectedItems={selectedHit ? [selectedHit] : []}
            onSelectionChange={(event) => {
              const next = event.detail.selectedItems[0]
              if (next) selectHit(next)
            }}
            cardDefinition={cardDefinition}
          />
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
      </ColumnLayout>
    ) : (
      <div className="ev2-rc-grid">
        {visibleHits.map((hit) => {
          const project =
            hit.projectId || resolveProjectFromRecordId(hit.recordId, projects) || 'enceladus'
          const href =
            hit.recordType === 'document'
              ? documentHref(hit.recordId)
              : recordHrefForType(project, hit.recordType, hit.recordId)
          return (
            <RecordCard
              key={hit.recordId}
              recordId={hit.recordId}
              recordType={hit.recordType}
              kindLabel={hit.recordType}
              title={hit.title}
              status={hit.status}
              href={href}
              variant="compact"
              trailing={<SearchTierBadge tier={hit.tier} />}
              onSelect={() => persistFeedReturnSearch(feedSearch)}
            />
          )
        })}
      </div>
    )

  return (
    <div className="feed-route">
      <header className="feed-route__header">
        <p className="feed-route__eyebrow">Search 2.0 · Feed</p>
        <h1 className="feed-route__title">Results</h1>
        <p className="feed-route__subtitle">
          Local tier paints instantly; hybrid merges async. Search state lives in the URL so back
          navigation and breadcrumb return restore filters and scroll.
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
          <span className="feed-route__telemetry">
            {keystrokeP50 !== null && (
              <>
                keystroke→suggest p50 {Math.round(keystrokeP50)}ms
                {keystrokeP95 !== null ? ` / p95 ${Math.round(keystrokeP95)}ms` : ''}
              </>
            )}
            {localP50 !== null && (
              <>
                {keystrokeP50 !== null ? ' · ' : ''}
                request→page (local) p50 {Math.round(localP50)}ms
                {localP95 !== null ? ` / p95 ${Math.round(localP95)}ms` : ''}
              </>
            )}
            {serverP50 !== null && (
              <>
                {' · '}
                request→page (server) p50 {Math.round(serverP50)}ms
                {serverP95 !== null ? ` / p95 ${Math.round(serverP95)}ms` : ''}
              </>
            )}
          </span>
        )}
      </div>

      {isHydrating && filteredHits.length === 0 && (
        <p className="feed-route__empty">Loading feed snapshot…</p>
      )}
      {!isHydrating && filteredHits.length === 0 && (
        <p className="feed-route__empty">No results — adjust search or filters.</p>
      )}

      {filteredHits.length > 0 ? resultsBody : null}
    </div>
  )
}

function FeedCardTitle({
  hit,
  projects,
  mobile,
  feedSearch,
}: {
  hit: SearchResultHit
  projects: Array<{ project_id: string; prefix: string }>
  mobile: boolean
  feedSearch: FeedRouteSearch
}) {
  const project =
    hit.projectId || resolveProjectFromRecordId(hit.recordId, projects) || 'enceladus'
  const href =
    hit.recordType === 'document'
      ? documentHref(hit.recordId)
      : recordHrefForType(project, hit.recordType, hit.recordId)

  if (mobile) {
    return (
      <Link
        to={href}
        className="feed-route__card-link"
        onClick={() => persistFeedReturnSearch(feedSearch)}
      >
        {hit.recordId}
      </Link>
    )
  }

  return <span className="feed-route__card-id">{hit.recordId}</span>
}
