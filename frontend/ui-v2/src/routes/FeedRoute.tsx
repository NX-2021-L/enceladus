import { useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { Autosuggest, ButtonDropdown, Cards, ColumnLayout } from '../design-system'
import { projectRegistryQueryOptions, resolveProjectFromRecordId } from '../api/projectRegistry'
import { SearchTierBadge } from '../components/SearchTierBadge'
import { StatusChip } from '../components/StatusChip'
import { useRealtimeFeed } from '../realtime/RealtimeFeedProvider'
import { applyPropertyFilter, type PropertyFilterQuery } from '../search/applyPropertyFilter'
import { FeedPropertyFilter } from '../search/FeedPropertyFilter'
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
import { useTieredSearch } from '../search/useTieredSearch'
import { documentHref, recordHrefForType } from '../routes/recordLink'
import type { SearchResultHit } from '../types/search'
import { FeedReadingPane } from './FeedReadingPane'
import { RecentlyViewedNav } from './RecentlyViewedNav'
import './feed.css'

const EMPTY_FILTER: PropertyFilterQuery = { tokens: [], operation: 'and' }
const LIST_CHUNK = 24
const WIDE_MEDIA = '(min-width: 64rem)'

export function FeedRoute() {
  const [query, setQuery] = useState('')
  const [filterQuery, setFilterQuery] = useState<PropertyFilterQuery>(EMPTY_FILTER)
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(() => loadSavedSearches())
  const [isWide, setIsWide] = useState(false)
  const [selectedHit, setSelectedHit] = useState<SearchResultHit | null>(null)
  const [visibleCount, setVisibleCount] = useState(LIST_CHUNK)
  const [recentItems, setRecentItems] = useState<RecentlyViewedEntry[]>([])
  const listRef = useRef<HTMLDivElement>(null)

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const { events, isHydrating } = useRealtimeFeed()
  const corpus = buildSearchCorpus(events, projects)
  const projectId = projects[0]?.project_id ?? 'enceladus'

  const tiered = useTieredSearch({ projectId, query }, corpus)
  const filteredHits = applyPropertyFilter(tiered.hits, filterQuery)
  const visibleHits = filteredHits.slice(0, visibleCount)

  const selectHit = (hit: SearchResultHit) => {
    setSelectedHit(hit)
    trackRecentlyViewed(hit)
    setRecentItems(getRecentlyViewed(hit.recordType))
  }

  useEffect(() => {
    const mq = window.matchMedia(WIDE_MEDIA)
    const sync = () => setIsWide(mq.matches)
    sync()
    mq.addEventListener('change', sync)
    return () => mq.removeEventListener('change', sync)
  }, [])

  useEffect(() => {
    setVisibleCount(LIST_CHUNK)
  }, [query, filterQuery, filteredHits.length])

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
      setSavedSearches(saveCurrentSearch(savedSearches, name, query, filterQuery))
      return
    }
    if (id.startsWith('__delete:')) {
      const target = id.slice('__delete:'.length)
      setSavedSearches(deleteSavedSearch(savedSearches, target))
      return
    }
    const saved = savedSearches.find((s) => s.id === id)
    if (!saved) return
    setQuery(saved.query)
    setFilterQuery(saved.filterQuery)
  }

  const searchSuggestions = corpus
    .filter((row) => {
      const q = query.trim().toLowerCase()
      if (!q) return true
      return row.recordId.toLowerCase().includes(q) || row.title.toLowerCase().includes(q)
    })
    .slice(0, 12)
    .map((row) => ({
      value: row.recordId,
      description: row.title,
      tag: row.recordType,
    }))

  const cardDefinition = {
    header: (hit: SearchResultHit) => <FeedCardTitle hit={hit} projects={projects} mobile={!isWide} />,
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
      <Cards
        items={visibleHits}
        trackBy="recordId"
        columns={1}
        cardDefinition={cardDefinition}
      />
    )

  return (
    <div className="feed-route">
      <header className="feed-route__header">
        <p className="feed-route__eyebrow">Search 2.0 · Feed</p>
        <h1 className="feed-route__title">Results</h1>
        <p className="feed-route__subtitle">
          Local tier paints instantly; hybrid merges async. Wide viewports open a reading pane;
          mobile opens the full record page.
        </p>
      </header>

      <div className="feed-route__toolbar">
        <div className="feed-route__search">
          <Autosuggest
            value={query}
            options={searchSuggestions}
            placeholder="Search records or saved name…"
            ariaLabel="Feed search"
            onChange={(event) => setQuery(event.detail.value)}
          />
        </div>
        <ButtonDropdown items={savedItems} onItemClick={(event) => handleSavedClick(event.detail.id)}>
          Saved searches
        </ButtonDropdown>
      </div>

      <FeedPropertyFilter query={filterQuery} corpus={corpus} onChange={setFilterQuery} />

      <div className="feed-route__meta">
        <span>
          {filteredHits.length} hit{filteredHits.length === 1 ? '' : 's'}
          {tiered.hybridPending ? ' · hybrid loading…' : ''}
        </span>
        {tiered.hybridError && (
          <span className="feed-route__meta-error">{tiered.hybridError.message}</span>
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
}: {
  hit: SearchResultHit
  projects: Array<{ project_id: string; prefix: string }>
  mobile: boolean
}) {
  const project =
    hit.projectId || resolveProjectFromRecordId(hit.recordId, projects) || 'enceladus'
  const href =
    hit.recordType === 'document'
      ? documentHref(hit.recordId)
      : recordHrefForType(project, hit.recordType, hit.recordId)

  if (mobile) {
    return (
      <a href={href} className="feed-route__card-link">
        {hit.recordId}
      </a>
    )
  }

  return <span className="feed-route__card-id">{hit.recordId}</span>
}
