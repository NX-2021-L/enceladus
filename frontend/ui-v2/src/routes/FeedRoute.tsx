import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Autosuggest, ButtonDropdown, Cards } from '../design-system'
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
import { buildSearchCorpus } from '../search/searchCorpus'
import { useTieredSearch } from '../search/useTieredSearch'
import { documentHref, recordHrefForType } from '../routes/recordLink'
import type { SearchResultHit } from '../types/search'
import './feed.css'

const EMPTY_FILTER: PropertyFilterQuery = { tokens: [], operation: 'and' }

export function FeedRoute() {
  const [query, setQuery] = useState('')
  const [filterQuery, setFilterQuery] = useState<PropertyFilterQuery>(EMPTY_FILTER)
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(() => loadSavedSearches())
  const [cardColumns, setCardColumns] = useState(1)

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const { events, isHydrating } = useRealtimeFeed()
  const corpus = buildSearchCorpus(events, projects)
  const projectId = projects[0]?.project_id ?? 'enceladus'

  const tiered = useTieredSearch({ projectId, query }, corpus)
  const filteredHits = applyPropertyFilter(tiered.hits, filterQuery)

  useEffect(() => {
    const desktop = window.matchMedia('(min-width: 48rem)')
    const sync = () => setCardColumns(desktop.matches ? 3 : 1)
    sync()
    desktop.addEventListener('change', sync)
    return () => desktop.removeEventListener('change', sync)
  }, [])

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

  return (
    <div className="feed-route">
      <header className="feed-route__header">
        <p className="feed-route__eyebrow">Search 2.0 · Feed</p>
        <h1 className="feed-route__title">Results</h1>
        <p className="feed-route__subtitle">
          Local tier paints instantly; hybrid merges async. Property pills refine the card
          collection below.
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

      <Cards
        items={filteredHits}
        trackBy="recordId"
        columns={cardColumns}
        cardDefinition={{
          header: (hit) => <FeedCardTitle hit={hit} projects={projects} />,
          sections: [
            {
              id: 'status',
              header: 'Status',
              content: (hit) => (hit.status ? <StatusChip status={hit.status} /> : '—'),
            },
            {
              id: 'tier',
              header: 'Tier',
              content: (hit) => <SearchTierBadge tier={hit.tier} />,
            },
            {
              id: 'project',
              header: 'Project',
              content: (hit) => hit.projectId,
            },
          ],
        }}
      />
    </div>
  )
}

function FeedCardTitle({
  hit,
  projects,
}: {
  hit: SearchResultHit
  projects: Array<{ project_id: string; prefix: string }>
}) {
  const project =
    hit.projectId || resolveProjectFromRecordId(hit.recordId, projects) || 'enceladus'
  const href =
    hit.recordType === 'document'
      ? documentHref(hit.recordId)
      : recordHrefForType(project, hit.recordType, hit.recordId)

  return (
    <a href={href} className="feed-route__card-link">
      {hit.recordId}
    </a>
  )
}
