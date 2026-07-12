import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Autosuggest, Cards } from '../design-system'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { applyPropertyFilter, type PropertyFilterQuery } from '../search/applyPropertyFilter'
import { FeedPropertyFilter } from '../search/FeedPropertyFilter'
import { onlyRecordType } from '../search/recordTypeScope'
import { buildSearchCorpus } from '../search/searchCorpus'
import { sortSearchHits } from '../search/sortSearchHits'
import type { FeedSort } from '../search/feedSearchParams'
import { useTieredSearch } from '../search/useTieredSearch'
import { getCacheEngine } from '../sync/cacheEngine'
import { useCacheEngineState } from '../sync/CacheEngineProvider'
import { documentHref } from './recordLink'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import type { SearchResultHit } from '../types/search'
import './docs.css'

const SORT_OPTIONS: { value: FeedSort; label: string }[] = [
  { value: 'tier', label: 'Relevance (default)' },
  { value: 'title', label: 'Title' },
  { value: 'id', label: 'Document ID' },
]

/**
 * ENC-TSK-L32 — Documents page. Reciprocal half of the Feed-scoping AC: this
 * page's search (local keyword tier + hybrid graphsearch tier) is scoped to
 * ONLY document records via `onlyRecordType` + `recordType: 'document'` on
 * the hybrid params, mirroring how FeedRoute now excludes documents via
 * `excludeRecordType`. See src/search/recordTypeScope.ts.
 *
 * AC-16 (React Compiler): no hand-written useMemo/useCallback — values below
 * are plain per-render computations; the compiler owns memoization.
 */
export function DocsRoute() {
  useDocumentTitle('Docs')
  const [query, setQuery] = useState('')
  const [filterQuery, setFilterQuery] = useState<PropertyFilterQuery>({ tokens: [] })
  const [sort, setSort] = useState<FeedSort>('tier')

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const events = useRealtimeFeedEvents()
  const { isWarm } = useCacheEngineState()

  const fromEvents = buildSearchCorpus(events, projects)
  let corpus = fromEvents
  if (isWarm) {
    const byId = new Map(getCacheEngine().searchIndex.all().map((row) => [row.recordId, row]))
    for (const row of fromEvents) byId.set(row.recordId, row)
    corpus = [...byId.values()]
  }

  // Documents-only scope — the reciprocal of FeedRoute's excludeRecordType.
  const docsCorpus = onlyRecordType(corpus, 'document')

  const tiered = useTieredSearch(
    { projectId: projects[0]?.project_id ?? 'enceladus', query, recordType: 'document' },
    docsCorpus,
  )
  const filteredHits = onlyRecordType(
    sortSearchHits(applyPropertyFilter(tiered.hits, filterQuery), sort),
    'document',
  )

  const needle = query.trim().toLowerCase()
  const searchSuggestions = docsCorpus
    .filter((row) => {
      if (!needle) return true
      return row.recordId.toLowerCase().includes(needle) || row.title.toLowerCase().includes(needle)
    })
    .slice(0, 12)
    .map((row) => ({ value: row.recordId, description: row.title, tag: row.recordType }))

  const cardDefinition = {
    header: (hit: SearchResultHit) => (
      <Link to={documentHref(hit.recordId)} className="docs-route__card-link">
        {hit.title || hit.recordId}
      </Link>
    ),
    sections: [
      {
        id: 'recordId',
        header: 'Document',
        content: (hit: SearchResultHit) => <span className="docs-route__card-id">{hit.recordId}</span>,
      },
      {
        id: 'status',
        header: 'Status',
        content: (hit: SearchResultHit) => hit.status ?? '—',
      },
    ],
  }

  return (
    <div className="docs-route">
      <header className="docs-route__header">
        <p className="docs-route__eyebrow">DOCUMENTS · LIVE</p>
        <h1 className="docs-route__title">Documents</h1>
        <p className="docs-route__subtitle">
          Search is scoped to document records only — tracker primitives (tasks, issues,
          features, plans, lessons) live on the Feed page.
        </p>
      </header>

      <div className="docs-route__toolbar">
        <div className="docs-route__search">
          <Autosuggest
            value={query}
            options={searchSuggestions}
            placeholder="Search documents…"
            ariaLabel="Document search"
            onChange={(event) => setQuery(event.detail.value)}
          />
        </div>
        <label className="docs-route__sort">
          <span>Sort</span>
          <select value={sort} onChange={(event) => setSort(event.target.value as FeedSort)}>
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <FeedPropertyFilter query={filterQuery} corpus={docsCorpus} onChange={setFilterQuery} />

      <div className="docs-route__meta">
        <span>
          {filteredHits.length} document{filteredHits.length === 1 ? '' : 's'}
          {tiered.hybridPending ? ' · hybrid loading…' : ''}
        </span>
        {tiered.hybridError && <span className="docs-route__meta-error">{tiered.hybridError.message}</span>}
      </div>

      {filteredHits.length === 0 ? (
        <p className="docs-route__empty">
          No documents match this search.
          {(query || filterQuery.tokens.length > 0) && (
            <button
              type="button"
              className="docs-route__empty-action"
              onClick={() => {
                setQuery('')
                setFilterQuery({ tokens: [] })
              }}
            >
              Clear filters
            </button>
          )}
        </p>
      ) : (
        <Cards items={filteredHits} trackBy="recordId" columns={2} cardDefinition={cardDefinition} />
      )}
    </div>
  )
}
