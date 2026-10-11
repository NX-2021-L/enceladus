import { useState } from 'react'
import { DegradedBanner } from '@io-kit/search/react'
import { Autosuggest, ButtonDropdown } from '../design-system'
import { feedTransportLabel } from '../realtime/transportStatus'
import type { PropertyFilterQuery } from '../search/applyPropertyFilter'
import { serializeFilterQuery, type FeedRouteSearch, type FeedSort } from '../search/feedSearchParams'
import { deleteSavedSearch, loadSavedSearches, saveCurrentSearch, type SavedSearch } from '../search/savedSearches'
import type { useTieredSearch } from '../search/useTieredSearch'
import { useFeedConnectionStore } from '../store/feedConnectionStore'

/**
 * DVP-TSK-931: the /feed page chrome (header, toolbar, saved searches, meta line) shared by LegacyFeedRoute and
 * KitFeedPanel, so the two engines render the same layout and wording. Extracted verbatim from FeedRoute.tsx.
 */
export const SORT_OPTIONS: { value: FeedSort; label: string }[] = [
  // ENC-TSK-N56 (ENC-TSK-N45 UAT follow-up): 'Last Updated' is offered and is
  // the default (see FEED_SEARCH_DEFAULTS.sort = 'updated'). 'Tier' remains
  // available as the search-relevance ordering.
  { value: 'updated', label: 'Last Updated' },
  { value: 'tier', label: 'Tier' },
  { value: 'id', label: 'Record ID' },
  { value: 'title', label: 'Title' },
  { value: 'status', label: 'Status' },
]

export function FeedHeader() {
  const transportPhase = useFeedConnectionStore((s) => s.phase)
  return (
    <header className="feed-route__header">
      {/* ENC-TSK-M82 (AC-3): truthful transport label -- `LIVE` only while the WSS is actually connected. */}
      <p className="feed-route__eyebrow">FEED · {feedTransportLabel(transportPhase)}</p>
      <h1 className="feed-route__title">Results</h1>
      <p className="feed-route__subtitle">
        Search across every governed record type. Filters and scroll position are preserved on your way back.
      </p>
    </header>
  )
}

export interface FeedSuggestion {
  value: string
  description: string
  tag: string
}

export function FeedToolbar(p: {
  q: string
  sort: FeedSort
  suggestions: FeedSuggestion[]
  savedItems: ReturnType<typeof useSavedSearches>['savedItems']
  onSavedItemClick(id: string | undefined): void
  onQueryChange(value: string): void
  onSortChange(sort: FeedSort): void
}) {
  return (
    <div className="feed-route__toolbar">
      <div className="feed-route__search">
        <Autosuggest
          value={p.q}
          options={p.suggestions}
          placeholder="Search records or saved name…"
          ariaLabel="Feed search"
          onChange={(event) => p.onQueryChange(event.detail.value)}
        />
      </div>
      <label className="feed-route__sort">
        <span>Sort</span>
        <select value={p.sort} onChange={(event) => p.onSortChange(event.target.value as FeedSort)}>
          {SORT_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <ButtonDropdown items={p.savedItems} onItemClick={(event) => p.onSavedItemClick(event.detail.id)}>
        Saved searches
      </ButtonDropdown>
    </div>
  )
}

export function useSavedSearches(
  q: string,
  filterQuery: PropertyFilterQuery,
  patchFeedSearch: (patch: Partial<FeedRouteSearch>) => void,
) {
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>(() => loadSavedSearches())
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
      setSavedSearches(deleteSavedSearch(savedSearches, id.slice('__delete:'.length)))
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
  return { savedItems, handleSavedClick }
}

export function FeedMeta(p: { count: number; serverCorpusTotal: number | null; tiered: ReturnType<typeof useTieredSearch> }) {
  const { tiered } = p
  const keystrokeP50 = useFeedConnectionStore((s) => s.keystrokeSuggestion.p50Ms)
  const keystrokeP95 = useFeedConnectionStore((s) => s.keystrokeSuggestion.p95Ms)
  const localP50 = useFeedConnectionStore((s) => s.requestFirstPageLocal.p50Ms)
  const localP95 = useFeedConnectionStore((s) => s.requestFirstPageLocal.p95Ms)
  const serverP50 = useFeedConnectionStore((s) => s.requestFirstPageServer.p50Ms)
  const serverP95 = useFeedConnectionStore((s) => s.requestFirstPageServer.p95Ms)
  return (
    <div className="feed-route__meta">
      <span>
        {p.count} hit{p.count === 1 ? '' : 's'}
        {/* ENC-TSK-P60: server corpus total beside the local count makes snapshot staleness visible. */}
        {p.serverCorpusTotal !== null ? ` · server corpus ${p.serverCorpusTotal}` : ''}
        {tiered.hybridPending ? ' · hybrid loading…' : ''}
      </span>
      {tiered.hybridError && <span className="feed-route__meta-error">{tiered.hybridError.message}</span>}
      {tiered.availability ? <DegradedBanner availability={tiered.availability} degraded={tiered.degraded} /> : null}
      {tiered.serverDown ? <span role="status">Server search unavailable; showing local matches</span> : null}
      {(keystrokeP50 !== null || localP50 !== null || serverP50 !== null) && (
        // ENC-ISS-513 / FND-01: timing detail tucked behind a disclosure.
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
  )
}
