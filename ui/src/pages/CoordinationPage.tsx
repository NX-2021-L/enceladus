import { useCallback } from 'react'
import { useCoordinationList } from '../hooks/useCoordination'
import { useProjects } from '../hooks/useProjects'
import { useFilterState } from '../hooks/useFilterState'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { CoordinationRow } from '../components/cards/CoordinationRow'
import { AnimatedList } from '../components/shared/AnimatedList'
import { SearchInput } from '../components/shared/SearchInput'
import { FilterBar } from '../components/shared/FilterBar'
import { SortPicker } from '../components/shared/SortPicker'
import { ScrollSentinel } from '../components/shared/ScrollSentinel'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import {
  COORDINATION_STATES,
  COORDINATION_STATE_LABELS,
  COORDINATION_STATE_COLORS,
  SORT_OPTIONS_COORDINATION,
} from '../lib/constants'
import type { CoordinationFilters } from '../types/filters'
import type { CoordinationRequest } from '../types/coordination'

// Wrap CoordinationRequest to match AnimatedList's expectation of { _id: string }
interface CoordinationListItem {
  _id: string
  data: CoordinationRequest
}

export function CoordinationPage() {
  const { filters, toggleArrayFilter, setFilter } = useFilterState<CoordinationFilters>({})
  const { items, generatedAt, isPending, isError } = useCoordinationList(filters, { polling: true })
  const { projects } = useProjects()

  const listItems: CoordinationListItem[] = items.map((r) => ({
    _id: r.request_id,
    data: r,
  }))

  const { visible, sentinelRef, hasMore, total } = useInfiniteList(listItems, 20, 100)

  const renderItem = useCallback(
    (item: CoordinationListItem) => <CoordinationRow request={item.data} />,
    [],
  )

  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {visible.length} of {total} requests
        </span>
        <FreshnessBadge generatedAt={generatedAt} />
      </div>

      <SearchInput
        value={filters.search ?? ''}
        onChange={(v) => setFilter('search', v)}
        placeholder="Search requests..."
      />

      {projects.length > 1 && (
        <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
          <button
            onClick={() => setFilter('projectId', undefined)}
            className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
              !filters.projectId ? 'bg-purple-500/20 text-purple-400' : 'bg-slate-800 text-slate-400'
            }`}
          >
            All
          </button>
          {projects.map((p) => (
            <button
              key={p.project_id}
              onClick={() => setFilter('projectId', p.project_id)}
              className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
                filters.projectId === p.project_id ? 'bg-purple-500/20 text-purple-400' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {p.prefix}
            </button>
          ))}
        </div>
      )}

      <FilterBar
        options={COORDINATION_STATES}
        selected={filters.state ?? []}
        onToggle={(v) => toggleArrayFilter('state', v)}
        labels={COORDINATION_STATE_LABELS}
        colorMap={COORDINATION_STATE_COLORS}
      />

      <SortPicker
        options={SORT_OPTIONS_COORDINATION}
        active={filters.sortBy ?? 'updated:desc'}
        onChange={(v) => setFilter('sortBy', v)}
      />

      {visible.length ? (
        <>
          <AnimatedList
            items={visible}
            renderItem={renderItem}
            className="space-y-2"
          />
          <ScrollSentinel sentinelRef={sentinelRef} hasMore={hasMore} />
        </>
      ) : (
        <EmptyState message="No coordination requests match your filters" />
      )}
    </div>
  )
}
