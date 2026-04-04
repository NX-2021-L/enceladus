import { useEffect, useMemo } from 'react'
import { useDocs2 } from '../hooks/useDocuments'
import { useProjects } from '../hooks/useProjects'
import { useFilterState } from '../hooks/useFilterState'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { useLiveFeed } from '../contexts/LiveFeedContext'
import { DocumentRow } from '../components/cards/DocumentRow'
import { PlanRow } from '../components/cards/PlanRow'
import { SearchInput } from '../components/shared/SearchInput'
import { FilterBar } from '../components/shared/FilterBar'
import { SortPicker } from '../components/shared/SortPicker'
import { ScrollSentinel } from '../components/shared/ScrollSentinel'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import {
  DOCUMENT_STATUSES,
  STATUS_LABELS,
  STATUS_COLORS,
  SORT_OPTIONS_DOCUMENTS,
} from '../lib/constants'
import type { DocumentFilters } from '../types/filters'

export function DocumentsListPage() {
  const { filters, toggleArrayFilter, setFilter } = useFilterState<DocumentFilters>({})
  const { projects } = useProjects()
  const {
    documents,
    totalMatches,
    projectCounts,
    defaultProject,
    isPending,
    isError,
    refetch,
  } = useDocs2(filters)

  // Plans from live feed (ENC-FTR-058 / ENC-ISS-152)
  const { plans: allPlans } = useLiveFeed()
  const filteredPlans = useMemo(() => {
    let result = allPlans
    if (filters.projectId) {
      result = result.filter((p) => p.project_id === filters.projectId)
    }
    if (filters.search) {
      const q = filters.search.toLowerCase()
      result = result.filter(
        (p) => p.title.toLowerCase().includes(q) || p.plan_id.toLowerCase().includes(q),
      )
    }
    return result
  }, [allPlans, filters.projectId, filters.search])

  const selectedProject = filters.projectId ?? defaultProject

  const { visible, sentinelRef, hasMore, resetPage } = useInfiniteList(documents)

  useEffect(() => {
    resetPage()
  }, [selectedProject, filters.search, resetPage])

  if (!projects.length) return <LoadingState />

  const allTotal = Object.values(projectCounts).reduce((s, c) => s + c.total, 0)

  return (
    <div className="p-4 space-y-3">
      {/* Header with count + refresh */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {filteredPlans.length + visible.length} of {filteredPlans.length + totalMatches} items
        </span>
        <button
          onClick={() => refetch()}
          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Project pills with counts */}
      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
        <button
          onClick={() => setFilter('projectId', undefined as unknown as string)}
          className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
            !filters.projectId
              ? 'bg-blue-500/20 text-blue-400'
              : 'bg-slate-800 text-slate-400'
          }`}
        >
          All ({allTotal || '...'})
        </button>
        {projects.map((p) => (
          <button
            key={p.project_id}
            onClick={() => setFilter('projectId', p.project_id)}
            className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
              filters.projectId === p.project_id
                ? 'bg-blue-500/20 text-blue-400'
                : 'bg-slate-800 text-slate-400'
            }`}
          >
            {p.prefix} ({projectCounts[p.project_id]?.total ?? '...'})
          </button>
        ))}
      </div>

      <SearchInput
        value={filters.search ?? ''}
        onChange={(v) => setFilter('search', v)}
        placeholder="Search documents..."
      />

      {/* Subtype filter (ENC-FTR-061) */}
      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
        <button
          onClick={() => setFilter('subtype', undefined as unknown as string)}
          className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
            !filters.subtype
              ? 'bg-blue-500/20 text-blue-400'
              : 'bg-slate-800 text-slate-400'
          }`}
        >
          All Types
        </button>
        <button
          onClick={() => setFilter('subtype', 'handoff')}
          className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
            filters.subtype === 'handoff'
              ? 'bg-amber-500/20 text-amber-400'
              : 'bg-slate-800 text-slate-400'
          }`}
        >
          Handoffs
        </button>
      </div>

      <FilterBar
        options={DOCUMENT_STATUSES}
        selected={filters.status ?? []}
        onToggle={(v) => toggleArrayFilter('status', v)}
        labels={STATUS_LABELS}
        colorMap={STATUS_COLORS}
      />

      <SortPicker
        options={SORT_OPTIONS_DOCUMENTS}
        active={filters.sortBy ?? 'updated:desc'}
        onChange={(v) => setFilter('sortBy', v)}
      />

      {/* Plans section (ENC-FTR-058 / ENC-ISS-152) */}
      {filteredPlans.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">
              Plans
            </span>
            <span className="text-xs text-slate-500">({filteredPlans.length})</span>
          </div>
          {filteredPlans.map((p) => (
            <PlanRow key={p.plan_id} plan={p} />
          ))}
        </div>
      )}

      {/* Documents section */}
      {isPending ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState />
      ) : (
        <div className="space-y-2">
          {filteredPlans.length > 0 && (visible.length > 0) && (
            <div className="flex items-center gap-2 pt-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Documents
              </span>
              <span className="text-xs text-slate-500">({totalMatches})</span>
            </div>
          )}
          {visible.length ? (
            <>
              {visible.map((d) => (
                <DocumentRow key={d.document_id} doc={d} />
              ))}
              <ScrollSentinel sentinelRef={sentinelRef} hasMore={hasMore} />
            </>
          ) : (
            !filteredPlans.length && <EmptyState message="No documents match your filters" />
          )}
        </div>
      )}
    </div>
  )
}
