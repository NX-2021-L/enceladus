import { useDocuments } from '../hooks/useDocuments'
import { useProjects } from '../hooks/useProjects'
import { useFilterState } from '../hooks/useFilterState'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { DocumentRow } from '../components/cards/DocumentRow'
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

  // Documents require a project selection — default to first available
  const selectedProject = filters.projectId ?? projects[0]?.project_id ?? ''
  const { documents, isPending, isError } = useDocuments(selectedProject, filters)
  const { visible, sentinelRef, hasMore, total } = useInfiniteList(documents)

  if (!projects.length) return <LoadingState />

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {visible.length} of {total} documents
        </span>
      </div>

      {/* Project selector pills */}
      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
        {projects.map((p) => (
          <button
            key={p.project_id}
            onClick={() => setFilter('projectId', p.project_id)}
            className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
              selectedProject === p.project_id ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'
            }`}
          >
            {p.prefix}
          </button>
        ))}
      </div>

      <SearchInput
        value={filters.search ?? ''}
        onChange={(v) => setFilter('search', v)}
        placeholder="Search documents..."
      />

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

      {isPending ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState />
      ) : (
        <div className="space-y-2">
          {visible.length ? (
            <>
              {visible.map((d) => (
                <DocumentRow key={d.document_id} doc={d} />
              ))}
              <ScrollSentinel sentinelRef={sentinelRef} hasMore={hasMore} />
            </>
          ) : (
            <EmptyState message="No documents match your filters" />
          )}
        </div>
      )}
    </div>
  )
}
