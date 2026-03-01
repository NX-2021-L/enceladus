import { useEffect } from 'react'
import { useChangelogHistory } from '../hooks/useChangelog'
import { useProjects } from '../hooks/useProjects'
import { useFilterState } from '../hooks/useFilterState'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { ChangelogEntryCard } from '../components/cards/ChangelogEntryCard'
import { FilterBar } from '../components/shared/FilterBar'
import { SortPicker } from '../components/shared/SortPicker'
import { ScrollSentinel } from '../components/shared/ScrollSentinel'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import {
  CHANGELOG_CHANGE_TYPES,
  CHANGELOG_CHANGE_TYPE_LABELS,
  CHANGELOG_CHANGE_TYPE_COLORS,
  SORT_OPTIONS_CHANGELOG,
} from '../lib/constants'
import type { ChangelogFilters } from '../types/filters'

export function ChangelogListPage() {
  const { filters, toggleArrayFilter, setFilter } = useFilterState<ChangelogFilters & { changeTypeArr?: string[] }>({})
  const { projects } = useProjects()

  const changelogFilters: ChangelogFilters = {
    projectId: filters.projectId,
    changeType: filters.changeTypeArr?.length === 1
      ? (filters.changeTypeArr[0] as ChangelogFilters['changeType'])
      : undefined,
    sortBy: filters.sortBy,
  }

  const { entries, projectCounts, isPending, isError, refetch } = useChangelogHistory(changelogFilters)

  const { visible, sentinelRef, hasMore, resetPage } = useInfiniteList(entries)

  useEffect(() => {
    resetPage()
  }, [filters.projectId, filters.changeTypeArr, resetPage])

  if (!projects.length) return <LoadingState />

  const allTotal = Object.values(projectCounts).reduce((s, n) => s + n, 0)

  return (
    <div className="p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {visible.length} of {allTotal || entries.length} releases
        </span>
        <button
          onClick={() => refetch()}
          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Project pills */}
      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
        <button
          onClick={() => setFilter('projectId', undefined as unknown as string)}
          className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
            !filters.projectId ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'
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
            {p.prefix} ({projectCounts[p.project_id] ?? '...'})
          </button>
        ))}
      </div>

      {/* Change type filter */}
      <FilterBar
        options={CHANGELOG_CHANGE_TYPES as unknown as string[]}
        selected={filters.changeTypeArr ?? []}
        onToggle={(v) => toggleArrayFilter('changeTypeArr', v)}
        labels={CHANGELOG_CHANGE_TYPE_LABELS}
        colorMap={CHANGELOG_CHANGE_TYPE_COLORS}
      />

      <SortPicker
        options={SORT_OPTIONS_CHANGELOG}
        active={filters.sortBy ?? 'deployed:desc'}
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
              {visible.map((entry, i) => (
                <ChangelogEntryCard key={`${entry.project_id}-${entry.spec_id}-${i}`} entry={entry} />
              ))}
              <ScrollSentinel sentinelRef={sentinelRef} hasMore={hasMore} />
            </>
          ) : (
            <EmptyState message="No releases match your filters" />
          )}
        </div>
      )}
    </div>
  )
}
