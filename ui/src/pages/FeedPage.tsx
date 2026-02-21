import { useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useFeed } from '../hooks/useFeed'
import { useProjects } from '../hooks/useProjects'
import { useFilterState } from '../hooks/useFilterState'
import { useInfiniteList } from '../hooks/useInfiniteList'
import { FeedRow } from '../components/cards/FeedRow'
import { AnimatedList } from '../components/shared/AnimatedList'
import { SearchInput } from '../components/shared/SearchInput'
import { FilterBar } from '../components/shared/FilterBar'
import { RecentItemsDisplay } from '../components/shared/RecentItemsDisplay'
import { ScrollSentinel } from '../components/shared/ScrollSentinel'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import {
  FEED_RECORD_TYPES,
  RECORD_TYPE_LABELS,
  RECORD_TYPE_COLORS,
  SORT_OPTIONS_FEED,
  TASK_STATUSES,
  ISSUE_STATUSES,
  FEATURE_STATUSES,
  PRIORITIES,
  SEVERITIES,
  STATUS_LABELS,
  STATUS_COLORS,
  PRIORITY_COLORS,
  SEVERITY_COLORS,
} from '../lib/constants'
import type { FeedFilters } from '../types/filters'

export function FeedPage() {
  const [searchParams] = useSearchParams()
  const { filters, toggleArrayFilter, setFilter } = useFilterState<FeedFilters>({})
  const { items, generatedAt, isPending, isError } = useFeed(filters, { polling: true })
  const { projects } = useProjects()
  const { visible, sentinelRef, hasMore, total } = useInfiniteList(items, 20, 100)

  const hasInitializedRef = useRef(false)

  // Initialize filters from URL parameters on mount
  useEffect(() => {
    if (hasInitializedRef.current) return
    hasInitializedRef.current = true

    const type = searchParams.get('type')
    if (type && ['task', 'issue', 'feature'].includes(type)) {
      setFilter('recordType', [type])
    }
  }, [searchParams, setFilter])

  const renderFeedItem = useCallback(
    (item: (typeof visible)[number]) => <FeedRow item={item} />,
    [],
  )

  const singleType = filters.recordType?.length === 1 ? filters.recordType[0] : null
  const prevSingleTypeRef = useRef(singleType)

  // Clear type-specific filters when type selection changes
  useEffect(() => {
    if (prevSingleTypeRef.current !== singleType) {
      if (prevSingleTypeRef.current !== null) {
        setFilter('status', undefined)
        setFilter('priority', undefined)
        setFilter('severity', undefined)
        // Reset sort if current sort is type-specific (e.g., priority)
        const feedFields: string[] = SORT_OPTIONS_FEED.map((o) => o.value)
        const currentField = filters.sortBy?.split(':')[0]
        if (currentField && !feedFields.includes(currentField)) {
          setFilter('sortBy', undefined)
        }
      }
      prevSingleTypeRef.current = singleType
    }
  }, [singleType, setFilter, filters.sortBy])


  if (isPending) return <LoadingState />
  if (isError) return <ErrorState />

  return (
    <div className="p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {visible.length} of {total} items
        </span>
        <FreshnessBadge generatedAt={generatedAt} />
      </div>

      <SearchInput
        value={filters.search ?? ''}
        onChange={(v) => setFilter('search', v)}
        placeholder="Search feed..."
      />

      {projects.length > 1 && (
        <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
          <button
            onClick={() => setFilter('projectId', undefined)}
            className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
              !filters.projectId ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'
            }`}
          >
            All
          </button>
          {projects.map((p) => (
            <button
              key={p.project_id}
              onClick={() => setFilter('projectId', p.project_id)}
              className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] ${
                filters.projectId === p.project_id ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'
              }`}
            >
              {p.prefix}
            </button>
          ))}
        </div>
      )}

      <FilterBar
        options={FEED_RECORD_TYPES}
        selected={filters.recordType ?? []}
        onToggle={(v) => toggleArrayFilter('recordType', v)}
        labels={RECORD_TYPE_LABELS}
        colorMap={RECORD_TYPE_COLORS}
      />

      {singleType === 'task' && (
        <>
          <FilterBar
            options={TASK_STATUSES}
            selected={filters.status ?? []}
            onToggle={(v) => toggleArrayFilter('status', v)}
            labels={STATUS_LABELS}
            colorMap={STATUS_COLORS}
          />
          <FilterBar
            options={PRIORITIES}
            selected={filters.priority ?? []}
            onToggle={(v) => toggleArrayFilter('priority', v)}
            colorMap={PRIORITY_COLORS}
          />
        </>
      )}

      {singleType === 'issue' && (
        <>
          <FilterBar
            options={ISSUE_STATUSES}
            selected={filters.status ?? []}
            onToggle={(v) => toggleArrayFilter('status', v)}
            labels={STATUS_LABELS}
            colorMap={STATUS_COLORS}
          />
          <FilterBar
            options={SEVERITIES}
            selected={filters.severity ?? []}
            onToggle={(v) => toggleArrayFilter('severity', v)}
            colorMap={SEVERITY_COLORS}
          />
        </>
      )}

      {singleType === 'feature' && (
        <FilterBar
          options={FEATURE_STATUSES}
          selected={filters.status ?? []}
          onToggle={(v) => toggleArrayFilter('status', v)}
          labels={STATUS_LABELS}
          colorMap={STATUS_COLORS}
        />
      )}

      {/* Recent Items Display (replaces SortPicker) */}
      <RecentItemsDisplay items={items} />

      {visible.length ? (
        <>
          <AnimatedList
            items={visible}
            renderItem={renderFeedItem}
            className="space-y-2"
          />
          <ScrollSentinel sentinelRef={sentinelRef} hasMore={hasMore} />
        </>
      ) : (
        <EmptyState message="No items match your filters" />
      )}
    </div>
  )
}
