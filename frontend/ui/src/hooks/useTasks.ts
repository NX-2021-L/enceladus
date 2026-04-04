import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchTasks } from '../api/feeds'
import { useLiveFeed } from '../contexts/LiveFeedContext'
import { PRIORITY_ORDER } from '../lib/constants'
import type { Task } from '../types/feeds'
import type { TaskFilters } from '../types/filters'

function compareDates(a: string | null, b: string | null): number {
  if (!a) return 1
  if (!b) return -1
  return b.localeCompare(a)
}

function parseSort(raw?: string): { field: string; dir: 1 | -1 } {
  if (!raw) return { field: 'updated', dir: 1 }
  const [field, d] = raw.split(':')
  return { field, dir: d === 'asc' ? -1 : 1 }
}

export function useTasks(filters?: TaskFilters) {
  // Live data from the global delta-polling provider (ENC-TSK-609).
  const { tasks: liveTasks, generatedAt: liveGeneratedAt } = useLiveFeed()
  const hasLiveSnapshot = liveGeneratedAt !== null

  // S3 feed as fallback for initial load before LiveFeedProvider hydrates.
  const s3Query = useQuery({ queryKey: feedKeys.tasks, queryFn: fetchTasks })

  // ENC-ISS-148: The live feed API returns sparse task snapshots (missing
  // description, history, checklist, etc.) while S3 has full records.
  // When both are available, merge live data onto S3 data so detail fields
  // are preserved while status/priority stay current from live polling.
  const allTasks = useMemo(() => {
    if (!hasLiveSnapshot) return s3Query.data?.tasks ?? []
    const s3Tasks = s3Query.data?.tasks
    if (!s3Tasks?.length) return liveTasks

    const s3Map = new Map<string, Task>()
    for (const t of s3Tasks) s3Map.set(t.task_id, t)

    return liveTasks.map((live) => {
      const s3 = s3Map.get(live.task_id)
      if (!s3) return live
      // Spread S3 (rich base) then overlay live fields, skipping empty sentinels
      const merged = { ...s3 } as Record<string, unknown>
      for (const key of Object.keys(live)) {
        const val = (live as Record<string, unknown>)[key]
        const existing = merged[key]
        // Skip empty sentinels ('', [], null) when S3 has richer data
        if (
          (val === '' || val === null || (Array.isArray(val) && val.length === 0)) &&
          existing != null && existing !== '' && !(Array.isArray(existing) && existing.length === 0)
        ) continue
        merged[key] = val
      }
      return merged as Task
    })
  }, [hasLiveSnapshot, liveTasks, s3Query.data?.tasks])

  const isPending = !hasLiveSnapshot && s3Query.isPending
  const isError = !hasLiveSnapshot && s3Query.isError

  const filtered = useMemo(() => {
    if (!allTasks.length) return []
    let items = allTasks
    if (filters?.projectId) items = items.filter((t) => t.project_id === filters.projectId)
    if (filters?.status?.length) items = items.filter((t) => filters.status!.includes(t.status))
    if (filters?.priority?.length) items = items.filter((t) => filters.priority!.includes(t.priority))
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      items = items.filter(
        (t) => t.title.toLowerCase().includes(q) || t.task_id.toLowerCase().includes(q),
      )
    }
    const { field, dir } = parseSort(filters?.sortBy)
    return [...items].sort((a, b) => {
      let cmp: number
      if (field === 'created') cmp = compareDates(a.created_at, b.created_at)
      else if (field === 'priority')
        cmp = (PRIORITY_ORDER[a.priority] ?? 9) - (PRIORITY_ORDER[b.priority] ?? 9)
      else cmp = compareDates(a.updated_at, b.updated_at)
      return cmp * dir
    })
  }, [
    allTasks,
    filters?.projectId,
    filters?.status,
    filters?.priority,
    filters?.search,
    filters?.sortBy,
  ])

  return {
    tasks: filtered,
    allTasks,
    generatedAt: liveGeneratedAt ?? s3Query.data?.generated_at ?? null,
    isPending,
    isError,
    isLoading: isPending,
    data: s3Query.data,
  }
}
