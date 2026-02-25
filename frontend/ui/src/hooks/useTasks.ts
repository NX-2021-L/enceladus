import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchTasks } from '../api/feeds'
import { useLiveFeed } from '../contexts/LiveFeedContext'
import { PRIORITY_ORDER } from '../lib/constants'
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
  const { tasks: liveTasks } = useLiveFeed()

  // S3 feed as fallback for initial load before LiveFeedProvider hydrates.
  const s3Query = useQuery({ queryKey: feedKeys.tasks, queryFn: fetchTasks })

  // Prefer live data; fall back to S3 when live context hasn't loaded yet.
  const allTasks = liveTasks.length > 0 ? liveTasks : (s3Query.data?.tasks ?? [])
  const isPending = liveTasks.length === 0 && s3Query.isPending
  const isError = liveTasks.length === 0 && s3Query.isError

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
    generatedAt: s3Query.data?.generated_at ?? null,
    isPending,
    isError,
    isLoading: isPending,
    data: s3Query.data,
  }
}
