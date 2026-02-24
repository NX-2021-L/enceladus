import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchTasks } from '../api/feeds'
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
  const query = useQuery({ queryKey: feedKeys.tasks, queryFn: fetchTasks })

  const filtered = useMemo(() => {
    if (!query.data?.tasks) return []
    let items = query.data.tasks
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
    query.data?.tasks,
    filters?.projectId,
    filters?.status,
    filters?.priority,
    filters?.search,
    filters?.sortBy,
  ])

  return {
    tasks: filtered,
    allTasks: query.data?.tasks ?? [],
    generatedAt: query.data?.generated_at ?? null,
    ...query,
  }
}
