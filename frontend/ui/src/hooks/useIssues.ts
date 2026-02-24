import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchIssues } from '../api/feeds'
import { PRIORITY_ORDER } from '../lib/constants'
import type { IssueFilters } from '../types/filters'

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

export function useIssues(filters?: IssueFilters) {
  const query = useQuery({ queryKey: feedKeys.issues, queryFn: fetchIssues })

  const filtered = useMemo(() => {
    if (!query.data?.issues) return []
    let items = query.data.issues
    if (filters?.projectId) items = items.filter((i) => i.project_id === filters.projectId)
    if (filters?.status?.length) items = items.filter((i) => filters.status!.includes(i.status))
    if (filters?.severity?.length) items = items.filter((i) => filters.severity!.includes(i.severity))
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      items = items.filter(
        (i) => i.title.toLowerCase().includes(q) || i.issue_id.toLowerCase().includes(q),
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
    query.data?.issues,
    filters?.projectId,
    filters?.status,
    filters?.severity,
    filters?.search,
    filters?.sortBy,
  ])

  return {
    issues: filtered,
    allIssues: query.data?.issues ?? [],
    generatedAt: query.data?.generated_at ?? null,
    ...query,
  }
}
