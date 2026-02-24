import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchFeatures } from '../api/feeds'
import type { FeatureFilters } from '../types/filters'

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

export function useFeatures(filters?: FeatureFilters) {
  const query = useQuery({ queryKey: feedKeys.features, queryFn: fetchFeatures })

  const filtered = useMemo(() => {
    if (!query.data?.features) return []
    let items = query.data.features
    if (filters?.projectId) items = items.filter((f) => f.project_id === filters.projectId)
    if (filters?.status?.length) items = items.filter((f) => filters.status!.includes(f.status))
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      items = items.filter(
        (f) => f.title.toLowerCase().includes(q) || f.feature_id.toLowerCase().includes(q),
      )
    }
    const { field, dir } = parseSort(filters?.sortBy)
    return [...items].sort((a, b) => {
      let cmp: number
      if (field === 'created') cmp = compareDates(a.created_at, b.created_at)
      else cmp = compareDates(a.updated_at, b.updated_at)
      return cmp * dir
    })
  }, [query.data?.features, filters?.projectId, filters?.status, filters?.search, filters?.sortBy])

  return {
    features: filtered,
    allFeatures: query.data?.features ?? [],
    generatedAt: query.data?.generated_at ?? null,
    ...query,
  }
}
