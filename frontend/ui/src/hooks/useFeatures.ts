import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { feedKeys, fetchFeatures } from '../api/feeds'
import { useLiveFeed } from '../contexts/LiveFeedContext'
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
  // Live data from the global delta-polling provider (ENC-TSK-609).
  const { features: liveFeatures } = useLiveFeed()

  // S3 feed as fallback for initial load before LiveFeedProvider hydrates.
  const s3Query = useQuery({ queryKey: feedKeys.features, queryFn: fetchFeatures })

  const allFeatures = liveFeatures.length > 0 ? liveFeatures : (s3Query.data?.features ?? [])
  const isPending = liveFeatures.length === 0 && s3Query.isPending
  const isError = liveFeatures.length === 0 && s3Query.isError

  const filtered = useMemo(() => {
    if (!allFeatures.length) return []
    let items = allFeatures
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
  }, [allFeatures, filters?.projectId, filters?.status, filters?.search, filters?.sortBy])

  return {
    features: filtered,
    allFeatures,
    generatedAt: s3Query.data?.generated_at ?? null,
    isPending,
    isError,
    isLoading: isPending,
    data: s3Query.data,
  }
}
