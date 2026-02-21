import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { documentKeys, fetchDocumentsByProject } from '../api/documents'
import type { DocumentFilters } from '../types/filters'

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

export function useDocuments(projectId: string, filters?: DocumentFilters) {
  const query = useQuery({
    queryKey: documentKeys.list(projectId),
    queryFn: () => fetchDocumentsByProject(projectId),
    enabled: !!projectId,
  })

  const filtered = useMemo(() => {
    if (!query.data) return []
    let items = query.data
    if (filters?.status?.length) items = items.filter((d) => filters.status!.includes(d.status))
    if (filters?.search) {
      const q = filters.search.toLowerCase()
      items = items.filter(
        (d) =>
          d.title.toLowerCase().includes(q) ||
          d.document_id.toLowerCase().includes(q) ||
          d.keywords.some((k) => k.toLowerCase().includes(q)),
      )
    }
    const { field, dir } = parseSort(filters?.sortBy)
    return [...items].sort((a, b) => {
      let cmp: number
      if (field === 'created') cmp = compareDates(a.created_at, b.created_at)
      else if (field === 'size') cmp = (b.size_bytes ?? 0) - (a.size_bytes ?? 0)
      else cmp = compareDates(a.updated_at, b.updated_at)
      return cmp * dir
    })
  }, [query.data, filters?.status, filters?.search, filters?.sortBy])

  return {
    documents: filtered,
    allDocuments: query.data ?? [],
    ...query,
  }
}
