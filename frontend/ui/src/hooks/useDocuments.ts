import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { documentKeys, fetchDocumentsByProject } from '../api/documents'
import { isSessionExpiredError } from '../lib/authSession'
import type { DocumentFilters } from '../types/filters'

/** Fast polling interval for mission-critical docs freshness. */
const DOCUMENTS_POLL_INTERVAL = 500

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

interface UseDocumentsOptions {
  /** Enable automatic polling so newly created documents appear without a
   *  manual refresh.  Mirrors the Feed page's polling behaviour. */
  polling?: boolean
}

/**
 * Fetch documents directly from the document API (`/api/v1/documents?project=`).
 * This avoids feed debounce/cache lag and surfaces new/updated docs quickly.
 */
export function useDocuments(filters?: DocumentFilters, options?: UseDocumentsOptions) {
  const projectId = filters?.projectId ?? ''
  const query = useQuery({
    queryKey: documentKeys.list(projectId),
    queryFn: () => fetchDocumentsByProject(projectId),
    enabled: !!projectId,
    refetchInterval: options?.polling ? DOCUMENTS_POLL_INTERVAL : undefined,
    retry: (count, error) => {
      if (isSessionExpiredError(error)) return false
      return count < 2
    },
    throwOnError: false,
    meta: { suppressSessionExpired: true },
  })

  const documents = query.data?.documents

  const filtered = useMemo(() => {
    if (!documents) return []
    let items = documents
    if (filters?.projectId) items = items.filter((d) => d.project_id === filters.projectId)
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
  }, [documents, filters?.projectId, filters?.status, filters?.search, filters?.sortBy])

  return {
    documents: filtered,
    allDocuments: documents ?? [],
    ...query,
  }
}
