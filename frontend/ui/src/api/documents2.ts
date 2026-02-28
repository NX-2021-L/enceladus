import type { Document } from '../types/feeds'
import { fetchWithAuth } from './client'

const API_BASE = '/api/v1/documents'

export const docs2Keys = {
  list: (projectId: string) => ['docs2', 'list', projectId] as const,
  all: () => ['docs2', 'all'] as const,
  search: (params: Record<string, string>) => ['docs2', 'search', params] as const,
  counts: () => ['docs2', 'counts'] as const,
}

interface DocsListResponse {
  documents: Document[]
  count: number
  total_matches: number
}

export async function fetchProjectDocs(projectId: string): Promise<DocsListResponse> {
  const res = await fetchWithAuth(`${API_BASE}?project=${encodeURIComponent(projectId)}`)
  if (!res.ok) throw new Error(`Failed to fetch documents: ${res.status}`)
  const data = await res.json()
  const documents = data.documents ?? []
  return {
    documents,
    count: data.count ?? documents.length,
    total_matches: data.total_matches ?? documents.length,
  }
}

export async function fetchAllProjectDocs(
  projectIds: string[],
): Promise<{ documents: Document[]; total_matches: number }> {
  const results = await Promise.all(projectIds.map(fetchProjectDocs))
  const seen = new Set<string>()
  const merged: Document[] = []
  let totalMatches = 0
  for (const r of results) {
    totalMatches += r.total_matches
    for (const doc of r.documents) {
      if (!seen.has(doc.document_id)) {
        seen.add(doc.document_id)
        merged.push(doc)
      }
    }
  }
  merged.sort((a, b) => (b.updated_at ?? '').localeCompare(a.updated_at ?? ''))
  return { documents: merged, total_matches: totalMatches }
}

export async function fetchProjectDocCounts(
  projectIds: string[],
): Promise<Record<string, { count: number; total: number; latest_updated_at: string }>> {
  const results = await Promise.all(
    projectIds.map(async (id) => {
      const r = await fetchProjectDocs(id)
      const latest = r.documents[0]?.updated_at ?? ''
      return [id, { count: r.count, total: r.total_matches, latest_updated_at: latest }] as const
    }),
  )
  return Object.fromEntries(results)
}

export async function searchDocsByTitle(
  title: string,
  projectId?: string,
): Promise<DocsListResponse> {
  const qs = new URLSearchParams({ title })
  if (projectId) qs.set('project', projectId)
  const res = await fetchWithAuth(`${API_BASE}/search?${qs.toString()}`)
  if (!res.ok) throw new Error(`Search failed: ${res.status}`)
  const data = await res.json()
  const documents = data.documents ?? []
  return {
    documents,
    count: data.count ?? documents.length,
    total_matches: data.total_matches ?? documents.length,
  }
}
