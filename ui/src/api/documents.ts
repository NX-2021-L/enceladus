import type { Document } from '../types/feeds'
import { fetchWithAuth } from './client'

const API_BASE = '/api/v1/documents'
const GOVERNANCE_PROJECT_ID = 'devops'
const GOVERNANCE_KEYWORD = 'governance-file'
const PROJECT_REFERENCE_KEYWORD = 'project-reference'

export const documentKeys = {
  list: (projectId: string) => ['documents', 'list', projectId] as const,
  detail: (documentId: string) => ['documents', 'detail', documentId] as const,
  search: (params: Record<string, string>) => ['documents', 'search', params] as const,
  primaryReference: (projectId: string) => ['documents', 'primary-reference', projectId] as const,
}

export async function fetchDocumentsByProject(projectId: string): Promise<Document[]> {
  const res = await fetchWithAuth(`${API_BASE}?project=${encodeURIComponent(projectId)}`)
  if (!res.ok) throw new Error(`Failed to fetch documents: ${res.status}`)
  const data = await res.json()
  return data.documents ?? []
}

export async function fetchDocument(documentId: string): Promise<Document> {
  const res = await fetchWithAuth(`${API_BASE}/${encodeURIComponent(documentId)}`)
  if (!res.ok) throw new Error(`Failed to fetch document: ${res.status}`)
  const data = await res.json()
  return data.document ?? data
}

export async function searchDocuments(params: {
  project?: string
  keyword?: string
  related?: string
  title?: string
}): Promise<Document[]> {
  const qs = new URLSearchParams()
  if (params.project) qs.set('project', params.project)
  if (params.keyword) qs.set('keyword', params.keyword)
  if (params.related) qs.set('related', params.related)
  if (params.title) qs.set('title', params.title)
  const res = await fetchWithAuth(`${API_BASE}/search?${qs.toString()}`)
  if (!res.ok) throw new Error(`Search failed: ${res.status}`)
  const data = await res.json()
  return data.documents ?? []
}

function dedupeByDocumentId(docs: Document[]): Document[] {
  const deduped = new Map<string, Document>()
  for (const doc of docs) {
    if (!deduped.has(doc.document_id)) deduped.set(doc.document_id, doc)
  }
  return Array.from(deduped.values())
}

function referenceRank(doc: Document, projectId: string): number {
  const keywords = new Set((doc.keywords ?? []).map((keyword) => keyword.toLowerCase()))
  if (doc.project_id === projectId && keywords.has(PROJECT_REFERENCE_KEYWORD)) return 0
  if (keywords.has(GOVERNANCE_KEYWORD)) return 1
  return 2
}

function isCanonicalProjectReferenceDoc(doc: Document, projectId: string): boolean {
  const keywords = new Set((doc.keywords ?? []).map((keyword) => keyword.toLowerCase()))
  if (!keywords.has(PROJECT_REFERENCE_KEYWORD)) return false

  const fileName = (doc.file_name ?? '').trim().toLowerCase()
  if (fileName === `${projectId}-reference.md`) return true

  const title = (doc.title ?? '').trim().toLowerCase()
  return title.endsWith('project reference')
}

function isCanonicalGovernanceDoc(doc: Document): boolean {
  const keywords = new Set((doc.keywords ?? []).map((keyword) => keyword.toLowerCase()))
  if (!keywords.has(GOVERNANCE_KEYWORD)) return false

  const title = (doc.title ?? '').trim().toLowerCase()
  if (title.startsWith('governance:')) return true

  const fileName = (doc.file_name ?? '').trim().toLowerCase()
  return fileName === 'agents.md' || fileName.startsWith('agents/')
}

function compareUpdatedAtDesc(a: Document, b: Document): number {
  const aTime = a.updated_at ?? ''
  const bTime = b.updated_at ?? ''
  return bTime.localeCompare(aTime)
}

export async function fetchPrimaryProjectReferenceDocs(projectId: string): Promise<Document[]> {
  const normalizedProject = projectId.trim().toLowerCase()
  if (!normalizedProject) return []

  const [projectReferenceDocs, governanceDocs] = await Promise.all([
    searchDocuments({ project: normalizedProject, keyword: PROJECT_REFERENCE_KEYWORD }),
    searchDocuments({ project: GOVERNANCE_PROJECT_ID, keyword: GOVERNANCE_KEYWORD }),
  ])

  // Some older records may have title tags but not keyword tags.
  const fallbackProjectReferenceDocs =
    projectReferenceDocs.length > 0
      ? []
      : await searchDocuments({ project: normalizedProject, title: 'Project Reference' })

  const canonicalProjectReferenceDocs = [...projectReferenceDocs, ...fallbackProjectReferenceDocs]
    .filter((doc) => isCanonicalProjectReferenceDoc(doc, normalizedProject))
  const canonicalGovernanceDocs = governanceDocs.filter(isCanonicalGovernanceDoc)

  return dedupeByDocumentId([
    ...canonicalProjectReferenceDocs,
    ...canonicalGovernanceDocs,
  ]).sort((a, b) => {
    const rankDiff = referenceRank(a, normalizedProject) - referenceRank(b, normalizedProject)
    if (rankDiff !== 0) return rankDiff
    return compareUpdatedAtDesc(a, b)
  })
}
