import type { Document } from '../types/records'
import { fetchDocumentRecord, SessionExpiredError } from './client'

const API_BASE = '/api/v1/documents'
const GOVERNANCE_PROJECT_ID = 'devops'
const GOVERNANCE_KEYWORD = 'governance-file'
const PROJECT_REFERENCE_KEYWORD = 'project-reference'

export { SessionExpiredError }

export const governanceDocKeys = {
  primaryReference: (projectId: string) => ['governance', 'primary-reference', projectId] as const,
  detail: (documentId: string) => ['governance', 'detail', documentId] as const,
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`)
  return (await res.json()) as T
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
  const data = await requestJson<{ documents?: Document[] }>(`${API_BASE}/search?${qs.toString()}`)
  return data.documents ?? []
}

function dedupeByDocumentId(docs: Document[]): Document[] {
  const deduped = new Map<string, Document>()
  for (const doc of docs) deduped.set(doc.document_id, doc)
  return [...deduped.values()]
}

function isCanonicalGovernanceDoc(doc: Document): boolean {
  const keywords = new Set((doc.keywords ?? []).map((k) => k.toLowerCase()))
  if (!keywords.has(GOVERNANCE_KEYWORD)) return false
  const title = (doc.title ?? '').trim().toLowerCase()
  if (title.startsWith('governance:')) return true
  const fileName = (doc.file_name ?? '').trim().toLowerCase()
  return fileName === 'agents.md' || fileName.startsWith('agents/')
}

function isCanonicalProjectReferenceDoc(doc: Document, projectId: string): boolean {
  const keywords = new Set((doc.keywords ?? []).map((k) => k.toLowerCase()))
  if (!keywords.has(PROJECT_REFERENCE_KEYWORD)) return false
  const fileName = (doc.file_name ?? '').trim().toLowerCase()
  if (fileName === `${projectId}-reference.md`) return true
  return (doc.title ?? '').trim().toLowerCase().endsWith('project reference')
}

/** Live docstore governance + project reference docs (ENC-ISS-121 / ENC-TSK-K26). */
export async function fetchGovernanceDocs(projectId: string): Promise<Document[]> {
  const normalized = projectId.trim().toLowerCase()
  if (!normalized) return []

  const [projectReferenceDocs, governanceDocs] = await Promise.all([
    searchDocuments({ project: normalized, keyword: PROJECT_REFERENCE_KEYWORD }),
    searchDocuments({ project: GOVERNANCE_PROJECT_ID, keyword: GOVERNANCE_KEYWORD }),
  ])

  const fallbackProjectReferenceDocs =
    projectReferenceDocs.length > 0
      ? []
      : await searchDocuments({ project: normalized, title: 'Project Reference' })

  return dedupeByDocumentId([
    ...[...projectReferenceDocs, ...fallbackProjectReferenceDocs].filter((d) =>
      isCanonicalProjectReferenceDoc(d, normalized),
    ),
    ...governanceDocs.filter(isCanonicalGovernanceDoc),
  ]).sort((a, b) => (b.updated_at ?? '').localeCompare(a.updated_at ?? ''))
}

export async function fetchGovernanceDocument(documentId: string): Promise<Document> {
  return fetchDocumentRecord<Document>(documentId)
}
