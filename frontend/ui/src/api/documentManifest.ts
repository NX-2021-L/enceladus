/**
 * documentManifest.ts — client for GET /documents/{id}/manifest.
 *
 * ENC-TSK-P80 (AC-1): the document detail route loads this projection FIRST
 * (title/outline/content_hash — cheap and fast) so the outline can render
 * before the full body arrives via the separate `fetchDocument` call in
 * api/documents.ts. Same base path (`/api/v1/documents`) and auth transport
 * (`fetchWithAuth`, cookie-based) as the rest of the document API surface.
 */
import { fetchWithAuth } from './client'

const API_BASE = '/api/v1/documents'

export interface DocumentOutlineEntry {
  heading_path: string[]
  level: number
  ordinal: number
  block_id: string | null
  /** Informational only — see lib/documentSections.ts for why slicing does
   *  not rely on these line numbers being exact. */
  line_start: number
  line_end: number
  section_bytes: number
}

export interface DocumentManifest {
  document_id: string
  project_id: string
  title: string
  document_subtype?: string
  subtypepattern?: string
  version: number
  content_hash: string
  size_bytes: number
  updated_at: string
  history_count?: number
  outline: DocumentOutlineEntry[]
}

export const documentManifestKeys = {
  detail: (documentId: string) => ['documents', 'manifest', documentId] as const,
}

/** Strip surrounding quotes from an ETag header value (`"abc123"` -> `abc123`). */
function unquoteEtag(value: string | null): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  return trimmed.startsWith('"') && trimmed.endsWith('"') ? trimmed.slice(1, -1) : trimmed
}

export async function fetchDocumentManifest(
  documentId: string,
  init?: { signal?: AbortSignal },
): Promise<DocumentManifest> {
  const res = await fetchWithAuth(`${API_BASE}/${encodeURIComponent(documentId)}/manifest`, init)
  if (res.status === 404) {
    const { NotFoundError } = await import('./tracker')
    throw new NotFoundError(`document ${documentId} manifest not found`)
  }
  if (!res.ok) throw new Error(`Failed to fetch document manifest: ${res.status}`)
  const data = await res.json()
  // Defensive unwrap — mirrors fetchDocument's `data.document ?? data` in
  // case the backend lane nests the projection under a `manifest` key.
  const manifest = (data.manifest ?? data) as DocumentManifest
  return {
    ...manifest,
    content_hash: manifest.content_hash ?? unquoteEtag(res.headers.get('etag')) ?? '',
    outline: Array.isArray(manifest.outline) ? manifest.outline : [],
  }
}
