/**
 * documentManifest.ts — client for GET /documents/{id}/manifest
 * (documents.manifest).
 *
 * ENC-TSK-P92 (ports ENC-TSK-P80, which landed this contract in
 * frontend/ui — the sunset legacy app — instead of the production v4
 * cockpit). AC-1: the document detail view loads this projection FIRST
 * (title/outline/content_hash — cheap and fast) so the outline can render
 * independently of the full body, which arrives via the existing
 * `GET /documents/{id}` read (api/client.ts `fetchDocumentRecord` /
 * `documentQueryOptions`). Same base path and cookie-auth transport
 * (`credentials: 'include'`) as the rest of the document API surface.
 */
import { API_BASE, NotFoundError, SessionExpiredError } from './client'

export interface DocumentOutlineEntry {
  heading_path: string[]
  level: number
  ordinal: number
  block_id: string | null
  /** Informational only — see utils/documentSections.ts for why section
   *  slicing does not rely on these line numbers being exact. */
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
  const url = `${API_BASE}/documents/${encodeURIComponent(documentId)}/manifest`
  const res = await fetch(url, {
    signal: init?.signal,
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`document ${documentId} manifest not found`)
  if (!res.ok) throw new Error(`Failed to fetch document manifest: ${res.status}`)
  const data = (await res.json()) as Record<string, unknown>
  // Defensive unwrap — mirrors fetchDocumentRecord's `data.document ?? data`
  // in case the backend lane nests the projection under a `manifest` key.
  const manifest = (data.manifest ?? data) as DocumentManifest
  return {
    ...manifest,
    content_hash: manifest.content_hash ?? unquoteEtag(res.headers.get('etag')) ?? '',
    outline: Array.isArray(manifest.outline) ? manifest.outline : [],
  }
}
