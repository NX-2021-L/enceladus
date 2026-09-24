/**
 * documentHistory.ts — client for the document history/rewind/diff surface
 * (documents.history, documents.get at_version, documents.diff).
 *
 * ENC-TSK-P81 (FR-B5-4). Backend contract lands with ENC-TSK-P72 (in
 * flight) — this module codes against the documented shape and is exercised
 * against mocked fetch responses until the gamma endpoints are live. Same
 * base path and cookie-auth transport as api/documentManifest.ts /
 * api/documentSections.ts.
 */
import { API_BASE, NotFoundError, SessionExpiredError } from './client'

export type DocumentHistorySurface = 'mcp' | 'elr' | 'pwa' | 'lambda' | 'unknown'

export interface DocumentHistoryAnchor {
  heading_path: string[]
  ordinal: number
  block_id: string | null
}

export interface DocumentHistoryEvent {
  event_id: string
  ts: string
  actor: string
  surface: DocumentHistorySurface
  op: string
  anchor: DocumentHistoryAnchor | null
  before_hash: string
  after_hash: string
  before_version: number
  after_version: number
  patch_bytes: number
  document_bytes: number
  rejection_code?: string
  diff_available: boolean
}

export interface DocumentHistoryPage {
  events: DocumentHistoryEvent[]
  next_cursor: string | null
}

export interface DocumentAtVersionResponse {
  content: string
  content_hash: string
  version: number
  reconstructed: true
}

export interface DocumentDiffResponse {
  from_version: number
  to_version: number
  from_hash: string
  to_hash: string
  diff: string
  truncated?: boolean
}

/** A rejected event is one the server declined to apply — either flagged
 *  explicitly via rejection_code, or (legacy rows) via an `op` suffixed
 *  `-rejected`. */
export function isRejectedEvent(event: DocumentHistoryEvent): boolean {
  return Boolean(event.rejection_code) || event.op.endsWith('-rejected')
}

/** GET /api/v1/documents/{id}/history?project_id=&cursor=&page_size=&actor=&op=&block_id=
 *  Events come back ordered ts ascending within the page — the caller
 *  (DocumentHistoryPanel) reverses each page to build the newest-first list. */
export async function fetchDocumentHistory(
  documentId: string,
  projectId: string,
  opts: { cursor?: string; pageSize?: number; actor?: string; op?: string; blockId?: string } = {},
  init?: { signal?: AbortSignal },
): Promise<DocumentHistoryPage> {
  const qs = new URLSearchParams({ project_id: projectId })
  if (opts.cursor) qs.set('cursor', opts.cursor)
  qs.set('page_size', String(opts.pageSize ?? 50))
  if (opts.actor) qs.set('actor', opts.actor)
  if (opts.op) qs.set('op', opts.op)
  if (opts.blockId) qs.set('block_id', opts.blockId)

  const url = `${API_BASE}/documents/${encodeURIComponent(documentId)}/history?${qs.toString()}`
  const res = await fetch(url, {
    signal: init?.signal,
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`document ${documentId} history not found`)
  if (!res.ok) throw new Error(`Failed to fetch document history: ${res.status}`)
  const data = (await res.json()) as Partial<DocumentHistoryPage>
  return {
    events: Array.isArray(data.events) ? data.events : [],
    next_cursor: data.next_cursor ?? null,
  }
}

/** 500 INTEGRITY_VIOLATION from GET .../{id}?at_version=N — the reconstructed
 *  body's hash didn't match the recorded chain. Distinguished from a generic
 *  failure so the rewind pane can render a dedicated error state. */
export class DocumentIntegrityError extends Error {
  readonly status = 500
  constructor(message = 'Integrity violation: reconstructed content hash mismatch') {
    super(message)
    this.name = 'DocumentIntegrityError'
  }
}

/** GET /api/v1/documents/{id}?project_id=&at_version=N */
export async function fetchDocumentAtVersion(
  documentId: string,
  projectId: string,
  atVersion: number,
  init?: { signal?: AbortSignal },
): Promise<DocumentAtVersionResponse> {
  const qs = new URLSearchParams({ project_id: projectId, at_version: String(atVersion) })
  const url = `${API_BASE}/documents/${encodeURIComponent(documentId)}?${qs.toString()}`
  const res = await fetch(url, {
    signal: init?.signal,
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`document ${documentId} not found at version ${atVersion}`)
  if (res.status === 500) {
    const body = (await res.json().catch(() => ({}))) as { code?: string; message?: string }
    if (body.code === 'INTEGRITY_VIOLATION') throw new DocumentIntegrityError(body.message)
    throw new Error(body.message ?? `Request failed (500): ${url}`)
  }
  if (!res.ok) throw new Error(`Failed to fetch document at version ${atVersion}: ${res.status}`)
  const data = (await res.json()) as Partial<DocumentAtVersionResponse>
  return {
    content: data.content ?? '',
    content_hash: data.content_hash ?? '',
    version: data.version ?? atVersion,
    reconstructed: true,
  }
}

/** GET /api/v1/documents/{id}/diff?project_id=&from=A&to=B */
export async function fetchDocumentDiff(
  documentId: string,
  projectId: string,
  fromVersion: number,
  toVersion: number,
  init?: { signal?: AbortSignal },
): Promise<DocumentDiffResponse> {
  const qs = new URLSearchParams({
    project_id: projectId,
    from: String(fromVersion),
    to: String(toVersion),
  })
  const url = `${API_BASE}/documents/${encodeURIComponent(documentId)}/diff?${qs.toString()}`
  const res = await fetch(url, {
    signal: init?.signal,
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
    credentials: 'include',
    cache: 'no-store',
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`document ${documentId} diff not found`)
  if (!res.ok) throw new Error(`Failed to fetch document diff: ${res.status}`)
  const data = (await res.json()) as Partial<DocumentDiffResponse>
  return {
    from_version: data.from_version ?? fromVersion,
    to_version: data.to_version ?? toVersion,
    from_hash: data.from_hash ?? '',
    to_hash: data.to_hash ?? '',
    diff: data.diff ?? '',
    truncated: data.truncated,
  }
}

/** SHA-256 of the UTF-8 bytes of `text`, lowercase hex — used by
 *  DocumentRewindPane to verify a reconstructed body client-side in
 *  addition to trusting the server's content_hash field. */
export async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
