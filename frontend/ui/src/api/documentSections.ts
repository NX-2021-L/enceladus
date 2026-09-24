/**
 * documentSections.ts — client for POST /documents/{id}/sections
 * (documents.patch_section, op=replace).
 *
 * ENC-TSK-P80 (AC-2/AC-3). Same base path and cookie auth transport as
 * api/documents.ts / api/documentManifest.ts.
 */
import { fetchWithAuth } from './client'
import type { DocumentOutlineEntry } from './documentManifest'

const API_BASE = '/api/v1/documents'

export interface SectionAnchor {
  block_id?: string
  heading_path?: string[]
  ordinal?: number
}

export interface PatchSectionRequest {
  document_id: string
  project_id: string
  anchor: SectionAnchor
  op: 'replace'
  body: string
  if_match: string
  include_heading: boolean
  rebase_headings: boolean
  caused_by: string
  governance_hash?: string
}

export interface PatchSectionResponse {
  document_id: string
  version: number
  content_hash: string
  size_bytes: number
  event_id: string
  anchor_resolved: {
    heading_path: string[]
    level: number
    ordinal: number
    block_id: string | null
  }
  bytes_changed: number
  outline: DocumentOutlineEntry[]
}

export interface SectionErrorDetails {
  expected_hash?: string
  current_hash?: string
  current_version?: number
  updated_at?: string
  recommended_next_actions?: string[]
  outline?: DocumentOutlineEntry[]
  candidates?: unknown[]
}

/**
 * Covers all non-2xx responses from the sections endpoint: 412
 * CONTENT_HASH_MISMATCH, 404 ANCHOR_NOT_FOUND, 409 ANCHOR_AMBIGUOUS, and
 * anything else the backend returns. Tolerates both the documented
 * `{error_envelope:{code,message,details}}` shape and a flatter
 * `{code,message,details}` top-level shape.
 */
export class SectionPatchError extends Error {
  readonly status: number
  readonly code: string
  readonly details: SectionErrorDetails

  constructor(status: number, code: string, message: string, details: SectionErrorDetails = {}) {
    super(message)
    this.name = 'SectionPatchError'
    this.status = status
    this.code = code
    this.details = details
  }
}

export function isSectionPatchError(err: unknown): err is SectionPatchError {
  return err instanceof SectionPatchError
}

export function isContentHashMismatch(err: unknown): err is SectionPatchError {
  return isSectionPatchError(err) && (err.status === 412 || err.code === 'CONTENT_HASH_MISMATCH')
}

export async function patchSection(
  documentId: string,
  request: PatchSectionRequest,
): Promise<PatchSectionResponse> {
  const res = await fetchWithAuth(`${API_BASE}/${encodeURIComponent(documentId)}/sections`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })

  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>

  if (!res.ok) {
    const envelope = (data.error_envelope ?? data) as Record<string, unknown>
    const code = String(envelope.code ?? `HTTP_${res.status}`)
    const message = String(envelope.message ?? `Section patch failed: ${res.status}`)
    const details = (envelope.details ?? {}) as SectionErrorDetails
    throw new SectionPatchError(res.status, code, message, details)
  }

  return data as unknown as PatchSectionResponse
}
