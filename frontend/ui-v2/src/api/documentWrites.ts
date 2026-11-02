/**
 * documentWrites.ts -- whole-document create/update against the document API (ENC-TSK-R81-0G, FTR-148 AC-1).
 *
 * Same base path and Cognito-cookie transport as api/documentSections.ts. PUT creates (documents.put semantics:
 * server-assigned id, subtype allow-list and compliance checks all run server-side, unchanged); PATCH updates
 * with the content-hash `if_match` precondition (ENC-TSK-P70): a stale hash is 412 CONTENT_HASH_MISMATCH and
 * a stale revision is 409 REVISION_CONFLICT, never a silent overwrite.
 */
import { API_BASE, SessionExpiredError } from './client'
import { fetchGovernanceHash } from './actions'

export class DocumentWriteError extends Error {
  readonly status: number
  readonly code: string
  readonly details: Record<string, unknown>

  constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
    super(message)
    this.name = 'DocumentWriteError'
    this.status = status
    this.code = code
    this.details = details
  }

  /** 409 REVISION_CONFLICT / 412 CONTENT_HASH_MISMATCH: someone else saved first. */
  get isConflict(): boolean {
    return this.status === 409 || this.status === 412
  }
}

export interface CreateDocumentInput {
  project_id: string
  title: string
  content: string
  document_subtype: string
  description?: string
  keywords?: string[]
  caused_by?: string
}

export interface PatchDocumentInput {
  content?: string
  title?: string
  if_match: string
  caused_by?: string
}

async function send(method: 'PUT' | 'PATCH', url: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    method,
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest', 'content-type': 'application/json' },
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(body),
  })
  if (res.status === 401) throw new SessionExpiredError()
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    const env = (data.error_envelope ?? data) as Record<string, unknown>
    throw new DocumentWriteError(
      res.status,
      String(env.code ?? `HTTP_${res.status}`),
      String(env.message ?? env.error ?? `Document write failed (${res.status})`),
      (env.details ?? {}) as Record<string, unknown>,
    )
  }
  return data
}

/** documents.put: returns the server-assigned DOC id. */
export async function createDocument(input: CreateDocumentInput): Promise<string> {
  const governance_hash = await fetchGovernanceHash()
  const data = await send('PUT', `${API_BASE}/documents`, { ...input, governance_hash })
  const id = String(data.document_id ?? (data.document as Record<string, unknown> | undefined)?.document_id ?? '')
  if (!id) throw new DocumentWriteError(502, 'NO_DOCUMENT_ID', 'The document API did not return a document id.')
  return id
}

/** documents.patch (whole-document) with the If-Match content-hash precondition. */
export async function patchDocument(documentId: string, input: PatchDocumentInput): Promise<void> {
  const governance_hash = await fetchGovernanceHash()
  await send('PATCH', `${API_BASE}/documents/${encodeURIComponent(documentId)}`, { ...input, governance_hash })
}
