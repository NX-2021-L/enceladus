import { afterEach, describe, expect, it, vi } from 'vitest'
import { ContentError } from '@io-kit/content'

vi.mock('../api/client', () => ({ fetchDocumentRecord: vi.fn() }))
vi.mock('../api/documentWrites', async () => {
  class DocumentWriteError extends Error {
    status: number
    code: string
    constructor(status: number, code: string, message: string) {
      super(message)
      this.status = status
      this.code = code
    }
    get isConflict() {
      return this.status === 409 || this.status === 412
    }
  }
  return { DocumentWriteError, createDocument: vi.fn(), patchDocument: vi.fn() }
})

import { fetchDocumentRecord } from '../api/client'
import { createDocument, DocumentWriteError, patchDocument } from '../api/documentWrites'
import { createDocstoreContentSource, documentToPost, NEW_DOCUMENT_ID } from './docstoreContentSource'
import type { Document } from '../types/records'

const doc = {
  document_id: 'DOC-ABC123456789',
  title: 'T',
  content: '# T\n\nbody\n',
  content_hash: 'a'.repeat(64),
  created_by: 'io',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
} as unknown as Document

afterEach(() => vi.clearAllMocks())

describe('docstoreContentSource', () => {
  it('maps a docstore document to a document Post and keeps the DOC id as id and ref', () => {
    const p = documentToPost(doc)
    expect(p).toMatchObject({ id: doc.document_id, ref: doc.document_id, type: 'document', body: doc.content, title: 'T' })
    expect(p.can.edit).toBe(true)
  })

  it('PATCHes with the content_hash read at load as If-Match, then re-reads', async () => {
    vi.mocked(fetchDocumentRecord).mockResolvedValue(doc)
    const src = createDocstoreContentSource({ projectId: 'enceladus', subtype: 'doc', actor: 'sub-1' })
    await src.get(doc.document_id)
    await src.update(doc.document_id, { body: '# T\n\nnew\n', title: 'T2' })
    expect(patchDocument).toHaveBeenCalledWith(doc.document_id, { content: '# T\n\nnew\n', title: 'T2', if_match: 'a'.repeat(64), caused_by: 'sub-1' })
    expect(fetchDocumentRecord).toHaveBeenCalledTimes(2)
  })

  it('maps 412/409 to a conflict ContentError instead of overwriting', async () => {
    vi.mocked(fetchDocumentRecord).mockResolvedValue(doc)
    vi.mocked(patchDocument).mockRejectedValue(new (DocumentWriteError as unknown as new (s: number, c: string, m: string) => Error)(412, 'CONTENT_HASH_MISMATCH', 'x'))
    const src = createDocstoreContentSource({ projectId: 'enceladus', subtype: 'doc' })
    await src.get(doc.document_id)
    await expect(src.update(doc.document_id, { body: 'z' })).rejects.toMatchObject({ code: 'conflict' })
  })

  it('refuses to save before the document was loaded (no hash)', async () => {
    const src = createDocstoreContentSource({ projectId: 'enceladus', subtype: 'doc' })
    await expect(src.update('DOC-X', { body: 'z' })).rejects.toBeInstanceOf(ContentError)
    expect(patchDocument).not.toHaveBeenCalled()
  })

  it('creates through documents.put with project + subtype and returns the new document', async () => {
    vi.mocked(createDocument).mockResolvedValue(doc.document_id)
    vi.mocked(fetchDocumentRecord).mockResolvedValue(doc)
    const src = createDocstoreContentSource({ projectId: 'enceladus', subtype: 'idea', actor: 'sub-1' })
    const out = await src.update(NEW_DOCUMENT_ID, { title: ' Hello ', body: '# Hello\n' })
    expect(createDocument).toHaveBeenCalledWith({ project_id: 'enceladus', title: 'Hello', content: '# Hello\n', document_subtype: 'idea', caused_by: 'sub-1' })
    expect(out.id).toBe(doc.document_id)
    await expect(src.update(NEW_DOCUMENT_ID, { title: '  ', body: 'x' })).rejects.toMatchObject({ code: 'validation' })
  })
})
