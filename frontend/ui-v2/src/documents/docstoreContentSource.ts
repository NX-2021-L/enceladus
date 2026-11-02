/**
 * docstoreContentSource.ts -- a @io-kit/content ContentSource over the docstore (ENC-TSK-R81-0G, FTR-148 AC-1).
 *
 * Lets the kit's DocumentEditor (Cloudscape) edit and create docstore documents. Only get/update are real;
 * the editor never lists, publishes or deletes. Saving goes through the existing governed document API
 * (api/documentWrites.ts): PATCH with If-Match = the content_hash read at load, PUT for a new document.
 * Ids stay DOC-... and `ref` repeats the id so ELR / record-link addressing is unchanged.
 */
import { ContentError, type ContentSource, type Post, type PostPatch } from '@io-kit/content'
import { fetchDocumentRecord } from '../api/client'
import { createDocument, DocumentWriteError, patchDocument } from '../api/documentWrites'
import type { Document } from '../types/records'

export const NEW_DOCUMENT_ID = 'new'

export interface DocstoreSourceOptions {
  /** Project a NEW document is filed under. */
  projectId: string
  /** document_subtype for a NEW document. */
  subtype: string
  /** Cognito sub, stamped as caused_by. */
  actor?: string
}

const CAN = { edit: true, delete: false, publish: false, moderate: false } as const

export function documentToPost(doc: Document): Post {
  return {
    id: doc.document_id,
    ref: doc.document_id,
    type: 'document',
    author: { id: doc.created_by || 'unknown', label: doc.created_by || 'unknown' },
    title: doc.title,
    body: doc.content ?? '',
    attachments: [],
    visibility: 'published',
    created_at: doc.created_at,
    updated_at: doc.updated_at,
    can: { ...CAN },
  }
}

export function blankDocumentPost(actor = 'me'): Post {
  const now = new Date().toISOString()
  return {
    id: NEW_DOCUMENT_ID,
    type: 'document',
    author: { id: actor, label: actor },
    title: '',
    body: '',
    attachments: [],
    visibility: 'published',
    created_at: now,
    updated_at: now,
    can: { ...CAN },
  }
}

function unsupported(op: string): never {
  throw new ContentError('forbidden', `${op} is not available on docstore documents`)
}

export function createDocstoreContentSource(opts: DocstoreSourceOptions): ContentSource {
  const hashes = new Map<string, string>()

  async function get(id: string): Promise<Post> {
    let doc: Document
    try {
      doc = await fetchDocumentRecord<Document>(id)
    } catch (e) {
      throw new ContentError('not_found', e instanceof Error ? e.message : String(e), { id })
    }
    if (doc.content_hash) hashes.set(id, doc.content_hash)
    return documentToPost(doc)
  }

  return {
    capabilities: { drafts: false, edit: true, subject: false, getById: true, audit: false },
    get,
    async update(id: string, patch: PostPatch): Promise<Post> {
      if (id === NEW_DOCUMENT_ID) {
        const title = (patch.title ?? '').trim()
        if (!title) throw new ContentError('validation', 'A title is required.', { field: 'title' })
        try {
          const newId = await createDocument({
            project_id: opts.projectId,
            title,
            content: patch.body ?? '',
            document_subtype: opts.subtype,
            caused_by: opts.actor,
          })
          return await get(newId)
        } catch (e) {
          if (e instanceof DocumentWriteError) throw new ContentError('validation', e.message)
          throw e
        }
      }
      const ifMatch = hashes.get(id)
      if (!ifMatch) throw new ContentError('validation', 'Reload the document before saving (no content hash).', { id })
      try {
        await patchDocument(id, {
          ...(patch.body !== undefined ? { content: patch.body } : {}),
          ...(patch.title ? { title: patch.title } : {}),
          if_match: ifMatch,
          caused_by: opts.actor,
        })
      } catch (e) {
        if (e instanceof DocumentWriteError) {
          if (e.isConflict) throw new ContentError('conflict', 'This document changed since you opened it. Close the editor, reload and re-apply your edit.', { id })
          throw new ContentError(e.status === 403 ? 'forbidden' : 'validation', e.message, { id })
        }
        throw e
      }
      return get(id)
    },
    list: () => unsupported('list'),
    createDraft: () => unsupported('createDraft'),
    setVisibility: () => unsupported('setVisibility'),
    delete: () => unsupported('delete'),
  }
}
