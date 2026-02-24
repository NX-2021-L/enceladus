import type { Document } from '../types/feeds'

function basename(fileName: string): string {
  const trimmed = fileName.trim()
  if (!trimmed) return ''
  const parts = trimmed.split('/')
  return parts[parts.length - 1] ?? ''
}

export function stripExtension(fileName: string): string {
  const name = basename(fileName)
  if (!name) return ''
  const lastDot = name.lastIndexOf('.')
  if (lastDot <= 0) return name
  return name.slice(0, lastDot)
}

export function isDocId(value: string): boolean {
  return /^DOC-[A-Z0-9]+$/i.test(value.trim())
}

export function documentSlugFromFileName(fileName: string | undefined, fallback: string): string {
  const stripped = stripExtension(fileName ?? '')
  return stripped || fallback
}

export function buildCanonicalDocumentPath(documentId: string, fileName: string | undefined): string {
  const slug = documentSlugFromFileName(fileName, documentId)
  return `/documents/${documentId}/${encodeURIComponent(slug)}`
}

export function buildCanonicalDocumentPathFromDoc(doc: Document): string {
  return buildCanonicalDocumentPath(doc.document_id, doc.file_name)
}

export function decodeSlug(value: string | undefined): string {
  if (!value) return ''
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}
