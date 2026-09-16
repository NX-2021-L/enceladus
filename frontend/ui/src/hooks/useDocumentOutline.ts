/**
 * useDocumentOutline — ENC-TSK-P80 (AC-1, AC-4).
 *
 * Owns the manifest fetch (outline + content_hash), slices the already-
 * fetched document body into per-section text, and wires the AppSync
 * `/records/{document_id}` live-update channel so external mutations refresh
 * the outline and mark changed sections.
 *
 * Deliberately does NOT own the body fetch: DocumentDetailPage already loads
 * the full document (including `.content`) via useRecordFallback for the
 * header/metadata/related-items UI, so this hook takes that body as an
 * input instead of issuing a second, duplicate GET /documents/{id}. That
 * also satisfies AC-1's "manifest first, body separately" ordering for free
 * — the manifest query starts immediately and the outline can render as
 * soon as it resolves, independent of whichever caller-owned fetch supplies
 * the body.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  fetchDocumentManifest,
  documentManifestKeys,
  type DocumentManifest,
} from '../api/documentManifest'
import { sliceDocumentSections, diffChangedSectionKeys, type DocumentSection } from '../lib/documentSections'
import { subscribeToRecordChannel, type RecordChannelStatus } from '../lib/appsyncRecordChannel'

export interface UseDocumentOutlineOptions {
  /** Called when a live-update event arrives for this document, so the
   *  caller can refetch whatever owns the body (useRecordFallback.refetch).
   *  This hook refetches the manifest itself either way. */
  onLiveMutation?: () => void
}

export interface UseDocumentOutlineResult {
  manifest: DocumentManifest | undefined
  sections: DocumentSection[]
  isManifestLoading: boolean
  isManifestError: boolean
  /** Section keys marked "changed" by a live-update refetch since the user
   *  last acknowledged them (clearChanged). */
  changedKeys: Set<string>
  clearChanged: (key: string) => void
  refetchManifest: () => void
  liveStatus: RecordChannelStatus | 'idle'
}

export function useDocumentOutline(
  documentId: string | undefined,
  body: string | undefined,
  options: UseDocumentOutlineOptions = {},
): UseDocumentOutlineResult {
  const { onLiveMutation } = options

  const manifestQuery = useQuery({
    queryKey: documentId ? documentManifestKeys.detail(documentId) : ['documents', 'manifest', 'disabled'],
    queryFn: ({ signal }) => fetchDocumentManifest(documentId as string, { signal }),
    enabled: !!documentId,
  })

  const outline = useMemo(() => manifestQuery.data?.outline ?? [], [manifestQuery.data])
  const sections = useMemo(
    () => (body !== undefined ? sliceDocumentSections(body, outline) : []),
    [body, outline],
  )

  // Diff each new `sections` computation against the previous one so a
  // live-triggered refetch (of manifest and/or body) can mark exactly the
  // sections whose text actually changed, without needing a per-section
  // hash from the server.
  const prevSectionsRef = useRef<DocumentSection[] | null>(null)
  const skipNextDiffRef = useRef(true)
  const [changedKeys, setChangedKeys] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (skipNextDiffRef.current) {
      skipNextDiffRef.current = false
      prevSectionsRef.current = sections
      return
    }
    const prev = prevSectionsRef.current
    prevSectionsRef.current = sections
    // Skip when either side is empty: `prev.length === 0` covers the
    // manifest-still-loading -> first-populated-outline transition (not a
    // live update, just the initial load finishing), and an empty `sections`
    // means the body/outline aren't both available yet either way.
    if (!prev || prev.length === 0 || sections.length === 0) return
    const changed = diffChangedSectionKeys(prev, sections)
    if (changed.size > 0) {
      setChangedKeys((current) => new Set([...current, ...changed]))
    }
  }, [sections])

  const clearChanged = useCallback((key: string) => {
    setChangedKeys((prev) => {
      if (!prev.has(key)) return prev
      const next = new Set(prev)
      next.delete(key)
      return next
    })
  }, [])

  const [liveStatus, setLiveStatus] = useState<RecordChannelStatus | 'idle'>('idle')

  useEffect(() => {
    if (!documentId) return undefined
    setLiveStatus('connecting')
    const unsubscribe = subscribeToRecordChannel({
      documentId,
      onStatusChange: setLiveStatus,
      onEvent: () => {
        manifestQuery.refetch()
        onLiveMutation?.()
      },
    })
    return unsubscribe
    // manifestQuery is a fresh object per render (TanStack Query) — re-run
    // only when the document identity changes, not on every refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [documentId])

  return {
    manifest: manifestQuery.data,
    sections,
    isManifestLoading: manifestQuery.isPending,
    isManifestError: manifestQuery.isError,
    changedKeys,
    clearChanged,
    refetchManifest: () => {
      manifestQuery.refetch()
    },
    liveStatus,
  }
}
