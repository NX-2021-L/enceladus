import { lazy, Suspense, useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { Document } from '../types/records'
import { recordKeys } from '../api/queryOptions'
import { useDocumentOutline } from '../hooks/useDocumentOutline'
import { DocumentOutlineTree } from './DocumentOutlineTree'
import { DocumentSection } from './DocumentSection'
import { SectionEditor } from './SectionEditor'
import { MarkdownContent } from './MarkdownContent'
import type { DocumentSection as DocumentSectionModel } from '../utils/documentSections'
import './documentSections.css'

// DVP-TSK-916: lazy so the kit (and its unified/remark stack) stays out of the main chunk while the flag is off.
const KitDocumentView = lazy(() => import('./KitDocumentView'))

/**
 * ENC-TSK-P92 (AC-1..AC-4, ports ENC-TSK-P80) — the document detail
 * "Content" tab body (see primitives/DocumentPrimitive.tsx). Renders the
 * manifest-driven outline tree + per-section bodies, wires each section's
 * edit affordance to SectionEditor (AC-2/AC-3), and marks sections touched
 * by a live external mutation (AC-4).
 *
 * Falls back to whole-body MarkdownContent when the outline is empty
 * (headingless / non-markdown document, or the manifest fetch failed) —
 * utils/documentSections.ts documents this as the intended degrade.
 */
export function DocumentSectionsView({ record }: { record: Document }) {
  // DVP-TSK-916 (DVP-PLN-011 E3-W2.3): ?md=kit (or the ev2.md.engine preference)
  // swaps in the @io-kit/md docstore renderer. Default stays 'legacy' this
  // release; the flip-and-remove step is DVP-TSK-924 (E3-W3.4).
  // DVP-TSK-935: the default is the kit-backed MarkdownContent INSIDE this same section view, so the
  // document UI is unchanged. The whole-document KitDocumentView is opt-in via ?md=kitdoc.
  const [kitDoc] = useState(() => typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('md') === 'kitdoc')
  if (kitDoc) {
    return (
      <Suspense fallback={<p className="ev2-docsec__manifest-loading">Loading document&hellip;</p>}>
        <KitDocumentView record={record} />
      </Suspense>
    )
  }
  return <LegacyDocumentSectionsView record={record} />
}

function LegacyDocumentSectionsView({ record }: { record: Document }) {
  const queryClient = useQueryClient()
  const documentId = record.document_id
  const projectId = record.project_id

  function invalidateDocument() {
    // The document route always calls documentQueryOptions(id) with no
    // explicit projectId (routes/router.tsx), which defaults to 'global' —
    // matching that cache key here refreshes the record.content this view
    // was handed as a prop once a save or a live mutation lands.
    queryClient.invalidateQueries({ queryKey: recordKeys.detail('document', 'global', documentId) })
  }

  const { manifest, sections, isManifestLoading, isManifestError, changedKeys, clearChanged } =
    useDocumentOutline(documentId, record.content, { onLiveMutation: invalidateDocument })

  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [editIfMatch, setEditIfMatch] = useState('')

  const editingSection: DocumentSectionModel | undefined = sections.find((s) => s.key === editingKey)

  const hasSections = sections.length > 0

  useEffect(() => {
    if (!hasSections) return
    const hash = window.location.hash.replace(/^#/, '')
    if (!hash) return
    // AC-1: deep links to a section land on it once the outline-sliced
    // sections are in the DOM (they aren't yet on initial hash navigation,
    // since the browser's own anchor scroll fires before this renders).
    document.getElementById(hash)?.scrollIntoView({ block: 'start' })
  }, [hasSections])

  function openEditor(section: DocumentSectionModel) {
    // AC-2: if_match captured at load — the freshest content_hash we have
    // right now (the manifest that produced these sections).
    setEditIfMatch(manifest?.content_hash ?? record.content_hash ?? '')
    setEditingKey(section.key)
  }

  function closeEditor() {
    setEditingKey(null)
  }

  if (!hasSections && !isManifestLoading) {
    return <MarkdownContent text={record.content} projectId={projectId} />
  }

  return (
    <div className="ev2-docsec__view">
      {!hasSections && isManifestLoading ? (
        <p className="ev2-docsec__manifest-loading">Loading outline&hellip;</p>
      ) : (
        <>
          <DocumentOutlineTree sections={sections} changedKeys={changedKeys} />
          {sections.map((section) => (
            <DocumentSection
              key={section.key}
              section={section}
              projectId={projectId}
              changed={changedKeys.has(section.key)}
              onEdit={() => openEditor(section)}
              onAcknowledgeChange={() => clearChanged(section.key)}
            />
          ))}
        </>
      )}

      {isManifestError && (
        <p className="ev2-docsec__manifest-loading">
          Couldn&apos;t refresh the outline — showing the last known sections.
        </p>
      )}

      {editingSection && (
        <SectionEditor
          documentId={documentId}
          projectId={projectId}
          section={editingSection}
          ifMatch={editIfMatch}
          // The if_match token is the whole document's content_hash, not a
          // per-section one — ANY mutation (to this section or another)
          // bumps it and would 412 a save against the stale capture, so the
          // "changed elsewhere" banner keys off the manifest's current hash
          // moving past what this editor captured, not the narrower
          // per-section changedKeys (which drives the outline/section
          // "Updated" badges instead).
          liveChanged={!!manifest && manifest.content_hash !== editIfMatch}
          onClose={closeEditor}
          onSaved={() => {
            clearChanged(editingSection.key)
            closeEditor()
            invalidateDocument()
          }}
        />
      )}
    </div>
  )
}
