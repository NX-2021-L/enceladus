import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Modal } from '../design-system'
import {
  patchSection,
  isContentHashMismatch,
  isSectionPatchError,
  type PatchSectionResponse,
  type SectionPatchError,
} from '../api/documentSections'
import { fetchDocumentManifest } from '../api/documentManifest'
import { fetchDocumentRecord } from '../api/client'
import { sliceDocumentSections, type DocumentSection } from '../utils/documentSections'
import { getViewingUserSub } from '../utils/viewerIdentity'
import { SectionConflictView } from './SectionConflictView'
import './documentSections.css'
import './recordDetailHub.css'

export interface SectionEditorProps {
  documentId: string
  projectId: string
  section: DocumentSection
  /** content_hash captured when the editor opened (AC-2: "if_match captured
   *  at load"). Refreshed internally only from this editor's own successful
   *  save responses — never silently updated from background refreshes
   *  while the editor is open (AC-4). */
  ifMatch: string
  /** True when a live-update event touched this section while the editor is
   *  open — surfaces an informational banner only (AC-4: if_match itself is
   *  not touched by it). */
  liveChanged: boolean
  onClose: () => void
  onSaved: (response: PatchSectionResponse) => void
}

interface ConflictState {
  currentText: string
  currentContentHash: string
}

function readableSectionError(err: SectionPatchError): string {
  if (err.code === 'ANCHOR_NOT_FOUND') {
    return 'This section could not be found in the current document (it may have been renamed or removed). Close the editor and reload.'
  }
  if (err.code === 'ANCHOR_AMBIGUOUS') {
    const candidates = err.details.candidates
    const count = Array.isArray(candidates) ? candidates.length : undefined
    return `This section's anchor matches multiple locations${count ? ` (${count})` : ''}. Close the editor and reload to retry.`
  }
  return err.message || `Save failed (${err.code}).`
}

/** Find the same logical section inside a freshly fetched outline+body. */
function findCurrentSection(
  target: DocumentSection,
  currentSections: DocumentSection[],
): DocumentSection | undefined {
  if (target.entry.block_id) {
    const byBlock = currentSections.find((s) => s.entry.block_id === target.entry.block_id)
    if (byBlock) return byBlock
  }
  return (
    currentSections.find((s) => s.key === target.key) ??
    currentSections.find(
      (s) =>
        s.entry.ordinal === target.entry.ordinal &&
        s.entry.heading_path.join(' ') === target.entry.heading_path.join(' '),
    )
  )
}

export function SectionEditor({
  documentId,
  projectId,
  section,
  ifMatch: ifMatchInitial,
  liveChanged,
  onClose,
  onSaved,
}: SectionEditorProps) {
  const [draft, setDraft] = useState(section.body)
  const [includeHeading, setIncludeHeading] = useState(false)
  const [rebaseHeadings, setRebaseHeadings] = useState(true)
  const [ifMatch, setIfMatch] = useState(ifMatchInitial)
  const [error, setError] = useState<string | null>(null)
  const [conflict, setConflict] = useState<ConflictState | null>(null)
  const [loadingConflict, setLoadingConflict] = useState(false)

  const anchor = section.entry.block_id
    ? { block_id: section.entry.block_id }
    : { heading_path: section.entry.heading_path, ordinal: section.entry.ordinal }

  const saveMutation = useMutation({
    mutationFn: () =>
      patchSection(documentId, {
        document_id: documentId,
        project_id: projectId,
        anchor,
        op: 'replace',
        body: draft,
        if_match: ifMatch,
        include_heading: includeHeading,
        rebase_headings: rebaseHeadings,
        caused_by: getViewingUserSub(),
      }),
    onSuccess: (response) => {
      setIfMatch(response.content_hash)
      onSaved(response)
    },
    onError: (err: unknown) => {
      if (isContentHashMismatch(err)) {
        void loadConflictState()
        return
      }
      setError(
        isSectionPatchError(err)
          ? readableSectionError(err)
          : err instanceof Error
            ? err.message
            : 'Save failed.',
      )
    },
  })

  async function loadConflictState() {
    setLoadingConflict(true)
    try {
      const [manifest, doc] = await Promise.all([
        fetchDocumentManifest(documentId),
        fetchDocumentRecord<{ content?: string }>(documentId),
      ])
      const currentSections = sliceDocumentSections(doc.content ?? '', manifest.outline)
      const match = findCurrentSection(section, currentSections)
      setConflict({ currentText: match?.body ?? '', currentContentHash: manifest.content_hash })
    } catch {
      setError('Could not load the current version for comparison. Close and retry.')
    } finally {
      setLoadingConflict(false)
    }
  }

  function handleSave() {
    setError(null)
    saveMutation.mutate()
  }

  function handleReapply() {
    if (!conflict) return
    // "Rebase" per AC-3: keep the user's draft untouched, adopt the fresh
    // hash so a subsequent Save can succeed. No content merge happens here.
    setIfMatch(conflict.currentContentHash)
    setConflict(null)
  }

  const saving = saveMutation.isPending

  return (
    <Modal
      visible
      header={`Edit: ${section.headingText || 'Untitled section'}`}
      recordId={documentId}
      onDismiss={onClose}
      footer={
        conflict || loadingConflict ? null : (
          <>
            <button type="button" onClick={onClose} className="ev2-rdh__action ev2-rdh__modal-cancel">
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={saving}
              className="ev2-rdh__action ev2-rdh__modal-submit"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
          </>
        )
      }
    >
      {liveChanged && !conflict && (
        <div className="ev2-docsec__editor-banner">
          <p>
            This section changed elsewhere while you were editing. Your draft is unaffected — Save
            will only fail (with a conflict view) if the stored copy no longer matches what you
            started from.
          </p>
        </div>
      )}

      {conflict ? (
        <SectionConflictView
          headingText={section.headingText}
          yourEdit={draft}
          currentStored={conflict.currentText}
          onReapply={handleReapply}
          onDiscard={onClose}
        />
      ) : loadingConflict ? (
        <p className="ev2-docsec__editor-loading">Loading current version&hellip;</p>
      ) : (
        <>
          <textarea
            rows={10}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            aria-label={`Section body for ${section.headingText || 'untitled section'}`}
            className="ev2-rdh__note-textarea ev2-docsec__editor-textarea"
            autoFocus
          />

          <details className="ev2-docsec__editor-advanced">
            <summary>Advanced</summary>
            <div className="ev2-docsec__editor-advanced-body">
              <label>
                <input
                  type="checkbox"
                  checked={includeHeading}
                  onChange={(e) => setIncludeHeading(e.target.checked)}
                />
                Include heading line in replacement body
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={rebaseHeadings}
                  onChange={(e) => setRebaseHeadings(e.target.checked)}
                />
                Rebase nested headings
              </label>
            </div>
          </details>

          {error && <p className="ev2-rdh__action-feedback is-error">{error}</p>}
        </>
      )}
    </Modal>
  )
}
