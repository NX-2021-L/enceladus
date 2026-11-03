/**
 * DocumentEditorHost -- mounts the kit's Cloudscape DocumentEditor on a docstore document (ENC-TSK-R81-0G,
 * FTR-148 AC-1). Lazy chunk: Cloudscape + @io-kit/content never touch the initial route bundle.
 *   - documentId set: loads that document and edits it (PATCH + If-Match, 412/409 surfaces as a conflict).
 *   - documentId absent: "new document" -- pick project + subtype, then the same editor creates it (PUT).
 */
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, FormField, Select, SpaceBetween, Spinner } from '@cloudscape-design/components'
import { DocumentEditor } from '@io-kit/content/react'
import type { Post } from '@io-kit/content'
import '@io-kit/content/content.css'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { getViewingUserSub } from '../utils/viewerIdentity'
import { blankDocumentPost, createDocstoreContentSource, NEW_DOCUMENT_ID } from './docstoreContentSource'

/** Subtypes that need no extra metadata (handoff/coe/wave/skill/context-node carry required fields). */
const CREATE_SUBTYPES = [
  { value: 'doc', label: 'doc' },
  { value: 'idea', label: 'idea' },
]

export interface DocumentEditorHostProps {
  documentId?: string
  /** Project preselected for a new document. */
  defaultProjectId?: string
  onSaved(documentId: string): void
  onClose(): void
}

export default function DocumentEditorHost({ documentId, defaultProjectId, onSaved, onClose }: DocumentEditorHostProps) {
  const creating = !documentId
  const { data: projects = [] } = useQuery({ ...projectRegistryQueryOptions, enabled: creating })
  const [projectId, setProjectId] = useState(defaultProjectId ?? 'enceladus')
  const [subtype, setSubtype] = useState('doc')
  const actor = getViewingUserSub()
  const source = createDocstoreContentSource({ projectId, subtype, actor })
  const [post, setPost] = useState<Post | null>(() => (creating ? blankDocumentPost(actor) : null))
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!documentId) return
    let live = true
    source.get(documentId).then(
      (p) => live && setPost(p),
      (e: unknown) => live && setError(e instanceof Error ? e.message : String(e)),
    )
    return () => {
      live = false
    }
  }, [documentId, source])

  const projectOptions = projects.map((p) => ({ value: p.project_id, label: p.project_id }))

  return (
    <div className="ev2-doceditor" data-testid="document-editor-host">
      <SpaceBetween size="m">
        {creating && (
          <SpaceBetween direction="horizontal" size="m">
            <FormField label="Project">
              <Select
                selectedOption={{ value: projectId, label: projectId }}
                options={projectOptions.length ? projectOptions : [{ value: projectId, label: projectId }]}
                onChange={(e) => setProjectId(e.detail.selectedOption.value ?? projectId)}
              />
            </FormField>
            <FormField label="Subtype">
              <Select
                selectedOption={CREATE_SUBTYPES.find((s) => s.value === subtype) ?? CREATE_SUBTYPES[0]}
                options={CREATE_SUBTYPES}
                onChange={(e) => setSubtype(e.detail.selectedOption.value ?? 'doc')}
              />
            </FormField>
          </SpaceBetween>
        )}
        {error && <Alert type="error">{error}</Alert>}
        {!post && !error && <Spinner />}
        {post && (
          <DocumentEditor
            post={post}
            source={source}
            onClose={onClose}
            // ENC-ISS-888: a new document already has the whole page, and the Project/Subtype selects above it must stay
            // reachable on a phone, so create mode never switches to the kit's full-screen modal.
            {...(creating ? { fullScreenBelow: 0 } : {})}
            onSaved={(saved) => onSaved(post.id === NEW_DOCUMENT_ID ? saved.id : post.id)}
          />
        )}
      </SpaceBetween>
    </div>
  )
}
