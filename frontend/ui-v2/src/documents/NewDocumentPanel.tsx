import { lazy, Suspense } from 'react'
import { useNavigate } from '@tanstack/react-router'

// Cloudscape + @io-kit/content stay out of the initial bundle (200 KB gz budget).
const DocumentEditorHost = lazy(() => import('./DocumentEditorHost'))

/**
 * The Docs page's "New document" view: the kit DocumentEditor in create mode. DocsSearchPage shows it in place of the
 * list (ENC-ISS-888: never inside the page-header actions); the editor's own Cancel closes it and Save opens the new
 * document. useNavigate lives here so the Docs page calls no router hook until the panel opens.
 */
export function NewDocumentPanel({ defaultProjectId, onClose }: { defaultProjectId?: string; onClose(): void }) {
  const navigate = useNavigate()
  return (
    <div className="ev2-doceditor-panel" role="region" aria-label="New document">
      <Suspense fallback={null}>
        <DocumentEditorHost
          defaultProjectId={defaultProjectId}
          onClose={onClose}
          onSaved={(id) => {
            onClose()
            void navigate({ to: '/document/$id', params: { id } })
          }}
        />
      </Suspense>
    </div>
  )
}
