import { lazy, Suspense, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { Button } from '../design-system'

// Cloudscape + @io-kit/content stay out of the initial bundle (200 KB gz budget).
const DocumentEditorHost = lazy(() => import('./DocumentEditorHost'))

function NewDocumentPanel({ defaultProjectId, onClose }: { defaultProjectId?: string; onClose(): void }) {
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

/** "New document" entry for the Docs page: a button and, once opened, the kit DocumentEditor in create mode. */
export function NewDocumentButton({ defaultProjectId }: { defaultProjectId?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        {open ? 'Cancel new document' : 'New document'}
      </Button>
      {open && <NewDocumentPanel defaultProjectId={defaultProjectId} onClose={() => setOpen(false)} />}
    </>
  )
}
