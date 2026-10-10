import { lazy, Suspense } from 'react'
import type { Document } from '../types/records'
import './documentSections.css'

// The document view is the @io-kit/md docstore preset (DVP-TSK-924); lazy so the kit stays out of the initial route.
const KitDocumentView = lazy(() => import('./KitDocumentView'))

/**
 * The document detail "Content" tab body (see primitives/DocumentPrimitive.tsx):
 * docstore-preset rendering with a kit-derived outline and per-section edit
 * (SectionEditor), "Updated" marks on live external mutations.
 */
export function DocumentSectionsView({ record }: { record: Document }) {
  return (
    <Suspense fallback={<p className="ev2-docsec__manifest-loading">Loading document&hellip;</p>}>
      <KitDocumentView record={record} />
    </Suspense>
  )
}
