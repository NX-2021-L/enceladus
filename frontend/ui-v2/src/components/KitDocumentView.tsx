import { useState, type AnchorHTMLAttributes } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useRouter } from '@tanstack/react-router'
import { KitMarkdown } from '@io-kit/md/react'
import '@io-kit/md/docstore.css'
import type { Document } from '../types/records'
import { recordKeys } from '../api/queryOptions'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { useDocumentOutline } from '../hooks/useDocumentOutline'
import { kitDocstorePlugins, kitSections } from '../utils/kitDocstore'
import type { DocumentSection } from '../utils/documentSections'
import { SectionEditor } from './SectionEditor'
import './documentSections.css'

/** Internal (host-route) links navigate in-app; everything else keeps the browser default. */
function HostLink({ href, children, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const router = useRouter()
  const internal = !!href && href.startsWith('/') && !href.startsWith('//')
  return (
    <a
      href={href}
      {...rest}
      onClick={
        internal
          ? (e) => {
              if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
              e.preventDefault()
              router.history.push(href)
            }
          : rest.onClick
      }
    >
      {children}
    </a>
  )
}

/**
 * DVP-TSK-916 (DVP-PLN-011 E3-W2.3): the document Content tab rendered through
 * @io-kit/md's docstore preset (header card, YAML tree, id links to ui-v2
 * routes, claim badges, section anchors). Only mounted behind the markdown
 * engine flag (utils/markdownEngine.ts); the legacy DocumentSectionsView stays
 * the default this release.
 *
 * The outline and the section editor are driven by the kit's parse: block ids
 * and heading paths (+ ordinals) are what SectionEditor sends to patchSection,
 * the same addressing as `elr doc_patch`, so the 412 conflict view keeps working.
 */
export default function KitDocumentView({ record }: { record: Document }) {
  const queryClient = useQueryClient()
  const documentId = record.document_id
  const projectId = record.project_id
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)

  function invalidateDocument() {
    queryClient.invalidateQueries({ queryKey: recordKeys.detail('document', 'global', documentId) })
  }

  // The manifest only supplies the live content_hash (if_match) and the changed-section marks.
  const { manifest, changedKeys, clearChanged } = useDocumentOutline(documentId, record.content, {
    onLiveMutation: invalidateDocument,
  })

  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [editIfMatch, setEditIfMatch] = useState('')

  const { doc, items } = kitSections(record.content ?? '')
  const editing: DocumentSection | undefined = items.find((it) => it.section.key === editingKey)?.section

  function openEditor(section: DocumentSection) {
    setEditIfMatch(manifest?.content_hash ?? record.content_hash ?? '')
    setEditingKey(section.key)
  }

  if (!record.content || !record.content.trim()) return null

  return (
    <div className="ev2-docsec__view" data-md-engine="kit">
      {items.length > 0 && (
        <nav aria-label="Document outline" className="ev2-docsec__outline">
          <h3 className="ev2-docsec__outline-title">Outline</h3>
          <ul className="ev2-docsec__outline-list">
            {items.map(({ slug, section }) => (
              <li
                key={section.key}
                className="ev2-docsec__outline-item"
                style={{ paddingLeft: `${Math.max(0, section.entry.level - 2) * 12}px` }}
              >
                <a href={`#${slug}`} className="ev2-docsec__outline-link">
                  {changedKeys.has(section.key) && (
                    <span className="ev2-docsec__outline-dot" role="status" aria-label="Section updated" />
                  )}
                  <span className="ev2-docsec__outline-text">{section.headingText || '(untitled section)'}</span>
                </a>
                <button
                  type="button"
                  onClick={() => openEditor(section)}
                  aria-label={`Edit section ${section.headingText || 'untitled'}`}
                  className="ev2-docsec__edit-btn"
                >
                  Edit
                </button>
              </li>
            ))}
          </ul>
        </nav>
      )}

      <KitMarkdown
        source={doc}
        plugins={kitDocstorePlugins(projects)}
        components={{ a: HostLink } as never}
      />

      {editing && (
        <SectionEditor
          documentId={documentId}
          projectId={projectId}
          section={editing}
          ifMatch={editIfMatch}
          liveChanged={!!manifest && manifest.content_hash !== editIfMatch}
          onClose={() => setEditingKey(null)}
          onSaved={() => {
            clearChanged(editing.key)
            setEditingKey(null)
            invalidateDocument()
          }}
        />
      )}
    </div>
  )
}
