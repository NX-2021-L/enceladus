import { MarkdownContent } from './MarkdownContent'
import type { DocumentSection as DocumentSectionModel } from '../utils/documentSections'
import './documentSections.css'

interface DocumentSectionProps {
  section: DocumentSectionModel
  projectId?: string
  changed: boolean
  onEdit: () => void
  onAcknowledgeChange: () => void
}

/**
 * ENC-TSK-P92 (AC-1/AC-2/AC-4, ports ENC-TSK-P80): one rendered section,
 * keyed by block_id (or the derived slug) as its DOM id so deep links /
 * outline navigation land here, with an edit affordance and a "changed"
 * banner for live updates.
 */
export function DocumentSection({
  section,
  projectId,
  changed,
  onEdit,
  onAcknowledgeChange,
}: DocumentSectionProps) {
  return (
    <div id={section.key} className="ev2-docsec__section" data-testid={`document-section-${section.key}`}>
      <div className="ev2-docsec__section-head">
        <h3 className="ev2-docsec__section-title">{section.headingText || 'Untitled section'}</h3>
        <div className="ev2-docsec__section-actions">
          {changed && (
            <button type="button" onClick={onAcknowledgeChange} className="ev2-docsec__badge">
              Updated
            </button>
          )}
          <button
            type="button"
            onClick={onEdit}
            aria-label={`Edit section ${section.headingText || 'untitled'}`}
            className="ev2-docsec__edit-btn"
          >
            Edit
          </button>
        </div>
      </div>
      {section.body ? (
        <MarkdownContent text={section.body} projectId={projectId} />
      ) : (
        <p className="ev2-docsec__empty">Empty section.</p>
      )}
    </div>
  )
}
