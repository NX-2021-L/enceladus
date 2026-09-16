import { MarkdownRenderer } from '../shared/MarkdownRenderer'
import type { DocumentSection as DocumentSectionModel } from '../../lib/documentSections'

interface DocumentSectionProps {
  section: DocumentSectionModel
  changed: boolean
  onEdit: () => void
  onAcknowledgeChange: () => void
}

/**
 * ENC-TSK-P80 (AC-1/AC-2/AC-4): one rendered section, keyed by block_id (or
 * the derived slug) as its DOM id so deep links / outline navigation land
 * here, with an edit affordance and a "changed" banner for live updates.
 */
export function DocumentSection({ section, changed, onEdit, onAcknowledgeChange }: DocumentSectionProps) {
  return (
    <div
      id={section.key}
      className="bg-slate-800 rounded-lg p-4 scroll-mt-16"
      data-testid={`document-section-${section.key}`}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <h3 className="text-sm font-semibold text-slate-200">
          {section.headingText || 'Untitled section'}
        </h3>
        <div className="flex items-center gap-2 flex-shrink-0">
          {changed && (
            <button
              onClick={onAcknowledgeChange}
              className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 hover:bg-amber-500/30"
            >
              Updated
            </button>
          )}
          <button
            onClick={onEdit}
            aria-label={`Edit section ${section.headingText || 'untitled'}`}
            className="text-xs text-blue-400 hover:text-blue-300"
          >
            Edit
          </button>
        </div>
      </div>
      {section.body ? (
        <MarkdownRenderer content={section.body} />
      ) : (
        <p className="text-xs text-slate-500 italic">Empty section.</p>
      )}
    </div>
  )
}
