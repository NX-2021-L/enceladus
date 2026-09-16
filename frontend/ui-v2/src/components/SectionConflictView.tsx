import './documentSections.css'
// Reuses the RecordDetailHub modal action-button styles (ev2-rdh__action /
// ev2-rdh__modal-cancel / ev2-rdh__modal-submit) rather than inventing a
// parallel button style — see RecordDetailHub's own Note/Transition modals.
import './recordDetailHub.css'

interface SectionConflictViewProps {
  headingText: string
  /** The user's in-progress draft (what they were editing when save 412'd). */
  yourEdit: string
  /** Freshly re-fetched current section text from the server. */
  currentStored: string
  onReapply: () => void
  onDiscard: () => void
}

/**
 * ENC-TSK-P92 (AC-3, ports ENC-TSK-P80): 412 CONTENT_HASH_MISMATCH
 * side-by-side conflict view.
 *
 * "Re-apply" keeps the user's draft text as-is and adopts the freshly
 * fetched content_hash as the new if_match — this is the "rebase" the AC
 * describes: no line-level automatic merge is attempted, the user's edit is
 * simply re-based onto the current server state so a subsequent Save can
 * succeed. "Discard" abandons the draft entirely and closes the editor.
 * Neither action writes anything — only the editor's own Save button does.
 */
export function SectionConflictView({
  headingText,
  yourEdit,
  currentStored,
  onReapply,
  onDiscard,
}: SectionConflictViewProps) {
  return (
    <div className="ev2-docsec__conflict">
      <div className="ev2-docsec__conflict-banner">
        <p className="ev2-docsec__conflict-banner-title">
          Conflict — &ldquo;{headingText || 'this section'}&rdquo; changed on the server since you
          started editing.
        </p>
        <p className="ev2-docsec__conflict-banner-hint">
          Review both versions below. Nothing is saved until you choose.
        </p>
      </div>

      <div className="ev2-docsec__conflict-grid">
        <div className="ev2-docsec__conflict-col">
          <h4 className="ev2-docsec__conflict-col-label">Your edit</h4>
          <pre className="ev2-docsec__conflict-pre">{yourEdit || '(empty)'}</pre>
        </div>
        <div className="ev2-docsec__conflict-col">
          <h4 className="ev2-docsec__conflict-col-label">Current on server</h4>
          <pre className="ev2-docsec__conflict-pre">{currentStored || '(empty)'}</pre>
        </div>
      </div>

      <div className="ev2-docsec__conflict-actions">
        <button type="button" onClick={onDiscard} className="ev2-rdh__action ev2-rdh__modal-cancel">
          Discard my edit
        </button>
        <button type="button" onClick={onReapply} className="ev2-rdh__action ev2-rdh__modal-submit">
          Re-apply my edit
        </button>
      </div>
    </div>
  )
}
