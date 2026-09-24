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
 * ENC-TSK-P80 (AC-3): 412 CONTENT_HASH_MISMATCH side-by-side conflict view.
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
    <div className="space-y-3">
      <div className="rounded-lg bg-amber-500/10 border border-amber-600/40 p-3">
        <p className="text-xs text-amber-300 font-medium">
          Conflict — &ldquo;{headingText || 'this section'}&rdquo; changed on the server since you
          started editing.
        </p>
        <p className="text-xs text-amber-400/80 mt-1">
          Review both versions below. Nothing is saved until you choose.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <h4 className="text-[11px] uppercase tracking-wider text-slate-400 mb-1">Your edit</h4>
          <pre className="whitespace-pre-wrap break-words text-xs bg-slate-900 rounded-lg p-3 max-h-60 overflow-y-auto text-slate-200">
            {yourEdit || '(empty)'}
          </pre>
        </div>
        <div>
          <h4 className="text-[11px] uppercase tracking-wider text-slate-400 mb-1">
            Current on server
          </h4>
          <pre className="whitespace-pre-wrap break-words text-xs bg-slate-900 rounded-lg p-3 max-h-60 overflow-y-auto text-slate-200">
            {currentStored || '(empty)'}
          </pre>
        </div>
      </div>

      <div className="flex items-center justify-end gap-2">
        <button
          onClick={onDiscard}
          className="text-xs px-4 py-2 rounded-full text-slate-400 hover:text-slate-200"
        >
          Discard my edit
        </button>
        <button
          onClick={onReapply}
          className="text-xs px-4 py-2 rounded-full bg-blue-700 text-white hover:bg-blue-600"
        >
          Re-apply my edit
        </button>
      </div>
    </div>
  )
}
