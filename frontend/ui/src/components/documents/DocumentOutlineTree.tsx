import type { DocumentSection } from '../../lib/documentSections'

interface DocumentOutlineTreeProps {
  sections: DocumentSection[]
  changedKeys: Set<string>
}

/**
 * ENC-TSK-P80 (AC-1): navigable outline tree, rendered from the manifest's
 * outline (heading_path / level / ordinal) before the body arrives. Indent
 * reflects heading level (level 2 = no indent, deeper levels step in).
 */
export function DocumentOutlineTree({ sections, changedKeys }: DocumentOutlineTreeProps) {
  if (sections.length === 0) return null

  return (
    <nav aria-label="Document outline" className="bg-slate-800 rounded-lg p-3">
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2 px-1">
        Outline
      </h3>
      <ul className="space-y-0.5">
        {sections.map((section) => (
          <li key={section.key} style={{ paddingLeft: `${Math.max(0, section.entry.level - 2) * 12}px` }}>
            <a
              href={`#${section.key}`}
              className="flex items-center gap-1.5 text-xs text-slate-300 hover:text-blue-400 py-1 px-1 rounded truncate"
            >
              {changedKeys.has(section.key) && (
                <span
                  className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0"
                  role="status"
                  aria-label="Section updated"
                />
              )}
              <span className="truncate">{section.headingText || '(untitled section)'}</span>
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}
