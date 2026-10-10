import type { DocumentSection } from '../utils/documentSections'
import './documentSections.css'

interface DocumentOutlineTreeProps {
  sections: DocumentSection[]
  changedKeys: Set<string>
}

/**
 * ENC-TSK-P92 (AC-1, ports ENC-TSK-P80): navigable outline tree, rendered
 * from the manifest's outline (heading_path / level / ordinal) independently
 * of the full body. Indent reflects heading level (level 2 = no indent,
 * deeper levels step in).
 */
export function DocumentOutlineTree({ sections, changedKeys }: DocumentOutlineTreeProps) {
  if (sections.length === 0) return null

  return (
    <nav aria-label="Document outline" className="ev2-docsec__outline">
      <h3 className="ev2-docsec__outline-title">Outline</h3>
      <ul className="ev2-docsec__outline-list">
        {sections.map((section) => (
          <li
            key={section.key}
            className="ev2-docsec__outline-item"
            style={{ paddingLeft: `${Math.max(0, section.entry.level - 2) * 12}px` }}
          >
            <a href={`#${section.key}`} className="ev2-docsec__outline-link">
              {changedKeys.has(section.key) && (
                <span className="ev2-docsec__outline-dot" role="status" aria-label="Section updated" />
              )}
              <span className="ev2-docsec__outline-text">{section.headingText || '(untitled section)'}</span>
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}
