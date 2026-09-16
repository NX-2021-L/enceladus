/**
 * documentSections.ts — client-side section slicing for the P80 outline
 * editor (FR-B5-1..3, B5-5..6).
 *
 * The document API contract gives us the full body (`doc.content`) and an
 * outline of {heading_path, level, ordinal, block_id, line_start, line_end}
 * per section, but explicitly documents line_start/line_end as
 * "informational". This module derives each section's text by walking the
 * body's own heading lines in encounter order and pairing them 1:1 with the
 * outline (which excludes the body's leading H1 title line) — so slicing
 * stays correct even if the server's line-numbering convention differs from
 * a naive split, and degrades gracefully (empty section body) if the counts
 * don't line up rather than throwing.
 */
import type { DocumentOutlineEntry } from '../api/documentManifest'
import { slugifyTitle } from './documentMarkdown'

const BLOCK_COMMENT_RE = /^<!--\s*enc:block:[A-Za-z0-9_-]+\s*-->\s*$/
const HEADING_RE = /^(#{1,6})\s+\S/

export interface DocumentSection {
  entry: DocumentOutlineEntry
  /** Stable identity for this section: block_id when present, else a slug
   *  derived from the heading text + ordinal (AC-1's "derived slug"). Used
   *  as the DOM id (so deep links / scroll-to work) and as the React key. */
  key: string
  /** Last segment of heading_path — the section's own heading text. */
  headingText: string
  /** Extracted section body (heading line and any `enc:block` comment line
   *  stripped), per the API contract's slicing rule. */
  body: string
}

/** Derive the stable key for an outline entry (block_id, else slug+ordinal). */
export function sectionKey(entry: DocumentOutlineEntry): string {
  if (entry.block_id) return entry.block_id
  const lastHeading = entry.heading_path[entry.heading_path.length - 1] ?? ''
  const slug = slugifyTitle(lastHeading) || 'section'
  return `${slug}-${entry.ordinal}`
}

interface HeadingLine {
  index: number
  level: number
}

function findHeadingLines(lines: string[]): HeadingLine[] {
  const out: HeadingLine[] = []
  for (let i = 0; i < lines.length; i++) {
    const match = HEADING_RE.exec(lines[i] ?? '')
    if (match) out.push({ index: i, level: match[1].length })
  }
  return out
}

/**
 * Slice `body` into one DocumentSection per outline entry, in outline order.
 * Returns `[]` when the outline is empty (non-markdown / headingless docs —
 * callers should fall back to whole-body rendering in that case).
 */
export function sliceDocumentSections(
  body: string,
  outline: DocumentOutlineEntry[],
): DocumentSection[] {
  if (!outline.length) return []

  const lines = body.split('\n')
  const headingLines = findHeadingLines(lines)
  // heading_path excludes the document's own H1 title line — drop it here
  // too so outline[i] lines up with contentHeadings[i].
  const contentHeadings =
    headingLines.length > 0 && headingLines[0].level === 1 ? headingLines.slice(1) : headingLines

  return outline.map((entry, i) => {
    const key = sectionKey(entry)
    const headingText = entry.heading_path[entry.heading_path.length - 1] ?? ''
    const start = contentHeadings[i]
    if (!start) return { entry, key, headingText, body: '' }

    let bodyStart = start.index + 1
    if (BLOCK_COMMENT_RE.test((lines[bodyStart] ?? '').trim())) bodyStart += 1

    let bodyEnd = lines.length
    for (let j = i + 1; j < outline.length; j++) {
      const nextHeading = contentHeadings[j]
      if (nextHeading && outline[j].level <= entry.level) {
        bodyEnd = nextHeading.index
        break
      }
    }

    // Trim leading/trailing blank lines only — this is a display/editing
    // normalization, not a change to which lines belong to the section (a
    // parent section's range still spans its nested subsections' text, per
    // "up to the next heading of level <= its level").
    const text = lines
      .slice(bodyStart, bodyEnd)
      .join('\n')
      .replace(/^\n+/, '')
      .replace(/\n+$/, '')
    return { entry, key, headingText, body: text }
  })
}

/**
 * Compare two section slicings (e.g. before/after a live-update refetch) and
 * return the keys whose body text changed or is newly present (AC-4:
 * "sections whose content_hash-derived state changed are marked 'changed'").
 * Removed sections are not reported — there is nothing left to mark.
 */
export function diffChangedSectionKeys(
  before: DocumentSection[],
  after: DocumentSection[],
): Set<string> {
  const beforeByKey = new Map(before.map((s) => [s.key, s.body]))
  const changed = new Set<string>()
  for (const section of after) {
    const priorBody = beforeByKey.get(section.key)
    if (priorBody === undefined || priorBody !== section.body) changed.add(section.key)
  }
  return changed
}
