import type { Document } from '../types/feeds'

/**
 * ENC-FTR-051 — document markdown download.
 *
 * Serializes a loaded Document record into a standalone markdown file: a YAML
 * frontmatter block containing the record's key metadata fields, followed by
 * the raw (unmodified) markdown body from `document.content`.
 */

/**
 * Quote a YAML scalar value only when necessary. Plain scalars are returned
 * as-is; anything that could be misparsed by a YAML reader (colons, quotes,
 * `#` comments, leading/trailing whitespace, or a leading special indicator
 * character) is wrapped in a double-quoted YAML string with `\` and `"`
 * escaped.
 */
export function yamlQuote(value: string): string {
  const needsQuoting =
    value === '' ||
    value !== value.trim() ||
    /[:#"'\n]/.test(value) ||
    /^[-?:,[\]{}&*!|>%@`]/.test(value)

  if (!needsQuoting) return value

  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  return `"${escaped}"`
}

function yamlField(key: string, value: string | undefined): string {
  return `${key}: ${yamlQuote(value ?? '')}`
}

export interface DocumentMarkdownOptions {
  /** Injectable clock for deterministic tests. Defaults to `new Date()`. */
  now?: () => Date
}

/**
 * Build the full markdown document (frontmatter + verbatim body) for a
 * given loaded Document record.
 */
export function documentToMarkdown(doc: Document, options: DocumentMarkdownOptions = {}): string {
  const now = options.now ? options.now() : new Date()
  const exportedAt = now.toISOString()

  const frontmatterLines = [
    '---',
    yamlField('document_id', doc.document_id),
    yamlField('title', doc.title),
    yamlField('document_subtype', doc.document_subtype),
    yamlField('status', doc.status),
    yamlField('document_maturity_state', doc.document_maturity_state),
    yamlField('project_id', doc.project_id),
    yamlField('exported_at', exportedAt),
    '---',
    '',
    '',
  ]

  return frontmatterLines.join('\n') + (doc.content ?? '')
}

/**
 * Build a filesystem-safe filename for the exported markdown: lowercase,
 * non-alphanumeric runs collapsed to a single hyphen, trimmed of leading/
 * trailing hyphens.
 */
export function slugifyTitle(title: string): string {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

export function documentMarkdownFileName(doc: Document): string {
  const slug = slugifyTitle(doc.title ?? '')
  return slug ? `${doc.document_id}-${slug}.md` : `${doc.document_id}.md`
}
