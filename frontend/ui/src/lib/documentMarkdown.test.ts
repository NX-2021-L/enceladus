import { describe, expect, it } from 'vitest'
import { documentMarkdownFileName, documentToMarkdown, slugifyTitle, yamlQuote } from './documentMarkdown'
import type { Document } from '../types/feeds'

function makeDoc(overrides: Partial<Document> = {}): Document {
  return {
    document_id: 'DOC-ABC123',
    project_id: 'enceladus',
    title: 'My Doc',
    description: '',
    file_name: 'my-doc.md',
    content_type: 'text/markdown',
    content_hash: 'abc',
    size_bytes: 42,
    keywords: [],
    related_items: [],
    status: 'active',
    created_by: 'tester',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    version: 1,
    content: '# Hello\n\nSome body text.',
    document_maturity_state: 'raw',
    document_subtype: 'general',
    ...overrides,
  }
}

describe('documentToMarkdown', () => {
  it('includes a YAML frontmatter block with the expected fields', () => {
    const doc = makeDoc()
    const md = documentToMarkdown(doc, { now: () => new Date('2026-07-01T12:00:00.000Z') })

    expect(md.startsWith('---\n')).toBe(true)
    expect(md).toContain('document_id: DOC-ABC123')
    expect(md).toContain('title: My Doc')
    expect(md).toContain('document_subtype: general')
    expect(md).toContain('status: active')
    expect(md).toContain('document_maturity_state: raw')
    expect(md).toContain('project_id: enceladus')
    // exported_at contains colons, so yamlQuote wraps it in double quotes.
    expect(md).toContain('exported_at: "2026-07-01T12:00:00.000Z"')
  })

  it('passes the content field through verbatim, including markdown special characters', () => {
    const content = '# Title\n\n```js\nconst x = { a: 1 } // comment\n```\n\n> quote *em* **bold**\n\n- [ ] todo: item'
    const doc = makeDoc({ content })
    const md = documentToMarkdown(doc, { now: () => new Date('2026-07-01T12:00:00.000Z') })

    expect(md.endsWith(content)).toBe(true)
    // body must not be mutated/re-rendered
    expect(md).toContain(content)
  })

  it('handles a missing content field gracefully', () => {
    const doc = makeDoc({ content: undefined })
    const md = documentToMarkdown(doc, { now: () => new Date('2026-07-01T12:00:00.000Z') })
    expect(md.endsWith('---\n\n')).toBe(true)
  })

  it('generates exported_at at call time when no clock is injected', () => {
    const doc = makeDoc()
    const before = Date.now()
    const md = documentToMarkdown(doc)
    const after = Date.now()

    const match = md.match(/exported_at: "?([^"\n]+?)"?\n/)
    expect(match).not.toBeNull()
    const parsed = new Date(match![1]!).getTime()
    expect(parsed).toBeGreaterThanOrEqual(before)
    expect(parsed).toBeLessThanOrEqual(after)
  })

  it('quotes a title containing a colon so the frontmatter stays valid YAML', () => {
    const doc = makeDoc({ title: 'Design Doc: Phase 2' })
    const md = documentToMarkdown(doc, { now: () => new Date('2026-07-01T12:00:00.000Z') })
    expect(md).toContain('title: "Design Doc: Phase 2"')
  })

  it('quotes and escapes a title containing double quotes', () => {
    const doc = makeDoc({ title: 'The "Best" Doc' })
    const md = documentToMarkdown(doc, { now: () => new Date('2026-07-01T12:00:00.000Z') })
    expect(md).toContain('title: "The \\"Best\\" Doc"')
  })
})

describe('yamlQuote', () => {
  it('leaves plain scalars unquoted', () => {
    expect(yamlQuote('active')).toBe('active')
    expect(yamlQuote('DOC-ABC123')).toBe('DOC-ABC123')
  })

  it('quotes values containing a colon', () => {
    expect(yamlQuote('a: b')).toBe('"a: b"')
  })

  it('quotes values containing a hash', () => {
    expect(yamlQuote('note #1')).toBe('"note #1"')
  })

  it('quotes values with leading/trailing whitespace', () => {
    expect(yamlQuote('  padded  ')).toBe('"  padded  "')
  })

  it('quotes the empty string', () => {
    expect(yamlQuote('')).toBe('""')
  })

  it('quotes values starting with special YAML indicator characters', () => {
    expect(yamlQuote('- item')).toBe('"- item"')
    expect(yamlQuote('*anchor')).toBe('"*anchor"')
  })

  it('escapes embedded backslashes and quotes', () => {
    expect(yamlQuote('back\\slash "quote"')).toBe('"back\\\\slash \\"quote\\""')
  })
})

describe('slugifyTitle', () => {
  it('lowercases and hyphenates the title', () => {
    expect(slugifyTitle('My Great Doc!')).toBe('my-great-doc')
  })

  it('collapses repeated separators and trims leading/trailing hyphens', () => {
    expect(slugifyTitle('  --Weird   Title--  ')).toBe('weird-title')
  })
})

describe('documentMarkdownFileName', () => {
  it('builds {DOC-ID}-{slug}.md', () => {
    const doc = makeDoc({ document_id: 'DOC-XYZ789', title: 'Design Doc: Phase 2' })
    expect(documentMarkdownFileName(doc)).toBe('DOC-XYZ789-design-doc-phase-2.md')
  })

  it('falls back to just the document id when title slugifies to empty', () => {
    const doc = makeDoc({ document_id: 'DOC-XYZ789', title: '***' })
    expect(documentMarkdownFileName(doc)).toBe('DOC-XYZ789.md')
  })
})
