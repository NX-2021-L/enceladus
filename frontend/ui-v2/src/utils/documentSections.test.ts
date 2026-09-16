import { describe, expect, it } from 'vitest'
import { diffChangedSectionKeys, sectionKey, sliceDocumentSections } from './documentSections'
import type { DocumentOutlineEntry } from '../api/documentManifest'

function entry(overrides: Partial<DocumentOutlineEntry> = {}): DocumentOutlineEntry {
  return {
    heading_path: ['Section'],
    level: 2,
    ordinal: 0,
    block_id: null,
    line_start: 0,
    line_end: 0,
    section_bytes: 0,
    ...overrides,
  }
}

const BODY = [
  '# Doc Title',
  '',
  'Intro paragraph, not part of any section.',
  '',
  '## First',
  '',
  'First body line 1.',
  'First body line 2.',
  '',
  '### Nested',
  '',
  'Nested body.',
  '',
  '## Second',
  '<!-- enc:block:01HXYZ -->',
  '',
  'Second body.',
  '',
].join('\n')

const OUTLINE: DocumentOutlineEntry[] = [
  entry({ heading_path: ['First'], level: 2, ordinal: 0, line_start: 5, line_end: 9 }),
  entry({ heading_path: ['First', 'Nested'], level: 3, ordinal: 1, line_start: 10, line_end: 12 }),
  entry({
    heading_path: ['Second'],
    level: 2,
    ordinal: 2,
    block_id: '01HXYZ',
    line_start: 14,
    line_end: 17,
  }),
]

describe('sectionKey', () => {
  it('uses block_id when present', () => {
    expect(sectionKey(entry({ block_id: '01HABC' }))).toBe('01HABC')
  })

  it('derives a slug + ordinal when block_id is null', () => {
    expect(sectionKey(entry({ heading_path: ['Foo Bar'], ordinal: 3, block_id: null }))).toBe(
      'foo-bar-3',
    )
  })

  it('falls back to a generic slug for an empty heading', () => {
    expect(sectionKey(entry({ heading_path: [], ordinal: 0, block_id: null }))).toBe('section-0')
  })
})

describe('sliceDocumentSections', () => {
  it('returns [] for an empty outline', () => {
    expect(sliceDocumentSections(BODY, [])).toEqual([])
  })

  it('slices each section from its heading to the next heading of level <= its own', () => {
    const sections = sliceDocumentSections(BODY, OUTLINE)
    expect(sections).toHaveLength(3)

    const [first, nested, second] = sections

    // A parent section's range runs "up to the next heading of level <= its
    // level" — since Nested is a level-3 heading nested under First
    // (level 2), First's slice legitimately includes it (mirrors what a
    // patch_section replace against First's anchor would overwrite).
    expect(first.headingText).toBe('First')
    expect(first.body).toBe(
      'First body line 1.\nFirst body line 2.\n\n### Nested\n\nNested body.',
    )

    expect(nested.headingText).toBe('Nested')
    expect(nested.body).toBe('Nested body.')

    // Second carries a block_id and an `enc:block` comment line right after
    // its heading — both must be excluded from the extracted body.
    expect(second.key).toBe('01HXYZ')
    expect(second.body).toBe('Second body.')
  })

  it('excludes the leading H1 document title from heading matching', () => {
    const singleSection = sliceDocumentSections(
      ['# Title', '## Only', 'body text'].join('\n'),
      [entry({ heading_path: ['Only'], level: 2, ordinal: 0 })],
    )
    expect(singleSection[0]?.body).toBe('body text')
  })

  it('degrades gracefully (empty body) when heading counts do not line up', () => {
    const sections = sliceDocumentSections('# Title\nno headings here', [
      entry({ heading_path: ['Missing'], level: 2, ordinal: 0 }),
    ])
    expect(sections[0]?.body).toBe('')
  })
})

describe('diffChangedSectionKeys', () => {
  it('marks sections whose body text changed', () => {
    const before = sliceDocumentSections(BODY, OUTLINE)
    const changedBody = BODY.replace('First body line 1.', 'EDITED first body line.')
    const after = sliceDocumentSections(changedBody, OUTLINE)

    const changed = diffChangedSectionKeys(before, after)
    expect(changed.has('first-0')).toBe(true)
    expect(changed.has('01HXYZ')).toBe(false)
  })

  it('marks newly appeared sections as changed', () => {
    const before = sliceDocumentSections(BODY, OUTLINE.slice(0, 1))
    const after = sliceDocumentSections(BODY, OUTLINE)
    const changed = diffChangedSectionKeys(before, after)
    expect(changed.has('01HXYZ')).toBe(true)
  })

  it('reports no changes for identical slicing', () => {
    const sections = sliceDocumentSections(BODY, OUTLINE)
    expect(diffChangedSectionKeys(sections, sections).size).toBe(0)
  })
})
