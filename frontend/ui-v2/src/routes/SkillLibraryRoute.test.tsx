import { describe, expect, it } from 'vitest'
import type { ReactElement } from 'react'
import type { SkillListItem } from '../api/skillLibrary'
import { buildSkillLibraryColumns, sortSkillLibraryRows } from './SkillLibraryRoute'

const ITEMS: SkillListItem[] = [
  {
    document_id: 'DOC-B',
    title: 'Bravo skill',
    description: 'Second skill.',
    version: '2',
    updated_at: '2026-07-01T12:00:00Z',
    runtime_hint: 'claude',
    document_subtype: 'skill',
  },
  {
    document_id: 'DOC-A',
    title: 'Alpha skill',
    description: 'First skill.',
    version: '10',
    updated_at: '2026-07-03T09:00:00Z',
    runtime_hint: 'claude,agentskills',
    document_subtype: 'skill',
  },
]

describe('sortSkillLibraryRows', () => {
  it('sorts ascending by title by default field', () => {
    const sorted = sortSkillLibraryRows(ITEMS, { sortingField: 'title', isDescending: false })
    expect(sorted.map((r) => r.document_id)).toEqual(['DOC-A', 'DOC-B'])
  })

  it('sorts descending when isDescending is true', () => {
    const sorted = sortSkillLibraryRows(ITEMS, { sortingField: 'title', isDescending: true })
    expect(sorted.map((r) => r.document_id)).toEqual(['DOC-B', 'DOC-A'])
  })

  it('sorts by updated_at', () => {
    const sorted = sortSkillLibraryRows(ITEMS, { sortingField: 'updated_at', isDescending: false })
    expect(sorted.map((r) => r.document_id)).toEqual(['DOC-B', 'DOC-A'])
  })
})

describe('buildSkillLibraryColumns', () => {
  const columns = buildSkillLibraryColumns()

  it('renders title, description, version, runtime, and updated columns', () => {
    expect(columns.map((c) => c.id)).toEqual([
      'title',
      'description',
      'version',
      'runtime_hint',
      'updated_at',
    ])
  })

  it('leftmost column renders a Link to the document detail route', () => {
    const cellElement = columns[0]!.cell(ITEMS[0]!) as ReactElement<{
      to: string
      children: React.ReactNode
    }>
    expect(cellElement.props.to).toBe('/document/DOC-B')
    expect(cellElement.props.children).toBe('Bravo skill')
  })

  it('falls back to document_id when title is empty', () => {
    const noTitle = { ...ITEMS[0]!, title: '' }
    const cellElement = columns[0]!.cell(noTitle) as ReactElement<{ children: React.ReactNode }>
    expect(cellElement.props.children).toBe('DOC-B')
  })

  it('shows the description inline, falling back to an em dash when empty', () => {
    expect(columns[1]!.cell(ITEMS[0]!)).toBe('Second skill.')
    expect(columns[1]!.cell({ ...ITEMS[0]!, description: '' })).toBe('—')
  })
})
