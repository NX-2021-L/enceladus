import { describe, expect, it } from 'vitest'
import type { ReactElement } from 'react'
import type { ChangelogEntry } from '../api/changelog'
import {
  buildChangelogColumns,
  sortChangelogRows,
  toChangelogRows,
  type ChangelogRow,
} from './ChangelogRoute'

const ENTRIES: ChangelogEntry[] = [
  {
    project_id: 'enceladus',
    spec_id: 'ENC-1',
    version: '4.12.0',
    previous_version: '4.11.0',
    change_type: 'minor',
    release_summary: 'Changelog page',
    changes: ['Added changelog page'],
    deployed_at: '2026-07-01T12:00:00Z',
    related_record_ids: ['ENC-TSK-L33'],
  },
  {
    project_id: 'other-program',
    spec_id: 'ENC-1',
    version: '1.0.1',
    previous_version: '1.0.0',
    change_type: 'patch',
    release_summary: 'Hotfix',
    changes: ['Fixed a bug'],
    deployed_at: '2026-07-03T09:00:00Z',
    related_record_ids: [],
  },
]

describe('toChangelogRows', () => {
  it('composes a project-scoped unique row id since spec_id collides across projects', () => {
    const rows = toChangelogRows(ENTRIES)
    const ids = rows.map((r) => r.id)
    expect(new Set(ids).size).toBe(2)
    expect(ids).toEqual(['enceladus-ENC-1', 'other-program-ENC-1'])
  })
})

describe('sortChangelogRows', () => {
  it('sorts descending by deployed_at by default field', () => {
    const rows = toChangelogRows(ENTRIES)
    const sorted = sortChangelogRows(rows, { sortingField: 'deployed_at', isDescending: true })
    expect(sorted.map((r) => r.project_id)).toEqual(['other-program', 'enceladus'])
  })

  it('sorts ascending when isDescending is false', () => {
    const rows = toChangelogRows(ENTRIES)
    const sorted = sortChangelogRows(rows, { sortingField: 'deployed_at', isDescending: false })
    expect(sorted.map((r) => r.project_id)).toEqual(['enceladus', 'other-program'])
  })
})

describe('buildChangelogColumns', () => {
  const rows: ChangelogRow[] = toChangelogRows(ENTRIES)

  it('leftmost column renders the project as a Link to the project page', () => {
    const columns = buildChangelogColumns(new Map([['enceladus', 'Enceladus']]))
    expect(columns[0]!.id).toBe('project')

    const cellElement = columns[0]!.cell(rows[0]!) as ReactElement<{
      to: string
      children: React.ReactNode
    }>
    expect(cellElement.props.to).toBe('/projects/enceladus')
    expect(cellElement.props.children).toBe('Enceladus')
  })

  it('falls back to the raw project_id when no display name is registered', () => {
    const columns = buildChangelogColumns(new Map())
    const cellElement = columns[0]!.cell(rows[1]!) as ReactElement<{
      to: string
      children: React.ReactNode
    }>
    expect(cellElement.props.to).toBe('/projects/other-program')
    expect(cellElement.props.children).toBe('other-program')
  })

  it('renders version, change type, summary, and deployed columns', () => {
    const columns = buildChangelogColumns(new Map())
    expect(columns.map((c) => c.id)).toEqual([
      'project',
      'version',
      'change_type',
      'release_summary',
      'deployed_at',
    ])
    expect(columns[2]!.cell(rows[0]!)).toBe('Minor')
    expect(columns[3]!.cell(rows[0]!)).toBe('Changelog page')
  })
})
