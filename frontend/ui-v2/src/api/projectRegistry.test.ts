import { describe, expect, it } from 'vitest'
import {
  inferRecordNavigation,
  resolveProjectFromRecordId,
} from './projectRegistry'
import type { ProjectSummary } from './projects'

const PROJECTS: ProjectSummary[] = [
  { project_id: 'enceladus', prefix: 'ENC' },
  { project_id: 'other-program', prefix: 'OTH' },
]

describe('resolveProjectFromRecordId', () => {
  it('maps ENC prefix to enceladus', () => {
    expect(resolveProjectFromRecordId('ENC-TSK-K21', PROJECTS)).toBe('enceladus')
  })

  it('maps OTH prefix to other-program', () => {
    expect(resolveProjectFromRecordId('OTH-TSK-001', PROJECTS)).toBe('other-program')
  })

  it('returns null for unknown prefix', () => {
    expect(resolveProjectFromRecordId('DOC-12A69AF1D3BE', PROJECTS)).toBeNull()
  })
})

describe('inferRecordNavigation', () => {
  it('resolves tracker record with project', () => {
    expect(inferRecordNavigation('enc-tsk-k21', PROJECTS)).toEqual({
      type: 'task',
      id: 'ENC-TSK-K21',
      projectId: 'enceladus',
    })
  })

  it('resolves document without project', () => {
    expect(inferRecordNavigation('doc-abc', PROJECTS)).toEqual({
      type: 'document',
      id: 'DOC-ABC',
      projectId: null,
    })
  })

  it('returns null for garbage input', () => {
    expect(inferRecordNavigation('hello', PROJECTS)).toBeNull()
  })
})
