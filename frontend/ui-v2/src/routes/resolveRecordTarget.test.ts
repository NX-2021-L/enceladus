/**
 * ENC-TSK-P58 — the single id→route resolver (ENC-ISS-712 root cause).
 *
 * The plan-graph tap handler used to infer `plan` vs `task` from the id and
 * route everything else to /task/<id>, crashing on issues, features and
 * documents. These tests pin the resolver's full type coverage, cross-project
 * prefix resolution, the record_type hint override, and — critically — that
 * unresolvable ids return null rather than a guessed route.
 */
import { describe, expect, it } from 'vitest'
import { resolveRecordTarget } from './recordLink'
import type { ProjectSummary } from '../api/projects'

const PROJECTS: ProjectSummary[] = [
  { project_id: 'enceladus', prefix: 'ENC' },
  { project_id: 'devops', prefix: 'DVP' },
]

describe('resolveRecordTarget (ENC-TSK-P58)', () => {
  it('routes every tracker type by its id segment', () => {
    expect(resolveRecordTarget('ENC-TSK-O59', PROJECTS)).toEqual({
      to: '/$project/task/$id',
      params: { project: 'enceladus', id: 'ENC-TSK-O59' },
    })
    expect(resolveRecordTarget('ENC-ISS-648', PROJECTS)).toEqual({
      to: '/$project/issue/$id',
      params: { project: 'enceladus', id: 'ENC-ISS-648' },
    })
    expect(resolveRecordTarget('ENC-FTR-121', PROJECTS)).toEqual({
      to: '/$project/feature/$id',
      params: { project: 'enceladus', id: 'ENC-FTR-121' },
    })
    expect(resolveRecordTarget('ENC-PLN-086', PROJECTS)).toEqual({
      to: '/$project/plan/$id',
      params: { project: 'enceladus', id: 'ENC-PLN-086' },
    })
    expect(resolveRecordTarget('ENC-LSN-039', PROJECTS)).toEqual({
      to: '/$project/lesson/$id',
      params: { project: 'enceladus', id: 'ENC-LSN-039' },
    })
  })

  it('routes documents without a project segment', () => {
    expect(resolveRecordTarget('DOC-841F5D649EEF', PROJECTS)).toEqual({
      to: '/document/$id',
      params: { id: 'DOC-841F5D649EEF' },
    })
  })

  it('routes sessions and agent types (not project-scoped)', () => {
    expect(resolveRecordTarget('ENC-SES-0G0', PROJECTS)).toEqual({
      to: '/session/$id',
      params: { id: 'ENC-SES-0G0' },
    })
    expect(resolveRecordTarget('ENC-AGT-006', PROJECTS)).toEqual({
      to: '/agent/$agentTypeId',
      params: { agentTypeId: 'ENC-AGT-006' },
    })
  })

  it('resolves the owning project from the id prefix (cross-project)', () => {
    expect(resolveRecordTarget('DVP-ISS-135', PROJECTS)).toEqual({
      to: '/$project/issue/$id',
      params: { project: 'devops', id: 'DVP-ISS-135' },
    })
  })

  it('prefers an explicit record_type hint over id-shape inference', () => {
    expect(resolveRecordTarget('ENC-ISS-648', PROJECTS, 'issue')).toEqual({
      to: '/$project/issue/$id',
      params: { project: 'enceladus', id: 'ENC-ISS-648' },
    })
    expect(resolveRecordTarget('DOC-841F5D649EEF', PROJECTS, 'document')).toEqual({
      to: '/document/$id',
      params: { id: 'DOC-841F5D649EEF' },
    })
    expect(resolveRecordTarget('ENC-SES-0G0', PROJECTS, 'session')).toEqual({
      to: '/session/$id',
      params: { id: 'ENC-SES-0G0' },
    })
  })

  it('returns null instead of guessing — unknown type segment, unknown project prefix, garbage', () => {
    expect(resolveRecordTarget('ENC-XYZ-001', PROJECTS)).toBeNull()
    expect(resolveRecordTarget('ZZZ-TSK-001', PROJECTS)).toBeNull()
    expect(resolveRecordTarget('not-a-record-id', PROJECTS)).toBeNull()
    expect(resolveRecordTarget('', PROJECTS)).toBeNull()
    expect(resolveRecordTarget('   ', PROJECTS)).toBeNull()
  })

  it('returns null for a tracker hint whose project prefix is unregistered', () => {
    expect(resolveRecordTarget('ZZZ-ISS-001', PROJECTS, 'issue')).toBeNull()
  })

  it('trims surrounding whitespace and keeps the id verbatim in params', () => {
    expect(resolveRecordTarget('  ENC-TSK-O59  ', PROJECTS)).toEqual({
      to: '/$project/task/$id',
      params: { project: 'enceladus', id: 'ENC-TSK-O59' },
    })
  })
})
