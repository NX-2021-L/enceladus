import { describe, expect, it } from 'vitest'
import { documentHref, recordHref } from '../routes/recordLink'
import { recordKeys } from './queryOptions'

describe('recordKeys', () => {
  it('includes project slug in tracker detail keys', () => {
    expect(recordKeys.detail('task', 'enceladus', 'ENC-TSK-K21')).toEqual([
      'record',
      'task',
      'enceladus',
      'ENC-TSK-K21',
    ])
  })
})

describe('recordLink helpers', () => {
  it('builds project-scoped tracker href', () => {
    expect(recordHref('enceladus', 'task', 'ENC-TSK-K21')).toBe(
      '/enceladus/task/ENC-TSK-K21',
    )
  })

  it('builds document href without project', () => {
    expect(documentHref('DOC-12A69AF1D3BE')).toBe('/document/DOC-12A69AF1D3BE')
  })
})
