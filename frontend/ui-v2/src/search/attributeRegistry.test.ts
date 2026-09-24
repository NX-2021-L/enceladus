import { describe, expect, it } from 'vitest'
import {
  buildAttributeRegistry,
  fieldValueForProperty,
  suggestPropertyKeys,
  suggestPropertyValues,
} from './attributeRegistry'
import type { LocalSearchRecord } from '../types/search'

const CORPUS: LocalSearchRecord[] = [
  {
    recordId: 'ENC-TSK-L19',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Feed search wave A',
    status: 'in-progress',
  },
  {
    recordId: 'ENC-ISS-058',
    recordType: 'issue',
    projectId: 'enceladus',
    title: 'Sample issue',
    status: 'open',
  },
  {
    recordId: 'ENC-TSK-M40',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Open P0 task',
    status: 'open',
    priority: 'P0',
    checkoutState: 'checked_out',
  },
]

describe('attributeRegistry', () => {
  it('includes governance properties and observed keys', () => {
    const props = buildAttributeRegistry(CORPUS)
    expect(props.some((p) => p.key === 'status')).toBe(true)
    expect(props.some((p) => p.key === 'record_type')).toBe(true)
  })

  it('suggests status from sta prefix within bounded set', () => {
    const props = buildAttributeRegistry(CORPUS)
    const keys = suggestPropertyKeys('sta', props).map((p) => p.key)
    expect(keys).toContain('status')
  })

  it('suggests observed status values', () => {
    const values = suggestPropertyValues('status', 'in', CORPUS)
    expect(values).toContain('in-progress')
  })

  it('resolves hit fields for filter matching', () => {
    expect(fieldValueForProperty(CORPUS[0], 'status')).toBe('in-progress')
    expect(fieldValueForProperty(CORPUS[0], 'record_id')).toBe('ENC-TSK-L19')
  })

  it('registers priority and checkout_state as filterable properties (ENC-FTR-130 Band-B)', () => {
    const props = buildAttributeRegistry(CORPUS)
    expect(props.some((p) => p.key === 'priority')).toBe(true)
    expect(props.some((p) => p.key === 'checkout_state')).toBe(true)
  })

  it('resolves priority and checkout_state hit fields for filter matching', () => {
    expect(fieldValueForProperty(CORPUS[2], 'priority')).toBe('P0')
    expect(fieldValueForProperty(CORPUS[2], 'checkout_state')).toBe('checked_out')
  })
})
