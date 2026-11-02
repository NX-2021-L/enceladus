import { describe, expect, it } from 'vitest'
import {
  buildMetadataContract,
  changedEditableFields,
  metadataFieldPolicy,
  metadataInitialValues,
} from './recordMetadataPolicy'

describe('record metadata policy (ENC-TSK-R82-0E)', () => {
  it('excludes lifecycle fields from edit and shows them readonly', () => {
    const p = metadataFieldPolicy('task')
    expect(p('/status')).toBe('readonly')
    expect(p('/transition_type')).toBe('readonly')
    expect(p('/title')).toBe('show')
    expect(p('/unknown')).toBe('hide')
  })

  it('diffs only changed editable fields', () => {
    const rec = { title: 'T', description: 'd', priority: 'P2', assigned_to: null, status: 'open' }
    const init = metadataInitialValues('task', rec)
    const next = { ...init, priority: 'P1', status: 'closed' }
    expect(changedEditableFields('task', init, next)).toEqual([{ field: 'priority', value: 'P1' }])
  })

  it('builds a schema with enum priority and textarea description', () => {
    const c = buildMetadataContract('issue')
    const props = (c.inputSchema as { properties: Record<string, Record<string, unknown>> }).properties
    expect(props.priority.enum).toEqual(['P0', 'P1', 'P2', 'P3'])
    expect(props.severity.enum).toContain('critical')
    expect(props.description['x-io-widget']).toBe('textarea')
  })
})
