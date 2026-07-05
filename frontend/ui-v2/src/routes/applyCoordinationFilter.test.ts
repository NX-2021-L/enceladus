import { describe, expect, it } from 'vitest'
import { applyTokens } from './applyCoordinationFilter'

interface Row {
  id: string
  status: string
  agent_type_id?: string
}

const rows: Row[] = [
  { id: 'a', status: 'claimed', agent_type_id: 'ENC-AGT-001' },
  { id: 'b', status: 'retired', agent_type_id: 'ENC-AGT-002' },
  { id: 'c', status: 'claimed', agent_type_id: 'ENC-AGT-002' },
]

describe('applyTokens', () => {
  it('returns all rows when there are no tokens', () => {
    expect(applyTokens(rows, { tokens: [], operation: 'and' })).toEqual(rows)
  })

  it('filters by a single field:value token (case-insensitive substring)', () => {
    const result = applyTokens(rows, {
      tokens: [{ propertyKey: 'status', operator: ':', value: 'Claimed' }],
      operation: 'and',
    })
    expect(result.map((r) => r.id)).toEqual(['a', 'c'])
  })

  it('ANDs multiple tokens by default', () => {
    const result = applyTokens(rows, {
      tokens: [
        { propertyKey: 'status', operator: ':', value: 'claimed' },
        { propertyKey: 'agent_type_id', operator: ':', value: 'ENC-AGT-002' },
      ],
      operation: 'and',
    })
    expect(result.map((r) => r.id)).toEqual(['c'])
  })

  it('ORs multiple tokens when operation is or', () => {
    const result = applyTokens(rows, {
      tokens: [
        { propertyKey: 'status', operator: ':', value: 'retired' },
        { propertyKey: 'agent_type_id', operator: ':', value: 'ENC-AGT-001' },
      ],
      operation: 'or',
    })
    expect(result.map((r) => r.id)).toEqual(['a', 'b'])
  })

  it('treats a missing field as empty string (no match)', () => {
    const result = applyTokens(rows, {
      tokens: [{ propertyKey: 'nonexistent', operator: ':', value: 'x' }],
      operation: 'and',
    })
    expect(result).toEqual([])
  })
})
