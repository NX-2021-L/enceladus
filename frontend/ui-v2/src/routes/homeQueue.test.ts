import { describe, expect, it } from 'vitest'
import { GAP_QUEUE_ROWS, pendingEscalationRows } from './homeQueue'
import type { EscalationRecord } from '../api/coordination'

function escalation(overrides: Partial<EscalationRecord>): EscalationRecord {
  return {
    item_id: 'ENC-ESC-001',
    status: 'requested',
    created_at: '2026-07-01T00:00:00Z',
    ...overrides,
  }
}

describe('pendingEscalationRows', () => {
  it('keeps only status=requested rows', () => {
    const rows = pendingEscalationRows([
      escalation({ item_id: 'ENC-ESC-001', status: 'requested' }),
      escalation({ item_id: 'ENC-ESC-002', status: 'approved' }),
      escalation({ item_id: 'ENC-ESC-003', status: 'denied' }),
    ])
    expect(rows).toHaveLength(1)
    expect(rows[0]?.id).toBe('ENC-ESC-001')
  })

  it('links every row to the coordination escalations tab', () => {
    const rows = pendingEscalationRows([escalation({})])
    expect(rows[0]?.href).toBe('/coordination?tab=escalations')
  })

  it('titles by target record when present, falls back to the escalation id', () => {
    const withTarget = pendingEscalationRows([
      escalation({ item_id: 'ENC-ESC-001', target_record_id: 'ENC-TSK-K01' }),
    ])
    expect(withTarget[0]?.title).toBe('Unblock ENC-TSK-K01')

    const withoutTarget = pendingEscalationRows([escalation({ item_id: 'ENC-ESC-002', target_record_id: undefined })])
    expect(withoutTarget[0]?.title).toBe('Review ENC-ESC-002')
  })

  it('handles an empty list', () => {
    expect(pendingEscalationRows([])).toEqual([])
  })
})

describe('GAP_QUEUE_ROWS', () => {
  it('are all marked gap:true and never carry an href', () => {
    for (const row of GAP_QUEUE_ROWS) {
      expect(row.gap).toBe(true)
      expect(row.href).toBeUndefined()
    }
  })

  it('covers paused prod runs and stale-lock/backfill flags', () => {
    const ids = GAP_QUEUE_ROWS.map((row) => row.id)
    expect(ids).toEqual(['gap-paused-prod', 'gap-stale-lock'])
  })
})
