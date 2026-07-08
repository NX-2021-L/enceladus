import { describe, expect, it } from 'vitest'
import { pausedApprovalRows, pendingEscalationRows, staleLockRows } from './homeQueue'
import type { EscalationRecord } from '../api/coordination'
import type { PausedApprovalRun, StaleLockEntry } from '../api/homeQueue'

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

describe('pausedApprovalRows', () => {
  it('titles by requesting workflow when present, falls back to the run id', () => {
    const withWorkflow = pausedApprovalRows([
      { id: 42, requesting_workflow: 'promote-gamma-to-prod-request', run_url: 'https://github.com/x/y/actions/runs/42' } as PausedApprovalRun,
    ])
    expect(withWorkflow[0]?.title).toBe('promote-gamma-to-prod-request awaiting v3-prod approval')
    expect(withWorkflow[0]?.href).toBe('https://github.com/x/y/actions/runs/42')

    const withoutWorkflow = pausedApprovalRows([{ id: 7 } as PausedApprovalRun])
    expect(withoutWorkflow[0]?.title).toBe('Run 7 awaiting v3-prod approval')
  })

  it('handles an empty list', () => {
    expect(pausedApprovalRows([])).toEqual([])
  })
})

describe('staleLockRows', () => {
  it('surfaces record id, holder session, and age', () => {
    const rows = staleLockRows([
      { record_id: 'ENC-TSK-K01', holder_session: 'ENC-SES-057', age_minutes: 312 } as StaleLockEntry,
    ])
    expect(rows[0]?.id).toBe('stale-lock-ENC-TSK-K01')
    expect(rows[0]?.title).toBe('ENC-TSK-K01 checkout is stale')
    expect(rows[0]?.description).toBe('Held by ENC-SES-057 — 312m')
  })

  it('handles an empty list', () => {
    expect(staleLockRows([])).toEqual([])
  })
})
