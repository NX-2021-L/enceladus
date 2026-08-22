import { describe, expect, it } from 'vitest'
import type { EscalationItem, EscalationsFeed } from '../api/escalations'
import { EscalationDecisionError } from '../api/escalations'
import {
  bucketForStatus,
  countByBucket,
  describeDecisionError,
  describeDecisionResult,
  filterRows,
  formatAge,
  summarizeMutation,
  toEscalationRow,
  toEscalationRows,
} from './escalationRows'

const NOW = new Date('2026-08-22T12:00:00Z')

function item(overrides: Partial<EscalationItem> = {}): EscalationItem {
  return {
    item_id: 'ENC-ESC-090',
    project_id: 'enceladus',
    status: 'requested',
    mutation_type: 'deploy_arc_change',
    target_record_id: 'ENC-TSK-O12',
    justification: 'Arc is structurally unsatisfiable',
    payload: { target_status: 'closed', provider: 'ENC-SES-0EV' },
    requested_by: { session_id: 'ENC-SES-0EV', agent_type_id: 'ENC-AGT-006' },
    created_at: '2026-08-22T11:30:00Z',
    ...overrides,
  }
}

describe('bucketForStatus', () => {
  it('maps the backend vocabulary onto io-facing buckets', () => {
    expect(bucketForStatus('requested')).toBe('pending')
    expect(bucketForStatus('approved')).toBe('approved')
    expect(bucketForStatus('applied')).toBe('approved')
    expect(bucketForStatus('denied')).toBe('denied')
    expect(bucketForStatus('denied_with_guidance')).toBe('denied')
  })

  it('never lets an unrecognized status masquerade as pending', () => {
    // A status the cockpit does not know must not acquire decision controls —
    // the backend would 409 and io would be offered an action that cannot work.
    expect(bucketForStatus('some_future_status')).toBe('all')
    expect(bucketForStatus('')).toBe('all')
    expect(toEscalationRow(item({ status: 'some_future_status' })).decidable).toBe(false)
  })

  it('is case- and whitespace-insensitive', () => {
    expect(bucketForStatus('  REQUESTED ')).toBe('pending')
  })
})

describe('summarizeMutation', () => {
  it('renders a status transition with its current value when the diff carries one', () => {
    expect(
      summarizeMutation(
        item({ diff: { target_snapshot: { status: 'deploy-success' } } }),
      ),
    ).toBe('status: deploy-success → closed')
  })

  it('renders a bare target_status when no snapshot is available', () => {
    expect(summarizeMutation(item({ diff: undefined }))).toBe('status → closed')
  })

  it('falls back to field → value for a direct field override', () => {
    expect(
      summarizeMutation(
        item({
          payload: { field: 'priority', value: 'P0' },
          diff: { field: 'priority', requested: 'P0' },
        }),
      ),
    ).toBe('priority → P0')
  })

  it('summarizes a multi-field change and truncates past two fields', () => {
    expect(
      summarizeMutation(
        item({
          payload: {},
          diff: {
            field_values: {
              status: { current: 'a', requested: 'b' },
              priority: { current: 'P1', requested: 'P0' },
              components: { current: [], requested: ['frontend'] },
            },
          },
        }),
      ),
    ).toBe('status, priority +1 more')
  })

  it('never returns blank — an untriageable row is worse than a coarse one', () => {
    expect(summarizeMutation(item({ payload: {}, diff: undefined }))).toBe('deploy_arc_change')
    expect(summarizeMutation(item({ payload: {}, diff: undefined, mutation_type: '' }))).toBe('—')
  })

  it('serializes a non-scalar requested value rather than rendering [object Object]', () => {
    expect(
      summarizeMutation(
        item({ payload: {}, diff: { field: 'components', requested: ['frontend'] } }),
      ),
    ).toBe('components → ["frontend"]')
  })
})

describe('formatAge', () => {
  it('scales the unit with the elapsed time', () => {
    expect(formatAge('2026-08-22T11:59:30Z', NOW)).toBe('30s')
    expect(formatAge('2026-08-22T11:30:00Z', NOW)).toBe('30m')
    expect(formatAge('2026-08-22T04:00:00Z', NOW)).toBe('8h')
    expect(formatAge('2026-08-19T12:00:00Z', NOW)).toBe('3d')
  })

  it('clamps a future timestamp to zero rather than rendering a negative age', () => {
    expect(formatAge('2026-08-22T12:05:00Z', NOW)).toBe('0s')
  })

  it('degrades to an em dash on an unparseable timestamp', () => {
    expect(formatAge('not-a-date', NOW)).toBe('—')
    expect(formatAge('', NOW)).toBe('—')
  })
})

describe('toEscalationRows', () => {
  const feed: EscalationsFeed = {
    success: true,
    project_id: 'enceladus',
    count: 3,
    pending: [item({ item_id: 'ENC-ESC-092' })],
    terminal: [
      item({ item_id: 'ENC-ESC-091', status: 'applied' }),
      item({ item_id: 'ENC-ESC-003', status: 'denied_with_guidance' }),
    ],
  }

  it('flattens pending first, since it is the only actionable bucket', () => {
    expect(toEscalationRows(feed, NOW).map((r) => r.id)).toEqual([
      'ENC-ESC-092',
      'ENC-ESC-091',
      'ENC-ESC-003',
    ])
  })

  it('marks only pending rows decidable', () => {
    expect(toEscalationRows(feed, NOW).map((r) => r.decidable)).toEqual([true, false, false])
  })

  it('returns an empty list rather than throwing when the feed has not loaded', () => {
    expect(toEscalationRows(undefined)).toEqual([])
  })

  it('counts buckets independently of the active filter', () => {
    const rows = toEscalationRows(feed, NOW)
    expect(countByBucket(rows)).toEqual({ pending: 1, approved: 1, denied: 1, all: 3 })
    expect(filterRows(rows, 'denied').map((r) => r.id)).toEqual(['ENC-ESC-003'])
    expect(filterRows(rows, 'all')).toHaveLength(3)
  })

  it('surfaces drift so approving against a moved record is a visible choice', () => {
    const row = toEscalationRow(
      item({ diff: { drift: { detected: true, expected_version: '4' } } }),
      NOW,
    )
    expect(row.driftDetected).toBe(true)
    expect(toEscalationRow(item(), NOW).driftDetected).toBe(false)
  })
})

describe('describeDecisionError', () => {
  it('explains a 403 as the non-delegable boundary, keeping the server message', () => {
    const described = describeDecisionError(
      new EscalationDecisionError(403, 'Escalation approval/denial requires an interactive human Cognito ID token.'),
    )
    expect(described.type).toBe('error')
    expect(described.detail).toContain('interactive human Cognito ID token')
    expect(described.hint).toContain('cannot')
  })

  it('treats a 409 as a warning, not a failure — the queue simply moved on', () => {
    const described = describeDecisionError(
      new EscalationDecisionError(409, "Escalation is 'approved'; only 'requested' escalations can be decided."),
    )
    expect(described.type).toBe('warning')
    expect(described.header).toBe('Already decided')
  })

  it('falls back cleanly for a non-Error rejection', () => {
    expect(describeDecisionError('boom').detail).toBe('boom')
  })
})

describe('describeDecisionResult', () => {
  it('reports a clean approve+apply as success', () => {
    const described = describeDecisionResult({
      escalation_id: 'ENC-ESC-092',
      status: 'applied',
      applied: true,
    })
    expect(described.type).toBe('success')
    expect(described.detail).toContain('applied to the target record')
  })

  it('WARNS when the approval is durable but the mutation did not apply', () => {
    // The dangerous case: a green "approved" toast would tell io the mutation
    // landed when it did not. This must read as unfinished work.
    const described = describeDecisionResult({
      escalation_id: 'ENC-ESC-092',
      status: 'approved',
      applied: false,
      apply_error: 'tracker mutation returned 500.',
      retry: 'POST /api/v1/tracker/enceladus/escalation/ENC-ESC-092/apply',
    })
    expect(described.type).toBe('warning')
    expect(described.header).toContain('did not apply')
    expect(described.detail).toContain('/apply')
  })

  it('distinguishes deny from deny-with-guidance and echoes the note', () => {
    expect(describeDecisionResult({ escalation_id: 'E1', status: 'denied' }).header).toBe(
      'E1 denied',
    )
    const guided = describeDecisionResult({
      escalation_id: 'E1',
      status: 'denied_with_guidance',
      guidance_note: 'Re-file against the gamma record.',
    })
    expect(guided.header).toBe('E1 denied with guidance')
    expect(guided.detail).toContain('Re-file against the gamma record.')
  })
})
