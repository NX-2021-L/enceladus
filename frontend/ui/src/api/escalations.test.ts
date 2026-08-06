/**
 * escalations API tests — ENC-TSK-N81 / ENC-ISS-594.
 *
 * The feed endpoint is single-project by construction (one tracker partition
 * per project_id), so the cross-project inbox is assembled client-side. These
 * tests pin the assembly itself: every project is queried, the pending queues
 * merge newest-first, a failing project is isolated rather than fatal, and
 * items always carry the project_id that decision routing depends on.
 *
 * Mocks: only the ./client network boundary — fetchEscalationsInbox and
 * fetchEscalations run for real.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { EscalationItem } from './escalations'

const { mockFetchWithAuth } = vi.hoisted(() => ({ mockFetchWithAuth: vi.fn() }))

vi.mock('./client', () => ({ fetchWithAuth: mockFetchWithAuth }))

import { fetchEscalations, fetchEscalationsInbox } from './escalations'

function item(overrides: Partial<EscalationItem> = {}): EscalationItem {
  return {
    item_id: 'ENC-ESC-001',
    project_id: 'enceladus',
    status: 'requested',
    mutation_type: 'direct_state_override',
    target_record_id: 'ENC-TSK-001',
    justification: 'because',
    payload: {},
    created_at: '2026-08-06T01:00:00Z',
    updated_at: '2026-08-06T01:00:00Z',
    ...overrides,
  }
}

function ok(pending: EscalationItem[]) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      success: true,
      project_id: pending[0]?.project_id ?? 'enceladus',
      pending,
      terminal: [],
      count: pending.length,
    }),
  }
}

/** Resolve each project_id in the request URL to a canned response. */
function routeByProject(table: Record<string, () => unknown>) {
  return async (url: string) => {
    const projectId = new URL(url, 'https://jreese.net').searchParams.get('project_id') ?? ''
    const handler = table[projectId]
    if (!handler) return ok([])
    return handler()
  }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('fetchEscalations', () => {
  it('passes the status filter through when supplied', async () => {
    mockFetchWithAuth.mockResolvedValue(ok([]))
    await fetchEscalations('intelligence', 'requested')
    const url = String(mockFetchWithAuth.mock.calls[0][0])
    expect(url).toContain('project_id=intelligence')
    expect(url).toContain('status=requested')
  })

  it('omits the status param when not supplied', async () => {
    mockFetchWithAuth.mockResolvedValue(ok([]))
    await fetchEscalations('enceladus')
    expect(String(mockFetchWithAuth.mock.calls[0][0])).not.toContain('status=')
  })

  it('throws on a non-ok response', async () => {
    mockFetchWithAuth.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) })
    await expect(fetchEscalations('enceladus')).rejects.toThrow('500')
  })
})

describe('fetchEscalationsInbox', () => {
  it('queries every project exactly once, filtered to pending', async () => {
    mockFetchWithAuth.mockImplementation(routeByProject({}))
    await fetchEscalationsInbox(['enceladus', 'intelligence', 'devops'])
    expect(mockFetchWithAuth).toHaveBeenCalledTimes(3)
    const urls = mockFetchWithAuth.mock.calls.map((c) => String(c[0]))
    expect(urls.every((u) => u.includes('status=requested'))).toBe(true)
    expect(urls.some((u) => u.includes('project_id=intelligence'))).toBe(true)
  })

  it('merges pending escalations across projects newest-first', async () => {
    mockFetchWithAuth.mockImplementation(
      routeByProject({
        enceladus: () => ok([item({ item_id: 'ENC-ESC-009', created_at: '2026-08-06T02:00:00Z' })]),
        intelligence: () =>
          ok([
            item({
              item_id: 'INT-ESC-001',
              project_id: 'intelligence',
              created_at: '2026-08-06T06:39:41Z',
            }),
          ]),
      }),
    )
    const result = await fetchEscalationsInbox(['enceladus', 'intelligence'])
    expect(result.pending.map((e) => e.item_id)).toEqual(['INT-ESC-001', 'ENC-ESC-009'])
    expect(result.scanned).toEqual(['enceladus', 'intelligence'])
    expect(result.failed).toEqual([])
  })

  it('isolates a failing project instead of rejecting the whole inbox', async () => {
    mockFetchWithAuth.mockImplementation(
      routeByProject({
        enceladus: () => ok([item()]),
        intelligence: () => {
          throw new Error('boom')
        },
      }),
    )
    const result = await fetchEscalationsInbox(['enceladus', 'intelligence'])
    expect(result.pending.map((e) => e.item_id)).toEqual(['ENC-ESC-001'])
    expect(result.failed).toEqual(['intelligence'])
    expect(result.scanned).toEqual(['enceladus'])
  })

  it('reports a non-ok project response as failed, not empty', async () => {
    mockFetchWithAuth.mockImplementation(
      routeByProject({
        intelligence: () => ({ ok: false, status: 403, json: async () => ({}) }),
      }),
    )
    const result = await fetchEscalationsInbox(['intelligence'])
    expect(result.failed).toEqual(['intelligence'])
    expect(result.scanned).toEqual([])
  })

  it('backfills project_id from the queried partition when the item omits it', async () => {
    mockFetchWithAuth.mockImplementation(
      routeByProject({
        intelligence: () =>
          ok([{ ...item({ item_id: 'INT-ESC-002' }), project_id: '' } as EscalationItem]),
      }),
    )
    const result = await fetchEscalationsInbox(['intelligence'])
    expect(result.pending[0].project_id).toBe('intelligence')
  })

  it('bounds concurrency so a large fan-out does not open every request at once', async () => {
    let inFlight = 0
    let peak = 0
    mockFetchWithAuth.mockImplementation(async () => {
      inFlight += 1
      peak = Math.max(peak, inFlight)
      await new Promise((resolve) => setTimeout(resolve, 0))
      inFlight -= 1
      return ok([])
    })
    const projects = Array.from({ length: 25 }, (_, i) => `p${i}`)
    await fetchEscalationsInbox(projects)
    expect(mockFetchWithAuth).toHaveBeenCalledTimes(25)
    expect(peak).toBeLessThanOrEqual(6)
  })

  it('returns an empty inbox for an empty project list without any request', async () => {
    const result = await fetchEscalationsInbox([])
    expect(result).toEqual({ pending: [], scanned: [], failed: [] })
    expect(mockFetchWithAuth).not.toHaveBeenCalled()
  })
})
