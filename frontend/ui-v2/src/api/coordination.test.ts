import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  fetchAgentSessions,
  fetchAgentTypes,
  fetchCoordinationRequests,
  fetchEscalations,
  fetchLessons,
} from './coordination'

function mockFetchOnce(body: unknown, status = 200) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

/** Distinct response per call, in order -- for pagination tests where
 * successive fetches must return different pages. */
function mockFetchSequence(bodies: unknown[]) {
  const fetchMock = vi.fn()
  for (const body of bodies) {
    fetchMock.mockImplementationOnce(async () => ({
      ok: true,
      status: 200,
      json: async () => body,
    }))
  }
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('fetchCoordinationRequests', () => {
  it('hits /coordination/monitor and unwraps requests[]', async () => {
    const fetchMock = mockFetchOnce({
      success: true,
      generated_at: '2026-07-05T00:00:00Z',
      requests: [{ request_id: 'req-1' }],
      count: 1,
    })
    const result = await fetchCoordinationRequests()
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/coordination/monitor'),
      expect.objectContaining({ credentials: 'include' }),
    )
    expect(result).toEqual([{ request_id: 'req-1' }])
  })
})

describe('fetchAgentSessions', () => {
  it('builds agent_type_id + status query params and unwraps sessions[]', async () => {
    const fetchMock = mockFetchOnce({ sessions: [{ session_id: 'ENC-SES-001' }], count: 1 })
    const result = await fetchAgentSessions({ agentTypeId: 'ENC-AGT-001', status: 'claimed' })
    const calledUrl = fetchMock.mock.calls[0]![0] as string
    expect(calledUrl).toContain('/coordination/agents/sessions?')
    expect(calledUrl).toContain('agent_type_id=ENC-AGT-001')
    expect(calledUrl).toContain('status=claimed')
    expect(result).toEqual([{ session_id: 'ENC-SES-001' }])
  })

  it('omits query params when no filter is given', async () => {
    const fetchMock = mockFetchOnce({ sessions: [], count: 0 })
    await fetchAgentSessions()
    const calledUrl = fetchMock.mock.calls[0]![0] as string
    expect(calledUrl.endsWith('/coordination/agents/sessions')).toBe(true)
  })

  it('returns [] when the response has no sessions key', async () => {
    mockFetchOnce({ count: 0 })
    const result = await fetchAgentSessions()
    expect(result).toEqual([])
  })
})

describe('fetchAgentTypes', () => {
  it('unwraps agent_types[]', async () => {
    mockFetchOnce({ agent_types: [{ agent_type_id: 'ENC-AGT-001' }], count: 1 })
    const result = await fetchAgentTypes('active')
    expect(result).toEqual([{ agent_type_id: 'ENC-AGT-001' }])
  })
})

describe('fetchLessons', () => {
  it('queries the generic tracker list route with type=lesson (existing behaviour, green)', async () => {
    const fetchMock = mockFetchOnce({ success: true, records: [{ item_id: 'ENC-LSN-001' }], count: 1 })
    const result = await fetchLessons('enceladus')
    const calledUrl = fetchMock.mock.calls[0]![0] as string
    expect(calledUrl).toContain('/tracker/enceladus?type=lesson')
    expect(result).toEqual({ records: [{ item_id: 'ENC-LSN-001' }], truncated: false })
  })

  // ENC-TSK-Q17-0D: honour the O1.2 honest-cursors contract.
  it('surfaces page_truncated as truncated: true', async () => {
    mockFetchOnce({
      success: true,
      records: [{ item_id: 'ENC-LSN-001' }],
      count: 1,
      page_truncated: true,
    })
    const result = await fetchLessons('enceladus')
    expect(result).toEqual({ records: [{ item_id: 'ENC-LSN-001' }], truncated: true })
  })

  it('follows next_cursor with a follow-up fetch and concatenates records', async () => {
    const fetchMock = mockFetchSequence([
      {
        success: true,
        records: [{ item_id: 'ENC-LSN-001' }],
        count: 1,
        next_cursor: 'cursor-1',
      },
      { success: true, records: [{ item_id: 'ENC-LSN-002' }], count: 1 },
    ])
    const result = await fetchLessons('enceladus')
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const secondUrl = fetchMock.mock.calls[1]![0] as string
    expect(secondUrl).toContain('next_cursor=cursor-1')
    expect(result).toEqual({
      records: [{ item_id: 'ENC-LSN-001' }, { item_id: 'ENC-LSN-002' }],
      truncated: false,
    })
  })

  it('caps pagination at 10 pages and surfaces truncation when next_cursor still remains', async () => {
    const pages = Array.from({ length: 10 }, (_, i) => ({
      success: true,
      records: [{ item_id: `ENC-LSN-${i}` }],
      count: 1,
      next_cursor: `cursor-${i + 1}`,
    }))
    const fetchMock = mockFetchSequence(pages)
    const result = await fetchLessons('enceladus')
    expect(fetchMock).toHaveBeenCalledTimes(10)
    expect(result.records).toHaveLength(10)
    expect(result.truncated).toBe(true)
  })
})

describe('fetchEscalations', () => {
  it('concatenates pending + terminal escalations', async () => {
    mockFetchOnce({
      success: true,
      project_id: 'enceladus',
      pending: [{ item_id: 'escalation#ENC-ESC-001', status: 'requested' }],
      terminal: [{ item_id: 'escalation#ENC-ESC-002', status: 'approved' }],
      count: 2,
    })
    const result = await fetchEscalations('enceladus')
    expect(result.map((r) => r.item_id)).toEqual([
      'escalation#ENC-ESC-001',
      'escalation#ENC-ESC-002',
    ])
  })
})
