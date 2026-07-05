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
  it('queries the generic tracker list route with type=lesson', async () => {
    const fetchMock = mockFetchOnce({ success: true, records: [{ item_id: 'ENC-LSN-001' }], count: 1 })
    const result = await fetchLessons('enceladus')
    const calledUrl = fetchMock.mock.calls[0]![0] as string
    expect(calledUrl).toContain('/tracker/enceladus?type=lesson')
    expect(result).toEqual([{ item_id: 'ENC-LSN-001' }])
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
