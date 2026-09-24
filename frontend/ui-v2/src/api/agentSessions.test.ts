import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AgentSessionsFetchError,
  fetchAgentSessions,
  fetchAgentTypes,
} from './agentSessions'
import { SessionExpiredError } from './client'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('fetchAgentSessions', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('requests the coordination-api sessions route with agent_type_id + status', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        sessions: [
          {
            session_id: 'ENC-SES-001',
            agent_type_id: 'claude-code',
            runtime: 'claude-code-cli',
            created_at: '2026-07-01T00:00:00Z',
            claimed_at: '2026-07-01T00:01:00Z',
            status: 'claimed',
          },
        ],
        count: 1,
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const sessions = await fetchAgentSessions('claude-code')

    expect(sessions).toHaveLength(1)
    expect(sessions[0].session_id).toBe('ENC-SES-001')
    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toContain('/coordination/agents/sessions?')
    expect(url).toContain('agent_type_id=claude-code')
    expect(url).toContain('status=claimed')
  })

  it('defaults to status=claimed when no status is passed', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ sessions: [], count: 0 }))
    vi.stubGlobal('fetch', fetchMock)

    await fetchAgentSessions('claude-code')

    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toContain('status=claimed')
  })

  it('returns an empty array when the response omits sessions', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ count: 0 })))
    const sessions = await fetchAgentSessions('claude-code')
    expect(sessions).toEqual([])
  })

  it('throws SessionExpiredError on 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({}, 401)))
    await expect(fetchAgentSessions('claude-code')).rejects.toBeInstanceOf(SessionExpiredError)
  })

  it('throws AgentSessionsFetchError on other non-ok statuses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({}, 500)))
    await expect(fetchAgentSessions('claude-code')).rejects.toBeInstanceOf(
      AgentSessionsFetchError,
    )
  })
})

describe('fetchAgentTypes', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('requests the coordination-api types route with status=active by default', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        agent_types: [
          {
            agent_type_id: 'claude-code',
            surface: 'terminal',
            model: 'claude-sonnet-5',
            cost_tier: 'standard',
            status: 'active',
            usage_count: 42,
          },
        ],
        count: 1,
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const types = await fetchAgentTypes()

    expect(types).toHaveLength(1)
    expect(types[0].agent_type_id).toBe('claude-code')
    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toContain('/coordination/agents/types?')
    expect(url).toContain('status=active')
  })

  it('returns an empty array when the response omits agent_types', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ count: 0 })))
    const types = await fetchAgentTypes()
    expect(types).toEqual([])
  })
})
