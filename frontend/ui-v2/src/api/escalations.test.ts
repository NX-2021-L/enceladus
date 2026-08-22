/**
 * Escalations transport contract (ENC-TSK-O40).
 *
 * These assertions guard the non-delegable approval boundary at the only layer
 * this repo can guard it from: the request this client is willing to make, and
 * what it does with the server's refusal. The decision itself is structurally
 * io's — no agent can satisfy the backend's human-Cognito gates — so what is
 * testable here is that the client sends the browser's own session and never
 * invents an alternative credential path.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from './client'
import {
  approveEscalation,
  denyEscalation,
  EscalationDecisionError,
  fetchEscalationsFeed,
} from './escalations'

const originalFetch = globalThis.fetch

function mockFetch(response: {
  status?: number
  body?: unknown
  ok?: boolean
}) {
  const status = response.status ?? 200
  const spy = vi.fn().mockResolvedValue({
    ok: response.ok ?? (status >= 200 && status < 300),
    status,
    json: async () => response.body ?? {},
  } as Response)
  globalThis.fetch = spy as unknown as typeof fetch
  return spy
}

beforeEach(() => {
  vi.restoreAllMocks()
})

afterEach(() => {
  globalThis.fetch = originalFetch
})

describe('fetchEscalationsFeed', () => {
  it('sends the browser Cognito session and never a bearer/agent credential', async () => {
    const spy = mockFetch({ body: { success: true, project_id: 'enceladus', pending: [], terminal: [], count: 0 } })
    await fetchEscalationsFeed('enceladus')

    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/coordination/escalations?project_id=enceladus')
    expect(init.credentials).toBe('include')
    // The boundary: no Authorization header, no internal key, no SCI. If one of
    // these ever appears here, an agent path has been opened into a decision
    // surface that is required to have none.
    const headers = init.headers as Record<string, string>
    expect(Object.keys(headers).map((k) => k.toLowerCase())).not.toContain('authorization')
    expect(JSON.stringify(headers).toLowerCase()).not.toContain('api-key')
    expect(JSON.stringify(headers).toLowerCase()).not.toContain('sci')
  })

  it('normalizes a partial body so a missing bucket cannot crash the queue', async () => {
    mockFetch({ body: { success: true } })
    const feed = await fetchEscalationsFeed('enceladus')
    expect(feed).toEqual({
      success: true,
      project_id: 'enceladus',
      pending: [],
      terminal: [],
      count: 0,
    })
  })

  it('derives count from the buckets when the server omits it', async () => {
    mockFetch({
      body: {
        pending: [{ item_id: 'E1', status: 'requested', created_at: '' }],
        terminal: [{ item_id: 'E2', status: 'denied', created_at: '' }],
      },
    })
    expect((await fetchEscalationsFeed('enceladus')).count).toBe(2)
  })

  it('raises SessionExpiredError on 401 so the shell can re-authenticate', async () => {
    mockFetch({ status: 401 })
    await expect(fetchEscalationsFeed('enceladus')).rejects.toBeInstanceOf(SessionExpiredError)
  })
})

describe('approveEscalation', () => {
  it('POSTs to the approve route with the session cookie and an empty body', async () => {
    const spy = mockFetch({ body: { success: true, escalation_id: 'ENC-ESC-092', status: 'applied' } })
    const result = await approveEscalation('enceladus', 'ENC-ESC-092')

    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/coordination/escalations/enceladus/ENC-ESC-092/approve')
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('include')
    expect(JSON.parse(init.body as string)).toEqual({})
    expect(result.status).toBe('applied')
  })

  it('preserves apply_error and retry so a durable-but-unapplied approval is visible', async () => {
    mockFetch({
      body: {
        success: true,
        escalation_id: 'ENC-ESC-092',
        status: 'approved',
        applied: false,
        apply_error: 'tracker mutation returned 500.',
        retry: 'POST /api/v1/tracker/enceladus/escalation/ENC-ESC-092/apply',
      },
    })
    const result = await approveEscalation('enceladus', 'ENC-ESC-092')
    expect(result.applied).toBe(false)
    expect(result.apply_error).toContain('500')
    expect(result.retry).toContain('/apply')
  })

  it('surfaces a 403 from the human-principal gate verbatim, flagged forbidden', async () => {
    mockFetch({
      status: 403,
      body: {
        error:
          'Escalation approval/denial requires an interactive human Cognito ID token. ' +
          'Machine principals are structurally rejected.',
      },
    })
    await expect(approveEscalation('enceladus', 'E1')).rejects.toMatchObject({
      name: 'EscalationDecisionError',
      status: 403,
      forbidden: true,
      conflict: false,
    })
    // The server's own wording must reach io — a generic "failed" would hide
    // WHICH of the three gates refused.
    await expect(approveEscalation('enceladus', 'E1')).rejects.toThrow(/interactive human Cognito/)
  })

  it('flags a 409 as a conflict rather than a hard failure', async () => {
    mockFetch({ status: 409, body: { error: "Escalation E1 is 'approved'; only 'requested' can be decided." } })
    const error = await approveEscalation('enceladus', 'E1').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(EscalationDecisionError)
    expect((error as EscalationDecisionError).conflict).toBe(true)
    expect((error as EscalationDecisionError).forbidden).toBe(false)
  })

  it('still raises a typed error when the body is not JSON', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => {
        throw new SyntaxError('not json')
      },
    } as unknown as Response) as unknown as typeof fetch
    await expect(approveEscalation('enceladus', 'E1')).rejects.toThrow(/failed \(500\)/)
  })
})

describe('denyEscalation', () => {
  it('sends guidance_note when a note is supplied — the denied_with_guidance path', async () => {
    const spy = mockFetch({
      body: { success: true, escalation_id: 'E1', status: 'denied_with_guidance', guidance_note: 'Re-file on gamma.' },
    })
    const result = await denyEscalation('enceladus', 'E1', 'Re-file on gamma.')

    const [url, init] = spy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/coordination/escalations/enceladus/E1/deny')
    expect(JSON.parse(init.body as string)).toEqual({ guidance_note: 'Re-file on gamma.' })
    expect(result.status).toBe('denied_with_guidance')
  })

  it('omits guidance_note entirely for a bare deny', async () => {
    const spy = mockFetch({ body: { success: true, escalation_id: 'E1', status: 'denied' } })
    await denyEscalation('enceladus', 'E1')
    expect(JSON.parse((spy.mock.calls[0][1] as RequestInit).body as string)).toEqual({})
  })

  it('treats a whitespace-only note as no note, so it cannot fake denied_with_guidance', async () => {
    const spy = mockFetch({ body: { success: true, escalation_id: 'E1', status: 'denied' } })
    await denyEscalation('enceladus', 'E1', '   \n  ')
    expect(JSON.parse((spy.mock.calls[0][1] as RequestInit).body as string)).toEqual({})
  })

  it('trims a note before sending it', async () => {
    const spy = mockFetch({ body: { success: true, escalation_id: 'E1', status: 'denied_with_guidance' } })
    await denyEscalation('enceladus', 'E1', '  use the gamma record  ')
    expect(JSON.parse((spy.mock.calls[0][1] as RequestInit).body as string)).toEqual({
      guidance_note: 'use the gamma record',
    })
  })
})
