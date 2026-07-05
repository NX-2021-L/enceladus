import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { NotFoundError, SessionExpiredError } from './client'
import { fetchSessionRecord, sessionHref, sessionKeys, sessionQueryOptions } from './sessions'

describe('sessionKeys', () => {
  it('is namespaced separately from tracker recordKeys', () => {
    expect(sessionKeys.detail('ENC-SES-0A1')).toEqual(['session', 'ENC-SES-0A1'])
  })
})

describe('sessionHref', () => {
  it('builds a project-free session detail path', () => {
    expect(sessionHref('ENC-SES-0A1')).toBe('/session/ENC-SES-0A1')
  })

  it('encodes the session id', () => {
    expect(sessionHref('ENC-SES/weird')).toBe('/session/ENC-SES%2Fweird')
  })
})

describe('sessionQueryOptions', () => {
  it('produces a stable query key scoped to the session id', () => {
    const options = sessionQueryOptions('ENC-SES-0A1')
    expect(options.queryKey).toEqual(['session', 'ENC-SES-0A1'])
  })
})

describe('fetchSessionRecord', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    global.fetch = vi.fn() as unknown as typeof fetch
  })

  afterEach(() => {
    global.fetch = originalFetch
  })

  it('unwraps the { session } envelope', async () => {
    vi.mocked(global.fetch).mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        session: {
          session_id: 'ENC-SES-0A1',
          agent_type_id: 'ENC-AGT-001',
          status: 'claimed',
        },
      }),
    } as Response)

    const session = await fetchSessionRecord('ENC-SES-0A1')
    expect(session.session_id).toBe('ENC-SES-0A1')
    expect(session.status).toBe('claimed')
  })

  it('requests with credentials include and no-store cache', async () => {
    vi.mocked(global.fetch).mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({ session: { session_id: 'ENC-SES-0A1' } }),
    } as Response)

    await fetchSessionRecord('ENC-SES-0A1')
    const [, init] = vi.mocked(global.fetch).mock.calls[0]
    expect(init).toMatchObject({ credentials: 'include', cache: 'no-store' })
  })

  it('throws SessionExpiredError on 401', async () => {
    vi.mocked(global.fetch).mockResolvedValue({ status: 401, ok: false } as Response)
    await expect(fetchSessionRecord('ENC-SES-0A1')).rejects.toBeInstanceOf(SessionExpiredError)
  })

  it('throws NotFoundError on 404', async () => {
    vi.mocked(global.fetch).mockResolvedValue({ status: 404, ok: false } as Response)
    await expect(fetchSessionRecord('ENC-SES-ZZZ')).rejects.toBeInstanceOf(NotFoundError)
  })

  it('throws a generic error on other non-ok statuses', async () => {
    vi.mocked(global.fetch).mockResolvedValue({ status: 500, ok: false } as Response)
    await expect(fetchSessionRecord('ENC-SES-0A1')).rejects.toThrow(/Request failed \(500\)/)
  })
})
