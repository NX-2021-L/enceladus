/**
 * ENC-TSK-P59 (ENC-ISS-725) — cross-project awaiting-checkout count.
 * ENC-TSK-Q17-0A — swapped the per-project single-page fetch + client-side
 * checkout_state filter for one bounded `mode=census` call per project.
 * These pin the fan-out sum, the failed-project-counts-0 behaviour (so one
 * broken project cannot blank the tile), and the `truncated` OR-across-
 * projects propagation so a partial census on ANY project marks the whole
 * tile honestly instead of silently under-reporting.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fetchAwaitingCheckoutCount, fetchAwaitingCheckoutCountAll } from './homeQueue'

function fetchResponder(byProject: Record<string, unknown>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const match = url.match(/\/tracker\/([^/?]+)\?/)
    const project = match ? decodeURIComponent(match[1]) : ''
    const body = byProject[project]
    if (body === undefined) {
      return new Response('missing', { status: 500 })
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('fetchAwaitingCheckoutCount (ENC-TSK-Q17-0A)', () => {
  it('calls the tracker route in mode=census with the task/open status filter', async () => {
    const fetchMock = fetchResponder({
      enceladus: { success: true, mode: 'census', count: 7, count_truncated: false },
    })
    vi.stubGlobal('fetch', fetchMock)
    const result = await fetchAwaitingCheckoutCount('enceladus')
    const calledUrl = fetchMock.mock.calls[0]![0] as string
    expect(calledUrl).toContain('/tracker/enceladus?')
    expect(calledUrl).toContain('type=task')
    expect(calledUrl).toContain('status=open')
    expect(calledUrl).toContain('mode=census')
    expect(result).toEqual({ count: 7, truncated: false })
  })

  it('surfaces count_truncated as truncated: true', async () => {
    vi.stubGlobal(
      'fetch',
      fetchResponder({
        enceladus: { success: true, mode: 'census', count: 200, count_truncated: true },
      }),
    )
    const result = await fetchAwaitingCheckoutCount('enceladus')
    expect(result).toEqual({ count: 200, truncated: true })
  })
})

describe('fetchAwaitingCheckoutCountAll (ENC-TSK-P59 / ENC-TSK-Q17-0A)', () => {
  it('sums census counts across every project', async () => {
    vi.stubGlobal(
      'fetch',
      fetchResponder({
        enceladus: { success: true, mode: 'census', count: 3, count_truncated: false },
        devops: { success: true, mode: 'census', count: 1, count_truncated: false },
      }),
    )
    await expect(fetchAwaitingCheckoutCountAll(['enceladus', 'devops'])).resolves.toEqual({
      count: 4,
      truncated: false,
    })
  })

  it('ORs truncated across projects -- one truncated census marks the whole tile', async () => {
    vi.stubGlobal(
      'fetch',
      fetchResponder({
        enceladus: { success: true, mode: 'census', count: 200, count_truncated: true },
        devops: { success: true, mode: 'census', count: 1, count_truncated: false },
      }),
    )
    await expect(fetchAwaitingCheckoutCountAll(['enceladus', 'devops'])).resolves.toEqual({
      count: 201,
      truncated: true,
    })
  })

  it('counts a failing project as 0 (not truncated) instead of failing the whole tile', async () => {
    vi.stubGlobal(
      'fetch',
      fetchResponder({
        enceladus: { success: true, mode: 'census', count: 1, count_truncated: false },
        // 'broken' project has no responder entry -> 500
      }),
    )
    await expect(fetchAwaitingCheckoutCountAll(['enceladus', 'broken'])).resolves.toEqual({
      count: 1,
      truncated: false,
    })
  })

  it('returns a zero, non-truncated count for an empty project list', async () => {
    vi.stubGlobal('fetch', fetchResponder({}))
    await expect(fetchAwaitingCheckoutCountAll([])).resolves.toEqual({
      count: 0,
      truncated: false,
    })
  })
})
