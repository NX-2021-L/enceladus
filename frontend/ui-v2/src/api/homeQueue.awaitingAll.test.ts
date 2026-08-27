/**
 * ENC-TSK-P59 (ENC-ISS-725) — cross-project awaiting-checkout count.
 * The Home tile summed exactly one project before (whichever sorted first in
 * the registry); these pin the fan-out sum and the failed-project-counts-0
 * behaviour so one broken project cannot blank the tile.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fetchAwaitingCheckoutCountAll } from './homeQueue'

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

describe('fetchAwaitingCheckoutCountAll (ENC-TSK-P59)', () => {
  it('sums not-checked-out open tasks across every project', async () => {
    vi.stubGlobal(
      'fetch',
      fetchResponder({
        enceladus: {
          success: true,
          records: [
            { checkout_state: 'checked_out' },
            { checkout_state: '' },
            {},
          ],
          count: 3,
        },
        devops: { success: true, records: [{ checkout_state: 'checked_in' }], count: 1 },
      }),
    )
    await expect(fetchAwaitingCheckoutCountAll(['enceladus', 'devops'])).resolves.toBe(3)
  })

  it('counts a failing project as 0 instead of failing the whole tile', async () => {
    vi.stubGlobal(
      'fetch',
      fetchResponder({
        enceladus: { success: true, records: [{ checkout_state: '' }], count: 1 },
        // 'broken' project has no responder entry -> 500
      }),
    )
    await expect(fetchAwaitingCheckoutCountAll(['enceladus', 'broken'])).resolves.toBe(1)
  })

  it('returns 0 for an empty project list', async () => {
    vi.stubGlobal('fetch', fetchResponder({}))
    await expect(fetchAwaitingCheckoutCountAll([])).resolves.toBe(0)
  })
})
