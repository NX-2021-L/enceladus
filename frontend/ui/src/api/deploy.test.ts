/**
 * deploy.test.ts — Regression tests for the `decision#` prefix strip in
 * fetchDeployQueue (ENC-ISS-208 / ENC-TSK-D51, verified by ENC-TSK-E76).
 *
 * The DynamoDB composite key separator `#` in DPL record_id values
 * (decision#ENC-DPL-N) leaks into PWA form input validation if not stripped
 * before the data reaches UI components. The fetchDeployQueue response
 * transformer must strip the prefix on every decision.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchDeployQueue } from './deploy'

describe('fetchDeployQueue record_id normalization', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function respondWith(decisions: Array<{ record_id: string }>): void {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          success: true,
          project_id: 'enceladus',
          count: decisions.length,
          decisions,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
  }

  it('strips the decision# prefix from composite-key record_id values', async () => {
    respondWith([{ record_id: 'decision#ENC-DPL-42' }])
    const data = await fetchDeployQueue('enceladus')
    expect(data.decisions[0].record_id).toBe('ENC-DPL-42')
  })

  it('passes through record_id values that have no decision# prefix', async () => {
    respondWith([{ record_id: 'ENC-DPL-7' }])
    const data = await fetchDeployQueue('enceladus')
    expect(data.decisions[0].record_id).toBe('ENC-DPL-7')
  })

  it('only strips the leading prefix, preserving any embedded # characters', async () => {
    respondWith([{ record_id: 'decision#ENC-DPL-9#extra' }])
    const data = await fetchDeployQueue('enceladus')
    expect(data.decisions[0].record_id).toBe('ENC-DPL-9#extra')
  })
})
