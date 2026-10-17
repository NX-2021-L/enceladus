import { afterEach, describe, expect, it, vi } from 'vitest'
import { APP_REFRESH_URL } from '../api/appRefresh'

/**
 * DVP-TSK-B42 / ENC-TSK-R01. "App refresh" delegates to @io-kit/shell refreshApp (whose own tests cover
 * step order, timeouts, failure fall-through and the final reload); this pins the Enceladus wiring.
 */
const kitRefreshApp = vi.hoisted(() => vi.fn(async () => undefined))
vi.mock('@io-kit/shell', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@io-kit/shell')>()),
  refreshApp: kitRefreshApp,
}))

import { refreshApp } from './swUpdate'

afterEach(() => kitRefreshApp.mockClear())

describe('refreshApp (Enceladus App refresh)', () => {
  it('runs the kit reset with the Clear-Site-Data signal route', async () => {
    await refreshApp()
    expect(kitRefreshApp).toHaveBeenCalledTimes(1)
    expect(kitRefreshApp).toHaveBeenCalledWith({ signalUrl: APP_REFRESH_URL })
  })
})
