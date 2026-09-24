import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { refreshApp, setUpdateSW } from './swUpdate'

/**
 * ENC-TSK-M57 / ENC-ISS-525 regression coverage. The pre-fix refreshApp() only
 * ever awaited vite-plugin-pwa's updateSW(true), which silently no-ops when no
 * worker is waiting -- so an always-open tab's "App refresh" click did nothing
 * and never picked up a freshly deployed build. refreshApp() must now force an
 * update check and always guarantee forward progress (activate-and-reload, or a
 * plain reload fallback).
 */
describe('refreshApp (ENC-ISS-525)', () => {
  const reload = vi.fn()

  beforeEach(() => {
    reload.mockReset()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { reload },
    })
    // Reset the captured updateSW between tests.
    setUpdateSW(undefined as unknown as (reloadPage?: boolean) => Promise<void>)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('forces an update check and activates a waiting worker via updateSW (no direct reload)', async () => {
    const updateSW = vi.fn().mockResolvedValue(undefined)
    setUpdateSW(updateSW)
    const registration = {
      update: vi.fn().mockResolvedValue(undefined),
      waiting: {},
    }
    vi.stubGlobal('navigator', {
      serviceWorker: {
        getRegistration: vi.fn().mockResolvedValue(registration),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      },
    })

    await refreshApp()

    expect(registration.update).toHaveBeenCalledOnce()
    expect(updateSW).toHaveBeenCalledWith(true)
    // vite-plugin-pwa's updateSW owns the reload-on-controllerchange; we must
    // NOT also force a plain reload in this path.
    expect(reload).not.toHaveBeenCalled()
  })

  it('falls back to a real reload when no worker is waiting (the missing case)', async () => {
    const registration = {
      update: vi.fn().mockResolvedValue(undefined),
      waiting: null,
    }
    vi.stubGlobal('navigator', {
      serviceWorker: {
        getRegistration: vi.fn().mockResolvedValue(registration),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      },
    })

    await refreshApp()

    expect(registration.update).toHaveBeenCalledOnce()
    expect(reload).toHaveBeenCalledOnce()
  })

  it('reloads when service workers are unsupported', async () => {
    vi.stubGlobal('navigator', {})

    await refreshApp()

    expect(reload).toHaveBeenCalledOnce()
  })

  it('reloads if the registration lookup throws', async () => {
    vi.stubGlobal('navigator', {
      serviceWorker: {
        getRegistration: vi.fn().mockRejectedValue(new Error('boom')),
      },
    })

    await refreshApp()

    expect(reload).toHaveBeenCalledOnce()
  })
})
