import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../notifications/notifyApi', () => ({ notifyApi: {} }))
import { NotificationSettingsRoute } from './NotificationSettingsRoute'
import { escalationCatalog } from '../notifications/escalationCatalog'

let container: HTMLDivElement
let root: Root
const flush = async () => { for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)) }) }

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container)
})
afterEach(() => { act(() => root.unmount()); container.remove() })

describe('NotificationSettingsRoute (DVP-TSK-A24)', () => {
  it('renders the escalation catalog and a toggle PUTs preferences through the api', async () => {
    const api = {
      getVapidPublicKey: vi.fn().mockResolvedValue({ public_key: 'AAAA' }),
      subscribePush: vi.fn().mockResolvedValue({}),
      unsubscribePush: vi.fn().mockResolvedValue({}),
      getPreferences: vi.fn().mockResolvedValue({ enabled: true, types: {}, extra: {} }),
      putPreferences: vi.fn().mockResolvedValue({}),
    }
    await act(async () => { root.render(<NotificationSettingsRoute api={api} />) })
    await flush()
    expect(container.querySelectorAll('h1').length).toBe(1)
    expect(container.textContent).toContain('Notifications')
    expect(container.textContent).toContain('Minimum risk')
    const toggle = container.querySelector('[role="switch"][aria-labelledby^="iok-notify-l-"]') as HTMLElement | null
    expect(toggle).toBeTruthy()
    await act(async () => { toggle!.click() })
    await flush()
    expect(api.putPreferences).toHaveBeenCalled()
  })
  it('catalog has one type per gate kind in one group', () => {
    expect(escalationCatalog.groups.map((g) => g.id)).toEqual(['escalations'])
    for (const k of ['escalation', 'tool_call', 'reconciliation', 'drift', 'notice']) expect(escalationCatalog.types[k]).toBeTruthy()
  })
  it('vite config imports notify-sw.js in the service worker', () => {
    const cfg = readFileSync('vite.config.ts', 'utf8')
    expect(cfg).toMatch(/importScripts:\s*\[[^\]]*'notify-sw\.js'/)
    expect(cfg).toMatch(/notifySw\(\)/)
  })
})
