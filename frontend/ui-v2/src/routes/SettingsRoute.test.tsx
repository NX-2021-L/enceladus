import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// ENC-TSK-Q84: /settings hosts the Notifications and Passkeys sections; the menu carries Settings.
vi.mock('../notifications/notifyApi', () => ({ notifyApi: {} }))
vi.mock('@io-kit/notify/react', () => ({
  NotificationsSection: () => <div>notifications-body</div>,
  notificationsSettingsSection: { id: 'notifications', title: 'Notifications', order: 10, component: () => null },
}))
vi.mock('@io-kit/auth/passkeys', () => ({
  createCognitoPasskeyAdapter: vi.fn(() => ({})),
  passkeysSettingsSection: () => ({ id: 'passkeys', title: 'Passkeys', order: 20, component: () => <div>passkeys-body</div> }),
}))
import { SettingsRoute } from './SettingsRoute'
import { NAV_ITEMS } from '../shell/navRegistry'

let container: HTMLDivElement
let root: Root
const flush = async () => { for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)) }) }

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container)
})
afterEach(() => { act(() => root.unmount()); container.remove() })

describe('SettingsRoute (ENC-TSK-Q84)', () => {
  it('renders the Notifications and Passkeys sections', async () => {
    await act(async () => { root.render(<SettingsRoute />) })
    await flush()
    const text = container.textContent ?? ''
    expect(text).toContain('Notifications')
    expect(text).toContain('Passkeys')
    expect(text).toContain('notifications-body')
    expect(text).toContain('passkeys-body')
  })
  it('puts Settings in the nav registry and drops the old Notifications entry', () => {
    expect(NAV_ITEMS.some((i) => i.route === '/settings')).toBe(true)
    expect(NAV_ITEMS.some((i) => i.route === '/settings/notifications')).toBe(false)
  })
  it('menu has Settings and no Add a passkey; legacy notifications route redirects to /settings#notifications', () => {
    const shell = readFileSync('src/shell/AppShell.tsx', 'utf8')
    expect(shell).toContain("text: 'Settings', href: '/settings'")
    expect(shell).not.toMatch(/Add a passkey|redirectToAddPasskey/)
    const router = readFileSync('src/routes/router.tsx', 'utf8')
    expect(router).toMatch(/path: '\/settings\/notifications'[\s\S]*redirect\(\{ to: '\/settings', hash: 'notifications'/)
  })
})
