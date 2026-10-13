import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// DVP-TSK-B21: the cockpit's push opt-in is a design-system Alert on the kit client (io request 2026-10-13).
const kit = vi.hoisted(() => ({
  supported: true,
  subscription: null as unknown,
  enable: vi.fn(async () => ({ ok: true })),
  displayMode: 'browser' as 'browser' | 'standalone' | 'fullscreen',
}))
vi.mock('@io-kit/shell/react', () => ({ useDisplayMode: () => kit.displayMode }))
vi.mock('@io-kit/notify', () => ({
  pushSupported: () => kit.supported,
  currentSubscription: async () => kit.subscription,
  enablePush: kit.enable,
}))
const navigate = vi.hoisted(() => vi.fn())
vi.mock('@tanstack/react-router', () => ({ useNavigate: () => navigate }))

import { PUSH_NUDGE_DISMISS_KEY } from '@io-kit/notify/react'
import { EscalationPushNudge } from './EscalationPushNudge'

const api = {} as never
let host: HTMLDivElement
let root: ReturnType<typeof createRoot>
let store: Map<string, string>
const storage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v) } }

async function mount() {
  await act(async () => { root.render(<EscalationPushNudge api={api} storage={storage} className="ev2-esc__notice" />) })
}
const nudge = () => host.querySelector('[data-testid="push-nudge"]')
const buttons = () => Array.from(host.querySelectorAll('button'))

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.stubGlobal('Notification', { permission: 'default' })
  kit.supported = true
  kit.displayMode = 'browser'
  kit.subscription = null
  kit.enable.mockReset().mockResolvedValue({ ok: true })
  store = new Map()
  host = document.createElement('div')
  root = createRoot(host)
})

afterEach(() => {
  act(() => root.unmount())
  vi.unstubAllGlobals()
  Object.defineProperty(navigator, 'userAgent', { configurable: true, value: DESKTOP_UA })
})

const DESKTOP_UA = navigator.userAgent
const IOS_SAFARI_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'

describe('EscalationPushNudge', () => {
  it('renders a design-system info Alert with a primary action and a dismiss, not bare markup', async () => {
    await mount()
    expect(nudge()?.getAttribute('data-state')).toBe('prompt')
    expect(nudge()?.className).toBe('ev2-esc__notice')
    expect(host.querySelector('.ev2-alert.ev2-alert--info')).not.toBeNull()
    expect(host.querySelector('.ev2-alert__header')?.textContent).toBe('Get notified when a gate needs your verdict')
    const link = host.querySelector('a.ev2-link')
    expect(link?.getAttribute('href')).toBe('/settings/notifications')
    act(() => { (link as HTMLAnchorElement).click() })
    expect(navigate).toHaveBeenCalledWith({ to: '/settings/notifications' })
    expect(buttons().map((b) => b.textContent?.trim())).toContain('Turn on notifications')
    expect(host.querySelector('.ev2-alert__dismiss')?.getAttribute('aria-label')).toBe('Dismiss')
    expect(host.textContent).not.toMatch(/(^|\s)x(\s|$)/)
  })

  it('turns on push and disappears', async () => {
    await mount()
    const on = buttons().find((b) => b.textContent?.includes('Turn on notifications'))!
    await act(async () => { on.click() })
    expect(kit.enable).toHaveBeenCalledWith(api)
    expect(nudge()).toBeNull()
  })

  it('explains a refused permission as a warning', async () => {
    kit.enable.mockResolvedValue({ ok: false })
    await mount()
    await act(async () => { buttons().find((b) => b.textContent?.includes('Turn on'))!.click() })
    expect(nudge()?.getAttribute('data-state')).toBe('blocked')
    expect(host.querySelector('.ev2-alert--warning .ev2-alert__header')?.textContent).toBe('Notifications are blocked for this site')
  })

  it('remembers a dismissal under the kit key', async () => {
    await mount()
    await act(async () => { (host.querySelector('.ev2-alert__dismiss') as HTMLButtonElement).click() })
    expect(store.get(PUSH_NUDGE_DISMISS_KEY)).toBe('1')
    expect(nudge()).toBeNull()
  })

  it.each([
    ['already dismissed', () => { store.set(PUSH_NUDGE_DISMISS_KEY, '1') }],
    ['already subscribed', () => { kit.subscription = {} }],
    ['permission already decided', () => { vi.stubGlobal('Notification', { permission: 'granted' }) }],
    ['push unsupported', () => { kit.supported = false }],
  ])('stays hidden when %s', async (_label, arrange) => {
    arrange()
    await mount()
    expect(nudge()).toBeNull()
  })

  it('tells iOS Safari users to add the app to the Home Screen first', async () => {
    Object.defineProperty(navigator, 'userAgent', { configurable: true, value: IOS_SAFARI_UA })
    kit.supported = false // iOS Safari outside the installed app has no PushManager
    await mount()
    expect(nudge()?.getAttribute('data-state')).toBe('ios')
    expect(host.querySelector('.ev2-alert__header')?.textContent).toBe('Add Enceladus to your Home Screen for notifications')
    expect(buttons().map((b) => b.textContent?.trim())).not.toContain('Turn on notifications')
  })

  it('offers the normal prompt inside the installed iOS app', async () => {
    Object.defineProperty(navigator, 'userAgent', { configurable: true, value: IOS_SAFARI_UA })
    kit.displayMode = 'standalone'
    await mount()
    expect(nudge()?.getAttribute('data-state')).toBe('prompt')
  })
})
