import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

/**
 * DVP-TSK-970: the kit inbox on /escalations and in the home queue slot. The auth
 * client is mocked so no network or Cognito client is built; authFetch records the
 * exact requests the @io-kit/gates source makes against the consolidated hub.
 */
const authFetch = vi.fn()
vi.mock('../auth/authClient', () => ({
  auth: {
    authFetch: (...a: unknown[]) => authFetch(...a),
    getSession: () => ({ status: 'authenticated' }),
    stepUp: vi.fn(),
  },
}))
vi.mock('../auth/useCan', () => ({ useCanExecute: () => true, useAuthSession: () => ({}) }))
vi.mock('../api/projects', async () => {
  const actual = await vi.importActual<typeof import('../api/projects')>('../api/projects')
  return { ...actual, fetchProjectsList: vi.fn().mockResolvedValue([]) }
})

import { EscalationsRoute } from './EscalationsRoute'
import { GateInboxPanel, gateFetch } from './GateInboxPanel'
import { useFeedBufferStore } from '../store/feedBufferStore'

const LIST = readFileSync('node_modules/@io-kit/gates/fixtures/list-star.json', 'utf8')
const reply = () => new Response(LIST, { status: 200, headers: { 'Content-Type': 'application/json' } })

let container: HTMLDivElement
let root: Root
const flush = async () => {
  for (let i = 0; i < 6; i++) await act(async () => { await Promise.resolve() })
}
const mount = async (node: React.ReactNode) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  await act(async () => { root.render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>) })
  await flush()
}
const listCalls = () => authFetch.mock.calls.filter((c) => String(c[0]).includes('/coordination/escalations?'))

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  authFetch.mockReset()
  authFetch.mockImplementation(async () => reply())
  window.history.replaceState(null, '', '/escalations')
  useFeedBufferStore.getState().clear()
  container = document.createElement('div')
  document.body.appendChild(container)
  root = createRoot(container)
})
afterEach(() => {
  act(() => root.unmount())
  container.remove()
  window.history.replaceState(null, '', '/')
})

describe('gateFetch', () => {
  it('asks the hub for derived kinds and drops the placeholder bearer', async () => {
    await gateFetch('/api/v1/coordination/escalations?project_id=*', {
      method: 'GET',
      headers: { Authorization: 'Bearer session-held-by-auth-client', Accept: 'application/json' },
    })
    const [url, init] = authFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('include_derived=true')
    // authFetch adds its own '/api/v1' base: the kit prefix must be stripped (prod 404 2026-10-12)
    expect(url.startsWith('/coordination/escalations?')).toBe(true)
    expect(new Headers(init.headers).has('Authorization')).toBe(false)
    expect(init.credentials).toBe('include')
  })
})

describe('gateFetch path base', () => {
  it('strips the kit /api/v1 prefix on decide POSTs too', async () => {
    await gateFetch('/api/v1/coordination/escalations/devops/DVP-ESC-011/approve', { method: 'POST', body: '{}' })
    const [url] = authFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/coordination/escalations/devops/DVP-ESC-011/approve')
  })
})

describe('EscalationsRoute on the kit inbox', () => {
  it('lists every project (project_id=*) through the kit GateInbox', async () => {
    await mount(<EscalationsRoute />)
    const calls = listCalls()
    expect(calls.length).toBeGreaterThan(0)
    const url = String(calls[0][0])
    expect(url).toContain('project_id=*')
    expect(url).toContain('include_derived=true')
    expect(container.querySelector('[data-testid="gate-inbox-panel"]')).not.toBeNull()
    expect(container.querySelector('[data-testid="inbox-count"]')?.textContent).toMatch(/\d+ open/)
    expect(container.textContent).toContain('Escalations')
  })

  it('kind chips narrow the server query', async () => {
    await mount(<EscalationsRoute />)
    const chip = [...container.querySelectorAll('button.ev2-gates__chip')].find((b) => b.textContent === 'tool call') as HTMLButtonElement
    await act(async () => { chip.click() })
    await flush()
    expect(listCalls().some((c) => /kind=tool_call/.test(String(c[0])))).toBe(true)
  })

  it('ignores the retired ?escalations=legacy flag: the kit inbox is the only renderer (DVP-TSK-981)', async () => {
    window.history.replaceState(null, '', '/escalations?escalations=legacy')
    await mount(<EscalationsRoute />)
    expect(container.querySelector('[data-testid="gate-inbox-panel"]')).not.toBeNull()
    expect(listCalls().length).toBeGreaterThan(0)
  })

  it('refreshes in place when an escalation record event arrives (realtime)', async () => {
    await mount(<GateInboxPanel />)
    const before = listCalls().length
    await act(async () => {
      useFeedBufferStore.getState().bufferEvent({
        eventId: 'e1', recordId: 'DVP-ESC-009', record_type: 'escalation', action: 'created',
        actorType: 'agent', actorId: 'a', summary: 'new', cursor: 77, channels: [],
      })
    })
    await flush()
    expect(listCalls().length).toBeGreaterThan(before)
  })

  it('ignores non-escalation events', async () => {
    await mount(<GateInboxPanel />)
    const before = listCalls().length
    await act(async () => {
      useFeedBufferStore.getState().bufferEvent({
        eventId: 'e2', recordId: 'DVP-TSK-1', record_type: 'task', action: 'updated',
        actorType: 'agent', actorId: 'a', summary: 'x', cursor: 78, channels: [],
      })
    })
    await flush()
    expect(listCalls().length).toBe(before)
  })
})

describe('home queue slot', () => {
  it('compact panel hides the kind chips and still reads all projects', async () => {
    await mount(<GateInboxPanel compact />)
    expect(container.querySelector('.ev2-gates--compact')).not.toBeNull()
    expect(String(listCalls()[0][0])).toContain('project_id=*')
  })
})
