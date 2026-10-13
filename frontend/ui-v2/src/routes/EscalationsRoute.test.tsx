import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { callHashFor, type GateCard } from '@io-kit/gates'

/** DVP-TSK-A20: the restored cockpit on a mocked kit source (authFetch records the hub requests). */
const { authFetch, stepUp } = vi.hoisted(() => ({ authFetch: vi.fn(), stepUp: vi.fn() }))
vi.mock('../auth/authClient', () => ({
  auth: {
    authFetch: (...a: unknown[]) => authFetch(...a),
    getSession: () => ({ status: 'authenticated' }),
    stepUp: (...a: unknown[]) => stepUp(...a),
  },
}))
vi.mock('../auth/useCan', () => ({ useCanExecute: () => true, useAuthSession: () => ({}) }))
vi.mock('../api/projects', async () => {
  const actual = await vi.importActual<typeof import('../api/projects')>('../api/projects')
  return { ...actual, fetchProjectsList: vi.fn().mockResolvedValue([]) }
})

import { EscalationsRoute } from './EscalationsRoute'
import { EscalationsCockpit } from './EscalationsCockpit'
import { gateFetch } from './GateInboxPanel'
import { useFeedBufferStore } from '../store/feedBufferStore'

const FX = JSON.parse(readFileSync('node_modules/@io-kit/gates/fixtures/list-star.json', 'utf8')) as Record<string, unknown>
// The kit fixture wraps the hub body: { note, provenance, response: { escalations: [...], ... } }
const RESP = (FX as { response: Record<string, unknown> }).response
const TPL = (RESP.escalations as Record<string, unknown>[])[0]!
const EV = [{ label: 'Target record', ref: 'DVP-TSK-1' }]
const NOW = Date.now()
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
const base = (o: Record<string, unknown>) => {
  const c: Record<string, unknown> = { ...TPL }
  for (const k of ['candidates', 'proposedCalls', 'decision', 'diff', 'decision_log', 'decision_log_head', 'decision_log_valid', 'snoozedUntil']) c[k] = undefined
  return Object.assign(c, o)
}
const decision = (d: string) => ({ decision: d, decider: 'io', decidedAt: iso(NOW - 3600_000), auth_method: 'interactive_human', auth_time: iso(NOW - 3600_000), assurance: 'interactive_human' })
const PENDING = [
  base({ id: 'DVP-ESC-100', project_id: 'devops', kind: 'escalation', family: 'decision', risk: 'medium', state: 'pending', title: 'Apply status change', subject: { record_id: 'DVP-TSK-1', project: 'devops', version: '3' }, etag: '"e100"', createdAt: iso(NOW - 7200_000), expiresAt: iso(NOW + 5 * 3600_000), requiredAuth: 'interactive_human', evidence: EV }),
  base({ id: 'TC-200', project_id: 'enceladus', kind: 'tool_call', family: 'decision', risk: 'low', state: 'pending', title: 'Deploy lambda', subject: { record_id: 'ENC-TSK-2', project: 'enceladus', version: '1' }, etag: '"e200"', createdAt: iso(NOW - 600_000), expiresAt: iso(NOW + 9 * 3600_000), requiredAuth: 'interactive_human', evidence: EV }),
  base({ id: 'DVP-ESC-300', project_id: 'devops', kind: 'escalation', family: 'decision', risk: 'high', state: 'pending', title: 'Rotate key', subject: { record_id: 'DVP-TSK-3', project: 'devops', version: '2' }, etag: '"e300"', createdAt: iso(NOW - 1800_000), expiresAt: iso(NOW + 8 * 3600_000), requiredAuth: 'step_up', evidence: EV }),
]
const TERMINAL = [
  base({ id: 'DVP-ESC-001', project_id: 'devops', kind: 'escalation', family: 'decision', risk: 'low', state: 'decided', title: 'Old approved', subject: { record_id: 'DVP-TSK-9', project: 'devops', version: '1' }, etag: '"e1"', createdAt: iso(NOW - 86400_000), expiresAt: iso(NOW + 3600_000), decision: decision('approve'), evidence: EV }),
  base({ id: 'DVP-ESC-002', project_id: 'devops', kind: 'escalation', family: 'decision', risk: 'low', state: 'decided', title: 'Old denied', subject: { record_id: 'DVP-TSK-8', project: 'devops', version: '1' }, etag: '"e2"', createdAt: iso(NOW - 86400_000), expiresAt: iso(NOW + 3600_000), decision: decision('deny'), evidence: EV }),
]
const listBody = (cards: unknown[]) => {
  const b: Record<string, unknown> = { ...RESP, escalations: cards }
  for (const k of Object.keys(b)) if (/cursor/i.test(k)) delete b[k]
  return JSON.stringify(b)
}
const json = (body: string, status = 200) => new Response(body, { status, headers: { 'Content-Type': 'application/json' } })
const defaultImpl = async (url: unknown, init?: RequestInit) => {
  if ((init?.method ?? 'GET') === 'POST') return json(JSON.stringify({ success: true, decision: { decision: 'approve', hash: 'abc123' } }))
  return json(listBody(String(url).includes('pending') ? PENDING : TERMINAL))
}

let container: HTMLDivElement
let root: Root
// react-query notifies on a macrotask, so the flush must yield to real timers (not only microtasks)
const flush = async () => { for (let i = 0; i < 6; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)) }) }
const mount = async (node: React.ReactNode) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  await act(async () => { root.render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>) })
  await flush()
}
const listCalls = () => authFetch.mock.calls.filter((c) => (c[1]?.method ?? 'GET') === 'GET' && String(c[0]).includes('/coordination/escalations?'))
const posts = () => authFetch.mock.calls.filter((c) => c[1]?.method === 'POST')
const click = async (el: Element | undefined) => { expect(el).toBeTruthy(); await act(async () => { (el as HTMLElement).click() }); await flush() }
const byText = (sel: string, text: string) => [...document.body.querySelectorAll(sel)].find((b) => b.textContent?.trim() === text)
const tab = (t: string) => [...document.body.querySelectorAll('[role="tab"], button, a')].find((b) => b.textContent?.trim().startsWith(t))
const openRow = (id: string) => click(byText('button.ev2-esc__idlink', id))
const typeNote = async (v: string) => {
  const ta = document.body.querySelector('textarea[aria-label="Guidance note"]') as HTMLTextAreaElement
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(ta, v); ta.dispatchEvent(new Event('input', { bubbles: true })) })
}

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  authFetch.mockReset(); stepUp.mockReset()
  authFetch.mockImplementation(defaultImpl)
  stepUp.mockResolvedValue({ method: 'cognito_max_age', auth_time: 1760000000 })
  window.history.replaceState(null, '', '/escalations')
  useFeedBufferStore.getState().clear()
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container)
})
afterEach(() => { act(() => root.unmount()); container.remove(); window.history.replaceState(null, '', '/') })

describe('gateFetch', () => {
  it('asks the hub for derived kinds, strips the kit prefix and drops the placeholder bearer', async () => {
    await gateFetch('/api/v1/coordination/escalations?project_id=*', { method: 'GET', headers: { Authorization: 'Bearer session-held-by-auth-client' } })
    const [url, init] = authFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('include_derived=true')
    expect(url.startsWith('/coordination/escalations?')).toBe(true)
    expect(new Headers(init.headers).has('Authorization')).toBe(false)
    expect(init.credentials).toBe('include')
    await gateFetch('/api/v1/coordination/escalations/devops/DVP-ESC-011/approve', { method: 'POST', body: '{}' })
    expect(authFetch.mock.calls[1][0]).toBe('/coordination/escalations/devops/DVP-ESC-011/approve')
  })
})

describe('restored cockpit layout on the hub data', () => {
  it('renders PageHeader, tabs, StackedTable rows with a kind badge, for every project, from ONE all-projects feed', async () => {
    await mount(<EscalationsRoute />)
    expect(container.querySelectorAll('h1').length).toBe(1)
    expect(container.textContent).toContain('Escalations')
    expect(container.textContent).toContain('3 pending')
    for (const label of ['Pending', 'Approved', 'Denied', 'All']) expect(container.textContent).toContain(label)
    expect(container.textContent).toContain('DVP-ESC-100')
    expect(container.textContent).toContain('TC-200')
    expect(container.textContent).toContain('tool call')
    expect(container.textContent).toContain('enceladus')
    expect(container.textContent).toContain('devops')
    const calls = listCalls()
    expect(calls.length).toBe(2) // pending+snoozed, and the terminal block: no per-project fan-out
    for (const c of calls) expect(String(c[0])).toContain('project_id=*')
    expect(container.querySelector('[data-testid="gate-inbox-panel"]')).toBeNull()
  })

  it('?escalations=legacy is inert: the pre-kit renderer is gone and the current cockpit renders (DVP-TSK-B34)', async () => {
    window.history.replaceState(null, '', '/escalations?escalations=legacy')
    expect(window.location.search).toBe('?escalations=legacy')
    await mount(<EscalationsRoute />)
    // identical to the default render: ONE PageHeader, the cockpit tabs and rows, the hub's all-projects feed
    expect(container.querySelectorAll('h1').length).toBe(1)
    expect(container.textContent).toContain('3 pending')
    for (const label of ['Pending', 'Approved', 'Denied', 'All']) expect(container.textContent).toContain(label)
    expect(container.textContent).toContain('DVP-ESC-100')
    expect(container.textContent).toContain('TC-200')
    expect(container.querySelector('button.ev2-esc__idlink')).toBeTruthy()
    expect(container.querySelector('[data-testid="gate-inbox-panel"]')).toBeNull()
    // no pre-kit per-project fan-out or ESC-only reader: only the two all-projects hub list calls
    expect(authFetch.mock.calls.length).toBe(2)
    for (const c of listCalls()) expect(String(c[0])).toContain('project_id=*')
    expect(listCalls().length).toBe(2)
  })

  it('shows terminal rows under the Approved and Denied tabs', async () => {
    await mount(<EscalationsRoute />)
    await click(tab('Approved'))
    expect(container.textContent).toContain('DVP-ESC-001')
    expect(container.textContent).not.toContain('DVP-ESC-002')
    await click(tab('Denied'))
    expect(container.textContent).toContain('DVP-ESC-002')
  })
})

describe('decide through the kit path', () => {
  it('approve sends If-Match, Idempotency-Key and shows the receipt inline', async () => {
    await mount(<EscalationsRoute />)
    await openRow('DVP-ESC-100')
    await click(byText('button', 'Approve & apply'))
    const p = posts()
    expect(p.length).toBe(1)
    expect(String(p[0][0])).toBe('/coordination/escalations/devops/DVP-ESC-100/approve')
    const h = new Headers((p[0][1] as RequestInit).headers)
    expect(h.get('If-Match')).toBeTruthy()
    expect(h.get('Idempotency-Key')).toBeTruthy()
    expect(stepUp).not.toHaveBeenCalled()
    expect(document.body.querySelector('[data-testid="decide-receipt"]')?.textContent).toContain('abc123')
  })

  it('deny needs a note and posts to the deny route', async () => {
    await mount(<EscalationsRoute />)
    await openRow('TC-200')
    expect((byText('button', 'Deny') as HTMLButtonElement).disabled).toBe(true)
    await typeNote('not now')
    await click(byText('button', 'Deny with guidance'))
    expect(String(posts()[0][0])).toBe('/coordination/escalations/enceladus/TC-200/deny')
    expect(String((posts()[0][1] as RequestInit).body)).toContain('not now')
  })

  it('a step_up / high-risk card prompts through the provider and carries the proof', async () => {
    await mount(<EscalationsRoute />)
    await openRow('DVP-ESC-300')
    expect(document.body.querySelector('[data-testid="step-up-required"]')).not.toBeNull()
    await click(byText('button', 'Approve & apply'))
    expect(stepUp).toHaveBeenCalledTimes(1)
    expect(String((posts()[0][1] as RequestInit).body)).toContain('cognito_max_age')
  })

  it('a 412 card_changed refreshes the queue and tells io', async () => {
    authFetch.mockImplementation(async (url: unknown, init?: RequestInit) =>
      (init?.method ?? 'GET') === 'POST' ? json(JSON.stringify({ error: 'card_changed', reason: 'card_changed' }), 412) : defaultImpl(url, init))
    await mount(<EscalationsRoute />)
    const before = listCalls().length
    await openRow('DVP-ESC-100')
    await click(byText('button', 'Approve & apply'))
    expect(listCalls().length).toBeGreaterThan(before)
    expect(container.textContent).toMatch(/Card changed|Decision was not recorded/)
  })

  it('refreshes in place when an escalation record event arrives (realtime)', async () => {
    await mount(<EscalationsRoute />)
    const before = listCalls().length
    await act(async () => {
      useFeedBufferStore.getState().bufferEvent({ eventId: 'e1', recordId: 'DVP-ESC-009', record_type: 'escalation', action: 'created', actorType: 'agent', actorId: 'a', summary: 'new', cursor: 77, channels: [] })
    })
    await flush()
    expect(listCalls().length).toBeGreaterThan(before)
  })
})

describe('producer cards with JSON-string gate fields (DVP-TSK-B30)', () => {
  // DVP-ESC-011..015 as the hub served them before B30: proposedCalls is the stored JSON string.
  const CALL = {
    capability: 'recipe.publish', mcpTool: 'recipe_publish_request', method: 'POST',
    path: '/api/v1/tracker/devops/recipe/DVP-REC-001/apply', args: { version: '1.0.0', target: 'published' },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true }, callHash: 'bbd05bc3',
  }
  const RECIPE = base({ id: 'DVP-ESC-011', project_id: 'devops', kind: 'acceptance', family: 'decision', risk: 'medium', state: 'pending', title: 'Publish recipe governance-arc (DVP-REC-001@1.0.0)', subject: { record_id: 'DVP-REC-001', project: 'devops', version: '1.0.0' }, etag: '"e011"', createdAt: iso(NOW - 600_000), expiresAt: iso(NOW + 5 * 86400_000), requiredAuth: 'interactive_human', evidence: EV, proposedCalls: JSON.stringify([CALL]) })

  it('opens the card and approves with the hash of the call, not the legacy triple', async () => {
    authFetch.mockImplementation(async (url: unknown, init?: RequestInit) =>
      (init?.method ?? 'GET') === 'GET' && String(url).includes('pending') ? json(listBody([RECIPE])) : defaultImpl(url, init))
    await mount(<EscalationsRoute />)
    await openRow('DVP-ESC-011')
    expect(document.body.textContent).toContain('Proposed call')
    await click(byText('button', 'Approve & apply'))
    const expected = await callHashFor({ ...RECIPE, proposedCalls: [CALL] } as unknown as GateCard)
    expect(String((posts()[0][1] as RequestInit).body)).toContain(expected)
  })
})

describe('home requires-io slot', () => {
  it('renders the same rows, pending only, without a second PageHeader', async () => {
    await mount(<EscalationsCockpit compact />)
    expect(container.querySelectorAll('h1').length).toBe(0)
    expect(container.textContent).toContain('DVP-ESC-100')
    expect(listCalls().length).toBe(1)
    expect(String(listCalls()[0][0])).toContain('project_id=*')
  })
})

describe('push deep link (DVP-TSK-A24)', () => {
  it('/escalations/ESC-1 opens that escalation with Approve/Deny rendered first', async () => {
    await mount(<EscalationsRoute escalationId="DVP-ESC-100" />)
    const focus = container.querySelector('[data-testid="escalation-focus"]')
    expect(focus).toBeTruthy()
    expect(focus!.textContent).toContain('DVP-ESC-100')
    expect(byText('[data-testid="escalation-focus"] button', 'Approve')).toBeTruthy()
    expect(focus!.querySelector('textarea[aria-label="Guidance note"]')).toBeTruthy()
    expect(byText('[data-testid="escalation-focus"] button', 'Deny')).toBeTruthy()
    // the focus panel precedes the queue in document order, so it is above the fold on a phone
    expect(container.querySelector('[data-testid="escalation-focus"]')!.compareDocumentPosition(container.querySelector('table, [role="tablist"]')!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    await click(byText('[data-testid="escalation-focus"] button', 'Approve'))
    expect(posts().length).toBe(1)
  })
  it('an unknown id says so', async () => {
    await mount(<EscalationsRoute escalationId="NOPE-1" />)
    expect(container.textContent).toContain('NOPE-1 was not found')
  })
})
