import { afterEach, describe, expect, it, vi } from 'vitest'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createMemoryHistory, createRootRoute, createRoute, createRouter } from '@tanstack/react-router'

vi.mock('../auth/useCan', () => ({ useCanExecute: () => true }))
import { ProposalReviewRoute } from './ProposalReviewRoute'
import { ComponentDetailRoute } from './ComponentRegistryRoute'
import { actionPlan } from './componentRegistry'
import { decideProposal, getComponent, lifecycleBody, toProposal } from '../api/components'

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'Content-Type': 'application/json' } })
const VIEW = { proposal_ref: 'cprop-0123456789', display_name: 'Widget', suggested_component_id: 'comp-widget', project_id: 'devops', category: 'lambda', version: 2, proposal_status: 'pending', source_paths: ['a/b'] }

describe('component read merges sibling edges', () => {
  it('GET /components/{id} returns edges beside component (S82); getComponent attaches them', async () => {
    const edges = [{ edge_type: 'DEPLOYS', task_id: 'ENC-TSK-1', created_at: 't', locked: false, lock_trigger: null }]
    vi.stubGlobal('fetch', vi.fn(async () => json({ success: true, component: { component_id: 'comp-a' }, edges })))
    expect((await getComponent('comp-a')).edges).toEqual(edges)
  })
})

describe('proposal adapter keys', () => {
  it('maps the S82 view', () => {
    const p = toProposal(VIEW)
    expect(p.component_id).toBe('cprop-0123456789')
    expect(p.component_name).toBe('Widget')
    expect(p.source_paths).toEqual({ '0': 'a/b' })
  })
  it('approve reads approved_component_id; 412 reads proposal', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ approved_component_id: 'comp-new', component_id: 'comp-new' })))
    expect((await decideProposal(toProposal(VIEW), 'approve', { verdict: 'approve', component_id: 'comp-new', required_transition_type: 'code' })).component_id).toBe('comp-new')
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'x', proposal: { ...VIEW, version: 3 } }, 412)))
    const err = await decideProposal(toProposal(VIEW), 'reject', { verdict: 'reject', rejection_reason: 'duplicate of x' }).catch((e) => e)
    expect(err.refreshed.version).toBe(3)
    expect(err.refreshed.component_name).toBe('Widget')
  })
})

describe('lifecycle actions', () => {
  it('plans actions from the transition table', () => {
    expect(actionPlan('approved')).toMatchObject({ advance: 'designed', revert: true, deprecate: false, restore: false })
    expect(actionPlan('production')).toMatchObject({ advance: undefined, deprecate: true })
    expect(actionPlan('deprecated')).toMatchObject({ restore: true, advance: undefined })
    expect(actionPlan('code-red').advance).toBe('production')
  })
  it('builds bodies with the server keys', () => {
    expect(lifecycleBody('advance', 'designed')).toEqual({ target_status: 'designed' })
    expect(lifecycleBody('revert', ' because it broke ')).toEqual({ reverted_reason: 'because it broke' })
    expect(lifecycleBody('deprecate', '')).toEqual({})
  })
})

describe('routes', () => {
  let host: HTMLDivElement | undefined
  afterEach(() => { host?.remove(); vi.unstubAllGlobals() })
  async function mount(path: string, pattern: string, Comp: () => React.ReactElement) {
    const root = createRootRoute()
    const r = createRoute({ getParentRoute: () => root, path: pattern, component: Comp })
    const router = createRouter({ routeTree: root.addChildren([r]), history: createMemoryHistory({ initialEntries: [path] }) })
    host = document.createElement('div'); document.body.append(host)
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    await act(async () => { createRoot(host!).render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>) })
    await act(async () => { await new Promise((x) => setTimeout(x, 30)) })
  }
  it('proposal review shows Approve and Reject', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ success: true, proposal: VIEW })))
    await mount('/component-registry/proposals/cprop-0123456789', '/component-registry/proposals/$ref', () => <ProposalReviewRoute />)
    const labels = [...host!.querySelectorAll('button')].map((b) => b.textContent)
    expect(labels).toContain('Approve')
    expect(labels).toContain('Reject')
    expect(host!.textContent).toContain('comp-widget')
    expect(host!.textContent).toContain('suggestion, not yet minted')
  })
  it('detail shows the track, edges and actions', async () => {
    const c = { component_id: 'comp-a', component_name: 'A', project_id: 'p', category: 'lambda', lifecycle_status: 'approved', edges: [{ edge_type: 'DEPLOYS', task_id: 'ENC-TSK-1', locked: true, lock_trigger: 'deploy_success' }] }
    vi.stubGlobal('fetch', vi.fn(async () => json({ success: true, component: c })))
    await mount('/component-registry/comp-a', '/component-registry/$componentId', () => <ComponentDetailRoute />)
    expect(host!.querySelector('.ev2-track__step[data-state="current"]')?.textContent).toBe('approved')
    expect(host!.textContent).toContain('locked')
    const labels = [...host!.querySelectorAll('button')].map((b) => b.textContent)
    expect(labels).toContain('Advance to designed')
    expect(labels).toContain('Revert')
  })
})
