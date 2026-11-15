import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from '@tanstack/react-router'
import type { RegistryComponent } from '../api/components'
import { floorClass, floorView, legacyDisagrees, registryRows, segmentCounts } from './componentRegistry'
import { ComponentDetailRoute, ComponentRegistryRoute } from './ComponentRegistryRoute'

const C = (o: Partial<RegistryComponent>): RegistryComponent => ({
  component_id: 'comp-x', component_name: 'X', project_id: 'enceladus', category: 'lambda', ...o,
})
const FIX: RegistryComponent[] = [
  C({ component_id: 'comp-a', lifecycle_status: 'production', transition_type: 'github_pr_deploy', required_transition_type: 'github_pr_deploy', updated_at: '2026-11-01T00:00:00Z' }),
  C({ component_id: 'comp-b', lifecycle_status: 'development', transition_type: 'no_code', required_transition_type: 'github_pr_deploy', updated_at: '2026-11-03T00:00:00Z' }),
  C({ component_id: 'comp-c', transition_type: 'code_only', updated_at: '2026-11-02T00:00:00Z' }),
  C({ component_id: 'comp-d', lifecycle_status: 'weird', updated_at: '2026-10-01T00:00:00Z' }),
  C({ component_id: 'comp-p', record_kind: 'proposal', lifecycle_status: 'proposed' }),
]

describe('registry mapping', () => {
  it('maps floor classes', () => {
    expect(floorClass('lambda_deploy')).toBe('code')
    expect(floorClass('no_code')).toBe('documentation')
    expect(floorClass('external_deploy')).toBe('external_deploy')
    expect(floorClass('odd')).toBe('odd')
    expect(floorView(C({ required_transition_type: 'no_code' }))).toMatchObject({ cls: 'documentation', showStored: true })
    expect(floorView(C({ required_transition_type: 'code' })).showStored).toBe(false)
    expect(legacyDisagrees(FIX[1]!)).toBe(true)
    expect(legacyDisagrees(FIX[0]!)).toBe(false)
  })
  it('counts segments and drops proposals', () => {
    const rows = registryRows(FIX)
    expect(rows).toHaveLength(4)
    expect(segmentCounts(rows)).toEqual({ all: 4, pipeline: 1, production: 1, none: 2, legacy: 1 })
  })
})

describe('registry render', () => {
  let host: HTMLDivElement | undefined
  afterEach(() => { host?.remove(); vi.unstubAllGlobals() })
  async function mount(path: string, Comp: () => React.ReactElement) {
    const root = createRootRoute()
    const list = createRoute({ getParentRoute: () => root, path: '/component-registry', component: Comp })
    const detail = createRoute({ getParentRoute: () => root, path: '/component-registry/$componentId', component: Comp })
    const router = createRouter({ routeTree: root.addChildren([list, detail]), history: createMemoryHistory({ initialEntries: [path] }) })
    host = document.createElement('div'); document.body.append(host)
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    await act(async () => {
      createRoot(host!).render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>)
    })
    await act(async () => { await new Promise((r) => setTimeout(r, 20)) })
  }
  const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'Content-Type': 'application/json' } })

  it('lists rows from the API with segment counts and unknown lifecycle verbatim', async () => {
    vi.stubGlobal('fetch', vi.fn(async (u: string) => json({ success: true, components: String(u).includes('kind=proposal') ? [] : FIX, count: FIX.length })))
    await mount('/component-registry', () => <ComponentRegistryRoute />)
    expect(host!.querySelectorAll('tbody tr')).toHaveLength(4)
    expect(host!.textContent).toContain('stored as github_pr_deploy')
    expect(host!.querySelector('[data-status="weird"]')?.getAttribute('data-role')).toBe('unknown')
    expect(host!.querySelector('[data-status="production"]')?.getAttribute('data-role')).toBe('live')
    expect(host!.textContent).toContain('none')
    expect(host!.querySelector('button.ev2-reg__seg[aria-pressed="true"]')?.textContent).toContain('4')
  })

  it('renders not-found for an unknown component', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'nope' }, 404)))
    await mount('/component-registry/comp-zzz', () => <ComponentDetailRoute />)
    expect(host!.textContent).toContain('comp-zzz was not found')
  })

  it('renders the detail page', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ success: true, component: FIX[0] })))
    await mount('/component-registry/comp-a', () => <ComponentDetailRoute />)
    expect(host!.textContent).toContain('Floor ladder')
    expect(host!.querySelector('[aria-current="true"]')?.textContent).toContain('code')
  })
})
