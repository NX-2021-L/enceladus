// DVP-TSK-974: recipes surface from a mocked run client (no network, no router.tsx import).
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { act } from 'react'
import type { ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createMemoryHistory, createRootRoute, createRoute, createRouter } from '@tanstack/react-router'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const h = vi.hoisted(() => ({ client: {} as Record<string, any>, gate: {} as Record<string, any> }))
vi.mock('../api/recipes', () => ({
  createRecipeClient: () => h.client,
  createRecipeGateSource: () => h.gate,
  newIdempotencyKey: () => 'ui-test',
  RUN_POLL_MS: 5000,
}))

import { RecipesRoute } from './RecipesRoute'
import { RecipeDetailRoute } from './RecipeDetailRoute'
import { RecipeRunRoute } from './RecipeRunRoute'
import { inputRows, parseRecipesSearch, planHasUnresolved, versionOf } from './recipesView'
import { NAV_ITEMS } from '../shell/navRegistry'
import { matchActionCommands } from '../actions/commands'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const DEF = {
  description: 'Close the books',
  inputs: { type: 'object', properties: { period: { type: 'string', description: 'YYYY-MM' }, dry: { type: 'boolean' } }, required: ['period'] },
  outputs: { schema: {}, from: {} },
  steps: [],
  tools: ['tracker.create', 'documents.put'],
}
const VERSION = { version: '1.0.0', status: 'published', content_hash: 'sha256:' + 'a'.repeat(64), supersedes: null, publish_escalation_id: null, definition: { ...DEF, inputs: { type: 'object', properties: { note: { type: 'string' } } } } }
const GET = {
  head: { recipe_id: 'ENC-REC-1', name: 'close-period', owner: 'io', project_ids: ['enceladus'], related_feature_ids: ['ENC-FTR-9'] },
  version: { head: {}, version: VERSION },
  resolved: 'latest_published',
  versions: [{ version: '1.0.0', status: 'published', content_hash: VERSION.content_hash }],
}
const RUN = {
  run_id: 'ENC-RUN-1', recipe_ref: { recipe_id: 'ENC-REC-1', version: '1.0.0', content_hash: VERSION.content_hash }, project_id: 'enceladus', inputs: {},
  status: 'awaiting_gate', cursor: 1, steps: [{ id: 's1', status: 'ok', resolved_call: null, result: null, error: null }, { id: 'g1', status: 'awaiting', resolved_call: null, result: null, error: null }],
  gate: { step_id: 'g1', escalation_id: 'ENC-ESC-9', opened_at: '2026-10-11T00:00:00Z', expires_at: '2026-10-12T00:00:00Z' },
  outputs: null, error: null, compensation: 'none', started_by: 'io', idempotency_key: 'k', governance_hash_start: 'x', governance_hash_last: 'x',
  telemetry: { steps_total: 2, gates_opened: 1, writes: 1, agent_calls: 0 }, expires_at: '2026-10-12T00:00:00Z', rev: 1, resume_token: 'tok-1', receipts: [],
}

const settle = async () => { for (let i = 0; i < 12; i++) await act(async () => { await new Promise((r) => setTimeout(r, 0)) }) }

async function mount(path: string, url: string, component: () => ReactNode) {
  const root = createRootRoute()
  const route = createRoute({ getParentRoute: () => root, path, component })
  const rest = createRoute({ getParentRoute: () => root, path: '$', component: () => null })
  const router = createRouter({ routeTree: root.addChildren([route, rest]), history: createMemoryHistory({ initialEntries: [url] }) })
  const el = document.createElement('div')
  document.body.appendChild(el)
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  await act(async () => { createRoot(el).render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>) })
  await settle()
  return el
}
const button = (el: HTMLElement, label: string) => [...el.querySelectorAll('button')].find((b) => b.textContent === label)

beforeEach(() => {
  h.client = {
    recipes: { list: vi.fn(async () => ({ items: [{ recipe_id: 'ENC-REC-1', name: 'close-period', owner: 'io', status: 'published', tags: [], project_ids: ['enceladus'], latest_published: '1.0.0', version_count: 1 }], count: 1, truncated: false })), get: vi.fn(async () => GET) },
    startRun: vi.fn(async () => ({ mode: 'dry_run', dry_run: true, run_id: null, recipe_ref: RUN.recipe_ref, planned: [{ step_id: 's1', action: 'tracker.create', arguments: { title: '$unresolved' } }], fixture_mode: false, unresolved: true })),
    getRun: vi.fn(async () => RUN),
    subscribeRun: vi.fn((_id: string, hd: { onRun: (r: unknown) => void }) => { void Promise.resolve().then(() => hd.onRun(h.client.__run ?? RUN)); return () => {} }),
    resume: vi.fn(async () => RUN),
    cancel: vi.fn(async () => RUN),
  }
  h.gate = { get: vi.fn(() => new Promise(() => {})) }
})

describe('recipes helpers', () => {
  it('parses the project, summarizes inputs, flags $unresolved, reads both version shapes', () => {
    expect(parseRecipesSearch({ project: 'devops' }).project).toBe('devops')
    expect(parseRecipesSearch({ project: 'nope' }).project).toBe('enceladus')
    expect(inputRows(DEF.inputs)).toEqual([
      { name: 'period', required: true, summary: 'string - YYYY-MM' },
      { name: 'dry', required: false, summary: 'boolean' },
    ])
    expect(planHasUnresolved([{ a: '$unresolved' }])).toBe(true)
    expect(versionOf(GET as never)?.version).toBe('1.0.0')
    expect(versionOf({ version: VERSION } as never)?.version).toBe('1.0.0')
  })
  it('registers the routes, the nav item and the palette command', () => {
    const src = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8')
    for (const p of ["path: '/recipes'", "path: '/recipes/runs/$runId'", "path: '/recipes/$recipeId'", "path: '/actions/recipe_run.start'"]) expect(src).toContain(p)
    expect(NAV_ITEMS.some((i) => i.id === 'recipes' && i.route === '/recipes')).toBe(true)
    expect(matchActionCommands('recipe_run').some((c) => c.name === 'recipe_run.start')).toBe(true)
  })
})

describe('recipes list and detail', () => {
  it('lists recipe records with lifecycle, version, tools, projects and features', async () => {
    const el = await mount('/recipes', '/recipes?project=enceladus', RecipesRoute)
    const text = el.textContent ?? ''
    expect(el.querySelectorAll('h1').length).toBe(1)
    for (const t of ['close-period', 'published', '1.0.0 (1)', 'enceladus', 'ENC-FTR-9']) expect(text).toContain(t)
    expect(h.client.recipes.list).toHaveBeenCalled()
  })
  it('detail shows declared inputs, tools, versions and a dry run that plans $unresolved with zero writes', async () => {
    const el = await mount('/recipes/$recipeId', '/recipes/ENC-REC-1?project=enceladus', RecipeDetailRoute)
    const text = el.textContent ?? ''
    for (const t of ['published', 'optional', 'tracker.create', 'documents.put', VERSION.content_hash, 'ENC-FTR-9', 'Run to next gate']) expect(text).toContain(t)
    await act(async () => { button(el, 'Dry run all')?.click() })
    await settle()
    expect(h.client.startRun).toHaveBeenCalledWith(expect.objectContaining({ recipeId: 'ENC-REC-1', mode: 'dry_run', idempotencyKey: 'ui-test' }))
    expect(el.textContent).toContain('zero writes')
    expect(el.textContent).toContain('$unresolved')
  })
})

describe('recipe run page', () => {
  it('awaiting_gate deep-links the escalation and resumes with the resume token', async () => {
    const el = await mount('/recipes/runs/$runId', '/recipes/runs/ENC-RUN-1?project=enceladus', RecipeRunRoute)
    const link = [...el.querySelectorAll('a')].find((a) => a.textContent === 'ENC-ESC-9')
    expect(link?.getAttribute('href')).toContain('/escalations')
    expect(link?.getAttribute('href')).toContain('focus=ENC-ESC-9')
    expect(h.gate.get).toHaveBeenCalledWith('ENC-ESC-9', expect.objectContaining({ project: 'enceladus' }))
    await act(async () => { button(el, 'Resume')?.click() })
    expect(h.client.resume).toHaveBeenCalledWith(expect.objectContaining({ resumeToken: 'tok-1' }))
    expect(h.client.subscribeRun).toHaveBeenCalled()
  })
  it('completed run shows the minted ids as receipts', async () => {
    h.client.__run = { ...RUN, status: 'completed', gate: null, resume_token: null, receipts: [{ step_id: 's1', action: 'tracker.create', pointer: '/id', id: 'ENC-TSK-900' }] }
    const el = await mount('/recipes/runs/$runId', '/recipes/runs/ENC-RUN-1?project=enceladus', RecipeRunRoute)
    expect(el.textContent).toContain('ENC-TSK-900')
    expect(button(el, 'Resume')).toBeUndefined()
  })
})
