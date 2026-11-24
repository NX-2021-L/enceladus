import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-query', async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  useQuery: () => ({ data: [{ project_id: 'enceladus', prefix: 'ENC' }, { project_id: 'intelligence', prefix: 'INT' }] }),
  useMutation: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, className }: { children: unknown; className?: string }) => (
    <a href="/r" className={className}>
      {children as never}
    </a>
  ),
  useNavigate: () => vi.fn(),
}))
vi.mock('../api/projectRegistry', async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  projectRegistryQueryOptions: {},
}))
vi.mock('../hooks/useRecordMutation', () => ({
  useRecordMutation: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('../search/corpusSource', () => ({ getEnceladusCorpusStore: () => ({ rows: () => [] }) }))
vi.mock('../components/PlanGraphExplorer', () => ({ PlanGraphExplorer: () => null }))

import { TaskPrimitive } from './TaskPrimitive'
import { IssuePrimitive } from './IssuePrimitive'
import { FeaturePrimitive } from './FeaturePrimitive'
import { PlanPrimitive } from './PlanPrimitive'
import { LessonPrimitive } from './LessonPrimitive'
import { normalizeRecordBody } from '../realtime/normalizeRecordBody'

/**
 * ENC-TSK-T30 (ENC-ISS-926): every tracker detail page renders the body a
 * /records/{id} realtime event leaves in the cache. That body is the raw stream
 * image (item_id, no `{type}_id`). Uses the REAL resolveRecordTarget, which is
 * what threw "t.trim" on prod.
 */
type TrackerType = 'task' | 'issue' | 'feature' | 'plan' | 'lesson'
const base = { project_id: 'enceladus', title: 'T', description: 'd', history: [], updated_at: null, created_at: null }
const cases: { type: TrackerType; id: string; raw: Record<string, unknown>; el: (r: never) => React.ReactElement }[] = [
  {
    type: 'task',
    id: 'ENC-TSK-100',
    raw: { ...base, status: 'open', priority: 'P2', assigned_to: null, checklist_total: 0, checklist_done: 0 },
    el: (r) => <TaskPrimitive record={r} />,
  },
  {
    type: 'issue',
    id: 'INT-ISS-157',
    raw: { ...base, project_id: 'intelligence', status: 'closed', priority: 'P2', hypothesis: null, write_kind: 'marker' },
    el: (r) => <IssuePrimitive record={r} />,
  },
  {
    type: 'feature',
    id: 'ENC-FTR-300',
    raw: { ...base, status: 'planned' },
    el: (r) => <FeaturePrimitive record={r} />,
  },
  {
    type: 'plan',
    id: 'ENC-PLN-400',
    raw: { ...base, status: 'started', priority: 'P2', category: null, objectives_set: [] },
    el: (r) => <PlanPrimitive record={r} />,
  },
  {
    type: 'lesson',
    id: 'ENC-LSN-500',
    raw: {
      ...base,
      status: 'active',
      observation: 'o',
      insight: 'i',
      evidence_chain: [],
      provenance: 'p',
      confidence: 0.5,
      pillar_scores: {},
      pillar_composite: 0,
      resonance_score: 0,
      category: 'c',
    },
    el: (r) => <LessonPrimitive record={r} />,
  },
]

describe('detail pages render a live realtime body', () => {
  let container: HTMLDivElement
  let root: Root
  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })
  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  for (const c of cases) {
    it(`${c.type}: the normalized body renders with the record id in the header`, () => {
      const raw = { ...c.raw, item_id: c.id, record_id: `${c.type}#${c.id}` }
      const body = normalizeRecordBody(c.type, c.id, raw, undefined)
      expect(() => act(() => root.render(c.el(body as never)))).not.toThrow()
      const header = [...container.querySelectorAll('.enc-record-link-copyable')].find((w) => w.textContent?.includes(c.id))
      expect(header, `${c.id} header`).toBeTruthy()
    })

    it(`${c.type}: even an un-normalized body (no ${c.type}_id) renders instead of throwing`, () => {
      const raw = { ...c.raw, item_id: c.id }
      expect(() => act(() => root.render(c.el(raw as never)))).not.toThrow()
      expect(container.textContent).toContain('T')
    })
  }
})
