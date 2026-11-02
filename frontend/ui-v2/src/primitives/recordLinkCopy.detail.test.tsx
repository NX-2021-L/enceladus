import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-query', () => ({
  useQuery: () => ({ data: [] }),
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
vi.mock('../api/projectRegistry', () => ({ projectRegistryQueryOptions: {} }))
vi.mock('../hooks/useRecordMutation', () => ({
  useRecordMutation: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('../search/corpusSource', () => ({ getEnceladusCorpusStore: () => ({ rows: () => [] }) }))
vi.mock('../components/PlanGraphExplorer', () => ({ PlanGraphExplorer: () => null }))
vi.mock('../components/DocumentHistoryPanel', () => ({ DocumentHistoryPanel: () => null }))
vi.mock('../components/DocumentSectionsView', () => ({ DocumentSectionsView: () => null }))
vi.mock('../routes/recordLink', async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  resolveRecordTarget: (id: string) => (/^(ENC|DOC)-/.test(id) ? { to: '/r', params: {} } : null),
}))

import { TaskPrimitive } from './TaskPrimitive'
import { IssuePrimitive } from './IssuePrimitive'
import { FeaturePrimitive } from './FeaturePrimitive'
import { PlanPrimitive } from './PlanPrimitive'
import { LessonPrimitive } from './LessonPrimitive'
import { DocumentPrimitive } from './DocumentPrimitive'
import KitMarkdownContent from '../components/KitMarkdownContent'
import { TypedRelationshipSection } from '../components/TypedRelationshipSection'

/**
 * ENC-TSK-R81-0C / ENC-FTR-151 AC-3 + AC-4 -- every record/document id on a detail page renders
 * through RecordLink with a copy control to its right (one regression test per detail page type).
 */
const base = { project_id: 'enceladus', title: 'T', description: 'd', history: [], updated_at: null, created_at: null }
const cases: { name: string; own: string; neighbors: string[]; el: () => React.ReactElement }[] = [
  {
    name: 'task',
    own: 'ENC-TSK-100',
    neighbors: ['ENC-TSK-101', 'ENC-ISS-102', 'ENC-FTR-103', 'ENC-TSK-104'],
    el: () => (
      <TaskPrimitive
        record={
          {
            ...base,
            task_id: 'ENC-TSK-100',
            status: 'open',
            priority: 'P2',
            assigned_to: null,
            related_task_ids: ['ENC-TSK-101'],
            related_issue_ids: ['ENC-ISS-102'],
            related_feature_ids: ['ENC-FTR-103'],
            subtask_ids: ['ENC-TSK-104'],
            checklist_total: 0,
            checklist_done: 0,
          } as never
        }
      />
    ),
  },
  {
    name: 'issue',
    own: 'ENC-ISS-200',
    neighbors: ['ENC-TSK-201', 'ENC-TSK-202'],
    el: () => (
      <IssuePrimitive
        record={
          {
            ...base,
            issue_id: 'ENC-ISS-200',
            status: 'open',
            priority: 'P2',
            severity: 'low',
            hypothesis: null,
            related_task_ids: ['ENC-TSK-201', 'ENC-TSK-202'],
          } as never
        }
      />
    ),
  },
  {
    name: 'feature',
    own: 'ENC-FTR-300',
    neighbors: ['ENC-TSK-301'],
    el: () => (
      <FeaturePrimitive
        record={{ ...base, feature_id: 'ENC-FTR-300', status: 'planned', related_task_ids: ['ENC-TSK-301'] } as never}
      />
    ),
  },
  {
    name: 'plan',
    own: 'ENC-PLN-400',
    neighbors: ['ENC-TSK-401', 'DOC-AAAA00000001', 'ENC-TSK-402'],
    el: () => (
      <PlanPrimitive
        record={
          {
            ...base,
            plan_id: 'ENC-PLN-400',
            status: 'started',
            priority: 'P2',
            category: null,
            objectives_set: ['ENC-TSK-401'],
            attached_documents: ['DOC-AAAA00000001'],
            related_task_ids: ['ENC-TSK-402'],
          } as never
        }
      />
    ),
  },
  {
    name: 'lesson',
    own: 'ENC-LSN-500',
    neighbors: ['ENC-TSK-501'],
    el: () => (
      <LessonPrimitive
        record={
          {
            ...base,
            lesson_id: 'ENC-LSN-500',
            status: 'active',
            observation: 'o',
            insight: 'i',
            evidence_chain: ['ENC-TSK-501'],
            provenance: 'p',
            confidence: 0.5,
            pillar_scores: {},
            pillar_composite: 0,
            resonance_score: 0,
            category: 'c',
          } as never
        }
      />
    ),
  },
  {
    name: 'document',
    own: 'DOC-BBBB00000001',
    neighbors: ['ENC-TSK-601', 'DOC-BBBB00000002'],
    el: () => (
      <DocumentPrimitive
        record={
          {
            ...base,
            document_id: 'DOC-BBBB00000001',
            file_name: 'f.md',
            content_type: 'text/markdown',
            keywords: [],
            status: 'active',
            created_by: 'x',
            version: 1,
            related_items: ['ENC-TSK-601', 'DOC-BBBB00000002'],
          } as never
        }
      />
    ),
  },
]

describe('detail pages render ids through RecordLink with a copy control', () => {
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

  const copyFor = (id: string) => container.querySelector(`[aria-label*="${id}"]`)

  for (const c of cases) {
    it(`${c.name}: header id and every neighbor id are a RecordLink followed by a copy button`, () => {
      act(() => root.render(c.el()))
      // header id: RecordLink wrapper with anchor then copy button as siblings
      const wrapper = [...container.querySelectorAll('.enc-record-link-copyable')].find((w) => w.textContent?.includes(c.own))
      expect(wrapper, `${c.own} header wrapper`).toBeTruthy()
      expect(wrapper!.firstElementChild?.tagName).toBe('A')
      expect(wrapper!.lastElementChild?.getAttribute('aria-label')).toContain(c.own)

      const tab = [...container.querySelectorAll<HTMLElement>('[role="tab"]')].find((t) => t.textContent?.includes('Neighbors'))
      expect(tab, 'Neighbors tab').toBeTruthy()
      act(() => tab!.click())
      for (const id of c.neighbors) {
        const w = [...container.querySelectorAll('.ev2-rdh__neighbor-row .enc-record-link-copyable')].find((x) => x.textContent?.includes(id))
        expect(w, `${id} neighbor row`).toBeTruthy()
        expect(w!.querySelector('a')?.textContent).toContain(id)
        expect(w!.lastElementChild?.getAttribute('aria-label')).toContain(id)
      }
      // no inert link-styled id anchors outside RecordLink: every anchor containing an id sits in a copyable wrapper
      for (const a of container.querySelectorAll('a')) {
        if (/\b(?:ENC-[A-Z]{2,5}-\w+|DOC-\w+)\b/.test(a.textContent ?? '')) {
          expect(a.closest('.enc-record-link-copyable'), `anchor "${a.textContent}"`).toBeTruthy()
        }
      }
      expect(copyFor(c.own)).toBeTruthy()
    })
  }

  it('task checkout vital: the owning session id is a copyable RecordLink', () => {
    act(() =>
      root.render(
        <TaskPrimitive
          record={
            {
              ...base,
              task_id: 'ENC-TSK-100',
              status: 'in-progress',
              priority: 'P2',
              assigned_to: null,
              related_task_ids: [],
              related_issue_ids: [],
              related_feature_ids: [],
              checklist_total: 0,
              checklist_done: 0,
              checked_out_by: 'ENC-SES-0AB',
              checkout_state: 'checked_out',
            } as never
          }
        />,
      ),
    )
    const vital = [...container.querySelectorAll('.ev2-rdh__vital')].find((v) => v.textContent?.includes('Checkout'))
    expect(vital?.querySelector('.enc-record-link-copyable [aria-label*="ENC-SES-0AB"]')).toBeTruthy()
  })

  it('typed relationship targets are copyable RecordLinks', () => {
    act(() =>
      root.render(
        <TypedRelationshipSection
          projectId="enceladus"
          edges={[{ target_id: 'ENC-TSK-700', relationship_type: 'depends_on' } as never]}
        />,
      ),
    )
    const w = container.querySelector('.enc-record-link-copyable')
    expect(w?.firstElementChild?.tagName).toBe('A')
    expect(w?.lastElementChild?.getAttribute('aria-label')).toContain('ENC-TSK-700')
  })
})

describe('markdown bodies on detail pages (description, worklog, evidence, document content)', () => {
  const md = 'See ENC-TSK-9 and DOC-488491DADD6C, plus ENC-SES-0JB (no route).'
  it('copyIds adds a copy button right of every id, linked or unlinked', () => {
    const html = renderToStaticMarkup(<KitMarkdownContent text={md} projectId="enceladus" copyIds />)
    expect(html.match(/enc-record-link-copyable/g)).toHaveLength(3)
    for (const id of ['ENC-TSK-9', 'DOC-488491DADD6C', 'ENC-SES-0JB']) expect(html).toContain(`aria-label="Copy ${id}"`)
  })
  it('stays off by default so the legacy parity oracle sees identical DOM', () => {
    expect(renderToStaticMarkup(<KitMarkdownContent text={md} projectId="enceladus" />)).not.toContain('enc-record-link-copyable')
  })
})
