import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { EscalationItem, EscalationsFeed } from '../api/escalations'
import type { ProjectSummary } from '../api/projects'

/**
 * ENC-TSK-P98 (ENC-ISS-773). No @testing-library/react in this package —
 * createRoot + act, matching src/components/DocumentSectionsView.test.tsx /
 * src/hooks/useRecordMutation.test.tsx (the established pattern for routes
 * backed by TanStack Query).
 *
 * RecordLink is mocked to a plain span: it renders a @tanstack/react-router
 * `Link` whenever an id resolves to a route (every session id does, via the
 * SES prefix, regardless of the project registry), and no test in this
 * package builds a live RouterProvider tree — see
 * src/components/MarkdownContent.test.tsx's note on the same constraint.
 */

vi.mock('../api/projects', async () => {
  const actual = await vi.importActual<typeof import('../api/projects')>('../api/projects')
  return { ...actual, fetchProjectsList: vi.fn() }
})

vi.mock('../api/escalations', async () => {
  const actual = await vi.importActual<typeof import('../api/escalations')>('../api/escalations')
  return {
    ...actual,
    fetchEscalationsFeed: vi.fn(),
    approveEscalation: vi.fn(),
    denyEscalation: vi.fn(),
  }
})

vi.mock('../components/RecordLink', () => ({
  RecordLink: ({ id }: { id: string }) => <span>{id}</span>,
}))

import { fetchProjectsList } from '../api/projects'
import { approveEscalation, denyEscalation, fetchEscalationsFeed } from '../api/escalations'
import { EscalationsRoute } from './EscalationsRoute'

const PROJECTS: ProjectSummary[] = [
  { project_id: 'enceladus', prefix: 'ENC' },
  { project_id: 'devops', prefix: 'DVP' },
]

function item(overrides: Partial<EscalationItem> = {}): EscalationItem {
  return {
    item_id: 'ENC-ESC-090',
    project_id: 'enceladus',
    status: 'requested',
    mutation_type: 'deploy_arc_change',
    target_record_id: 'ENC-TSK-O12',
    justification: 'Arc is structurally unsatisfiable',
    payload: { target_status: 'closed' },
    requested_by: { session_id: 'ENC-SES-0EV', agent_type_id: 'ENC-AGT-006' },
    created_at: '2026-09-16T11:30:00Z',
    ...overrides,
  }
}

function feed(overrides: Partial<EscalationsFeed> = {}): EscalationsFeed {
  return {
    success: true,
    project_id: 'enceladus',
    pending: [],
    terminal: [],
    count: 0,
    ...overrides,
  }
}

/** Devops has one pending, decidable escalation (DVP-ESC-002 -> DVP-TSK-766).
 *  Enceladus has none pending — only terminal rows — the exact shape ISS-773
 *  describes: 0 in the header while a real approval sat waiting on devops. */
function mockTwoProjectFeeds() {
  vi.mocked(fetchProjectsList).mockResolvedValue(PROJECTS)
  vi.mocked(fetchEscalationsFeed).mockImplementation(async (projectId: string) => {
    if (projectId === 'enceladus') {
      return feed({
        project_id: 'enceladus',
        terminal: [
          item({ item_id: 'ENC-ESC-091', status: 'applied', created_at: '2026-09-15T00:00:00Z' }),
          item({
            item_id: 'ENC-ESC-092',
            status: 'denied',
            created_at: '2026-09-14T00:00:00Z',
          }),
        ],
        count: 2,
      })
    }
    if (projectId === 'devops') {
      return feed({
        project_id: 'devops',
        pending: [
          item({
            item_id: 'DVP-ESC-002',
            project_id: 'devops',
            target_record_id: 'DVP-TSK-766',
            status: 'requested',
            created_at: '2026-09-16T12:00:00Z',
          }),
        ],
        count: 1,
      })
    }
    throw new Error(`unexpected project_id ${projectId}`)
  })
}

describe('EscalationsRoute — cross-project aggregation (ENC-ISS-773)', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.clearAllMocks()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  // TanStack Query's observer notification needs at least one real macrotask
  // tick to flush in this jsdom/vitest setup (see DocumentSectionsView.test.tsx);
  // two sequential queries here (project registry, then the per-project feeds
  // it gates) need a couple of rounds.
  async function flush(times = 4) {
    for (let i = 0; i < times; i++) {
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 0))
      })
    }
  }

  async function renderRoute() {
    await act(async () => {
      root.render(
        <QueryClientProvider client={qc}>
          <EscalationsRoute />
        </QueryClientProvider>,
      )
    })
    await flush()
  }

  it('merges every project into one queue: DVP-ESC-002 shows on the Pending tab and the header counts it', async () => {
    mockTwoProjectFeeds()
    await renderRoute()

    expect(fetchEscalationsFeed).toHaveBeenCalledWith('enceladus', expect.anything())
    expect(fetchEscalationsFeed).toHaveBeenCalledWith('devops', expect.anything())

    expect(container.textContent).toContain('(1 pending)')
    expect(container.textContent).toContain('DVP-ESC-002')
    // The project badge column identifies which project filed it.
    expect(container.textContent).toContain('devops')
  })

  it('the project filter hides devops rows when set to enceladus', async () => {
    mockTwoProjectFeeds()
    await renderRoute()
    expect(container.textContent).toContain('DVP-ESC-002')

    const trigger = container.querySelector('.ev2-select__trigger') as HTMLButtonElement
    expect(trigger).toBeTruthy()
    await act(async () => {
      trigger.click()
    })

    const enceladusOption = Array.from(container.querySelectorAll('[role="option"]')).find(
      (el) => el.textContent === 'enceladus',
    ) as HTMLElement
    expect(enceladusOption).toBeTruthy()
    await act(async () => {
      enceladusOption.click()
    })
    await flush(1)

    expect(container.textContent).not.toContain('DVP-ESC-002')
  })

  it('approving a devops row decides it against the devops route, not enceladus', async () => {
    mockTwoProjectFeeds()
    vi.mocked(approveEscalation).mockResolvedValue({
      success: true,
      escalation_id: 'DVP-ESC-002',
      status: 'approved',
      applied: true,
    })
    await renderRoute()

    const idButton = Array.from(container.querySelectorAll('button')).find(
      (b) => b.textContent === 'DVP-ESC-002',
    ) as HTMLButtonElement
    await act(async () => {
      idButton.click()
    })
    const approveButton = Array.from(container.querySelectorAll('button')).find((b) =>
      (b.textContent ?? '').includes('Approve & apply'),
    ) as HTMLButtonElement
    await act(async () => {
      approveButton.click()
    })
    await flush(1)

    expect(approveEscalation).toHaveBeenCalledWith('devops', 'DVP-ESC-002')
  })

  it('does not blank the page when one project feed fails — the others still render', async () => {
    vi.mocked(fetchProjectsList).mockResolvedValue(PROJECTS)
    vi.mocked(fetchEscalationsFeed).mockImplementation(async (projectId: string) => {
      if (projectId === 'enceladus') {
        return feed({
          project_id: 'enceladus',
          pending: [item({ item_id: 'ENC-ESC-500', status: 'requested' })],
          count: 1,
        })
      }
      throw new Error('devops feed unavailable (500)')
    })

    await renderRoute()

    expect(container.textContent).toContain('ENC-ESC-500')
    expect(container.textContent).toContain('Some projects did not load')
    expect(container.textContent).toContain('devops')
  })
})
