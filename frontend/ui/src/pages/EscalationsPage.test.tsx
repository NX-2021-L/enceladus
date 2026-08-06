/**
 * EscalationsPage tests — ENC-TSK-J70 / ENC-FTR-121 Ph3 (DOC-5B888FCA43B8 §5.7).
 *
 * Scope (AC-5, AC-7):
 *   - Feed renders pending escalations newest-first with target id, mutation
 *     type, requesting agent, justification, and the fresh diff.
 *   - The drift warning renders prominently when diff.drift.detected.
 *   - Approve / Deny / Deny-with-guidance wire to the API module.
 *   - Terminal escalations render inside the collapsed History section.
 *
 * ENC-TSK-N81 / ENC-ISS-594 additionally covers:
 *   - Pending merges every project's queue into one inbox (non-ENC included).
 *   - Approve/deny route to the escalation's OWN project_id.
 *   - A failing project degrades to a partial-result warning, not ErrorState.
 *
 * Mocks: the api/escalations module is stubbed at the import boundary so the
 * page renders without the network; approval calls are asserted on the mock.
 * The projects feed is stubbed too — it drives the pending fan-out.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { EscalationItem, EscalationsFeedResponse } from '../api/escalations'

const { mockFetchEscalations, mockFetchInbox, mockApprove, mockDeny, mockFetchProjects } =
  vi.hoisted(() => ({
    mockFetchEscalations: vi.fn(),
    mockFetchInbox: vi.fn(),
    mockApprove: vi.fn(),
    mockDeny: vi.fn(),
    mockFetchProjects: vi.fn(),
  }))

vi.mock('../api/escalations', async (importOriginal) => {
  const original = await importOriginal<typeof import('../api/escalations')>()
  return {
    ...original,
    fetchEscalations: mockFetchEscalations,
    fetchEscalationsInbox: mockFetchInbox,
    approveEscalation: mockApprove,
    denyEscalation: mockDeny,
  }
})

// The projects feed drives the pending fan-out (ENC-TSK-N81).
vi.mock('../api/feeds', async (importOriginal) => {
  const original = await importOriginal<typeof import('../api/feeds')>()
  return { ...original, fetchProjects: mockFetchProjects }
})

import { EscalationsPage } from './EscalationsPage'

function pendingEscalation(overrides: Partial<EscalationItem> = {}): EscalationItem {
  return {
    item_id: 'ENC-ESC-001',
    project_id: 'enceladus',
    status: 'requested',
    mutation_type: 'deploy_arc_change',
    target_record_id: 'ENC-TSK-J10',
    justification: 'Arc misclassified at create; no deployable artifact.',
    payload: { new_deploy_arc_type: 'code_only' },
    requested_by: { session_id: 'ENC-SES-02F' },
    created_at: '2026-07-02T04:00:00Z',
    updated_at: '2026-07-02T04:00:00Z',
    diff: {
      mutation_type: 'deploy_arc_change',
      field: 'transition_type',
      current: 'github_pr_deploy',
      requested: 'code_only',
      target_snapshot: {
        title: 'Full CFN drift close-out',
        status: 'in-progress',
        transition_type: 'github_pr_deploy',
        sync_version: 4,
        updated_at: '2026-07-02T03:00:00Z',
      },
    },
    ...overrides,
  }
}

function feed(overrides: Partial<EscalationsFeedResponse> = {}): EscalationsFeedResponse {
  return {
    success: true,
    project_id: 'enceladus',
    pending: [pendingEscalation()],
    terminal: [
      pendingEscalation({
        item_id: 'ENC-ESC-000',
        status: 'denied_with_guidance',
        guidance_note: 'Use a successor task instead.',
        diff: undefined,
      }),
    ],
    count: 2,
    ...overrides,
  }
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return render(<EscalationsPage />, { wrapper })
}

function inbox(overrides: Partial<{
  pending: EscalationItem[]
  scanned: string[]
  failed: string[]
}> = {}) {
  return {
    pending: [pendingEscalation()],
    scanned: ['enceladus', 'intelligence'],
    failed: [],
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchProjects.mockResolvedValue({
    generated_at: '2026-08-06T07:00:00Z',
    projects: [{ project_id: 'enceladus' }, { project_id: 'intelligence' }],
  })
  mockFetchInbox.mockResolvedValue(inbox())
  mockFetchEscalations.mockResolvedValue(feed())
  mockApprove.mockResolvedValue({
    success: true,
    escalation_id: 'ENC-ESC-001',
    status: 'applied',
    applied: true,
  })
  mockDeny.mockResolvedValue({
    success: true,
    escalation_id: 'ENC-ESC-001',
    status: 'denied',
  })
})

describe('EscalationsPage', () => {
  it('renders pending cards with target, mutation type, requester, justification, and diff', async () => {
    renderPage()
    const card = await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(within(card).getByText('ENC-TSK-J10')).toBeInTheDocument()
    expect(within(card).getByText('deploy_arc_change')).toBeInTheDocument()
    expect(within(card).getByText('ENC-SES-02F')).toBeInTheDocument()
    expect(
      within(card).getByText('Arc misclassified at create; no deployable artifact.'),
    ).toBeInTheDocument()
    const diff = within(card).getByTestId('escalation-diff')
    expect(within(diff).getByText('github_pr_deploy')).toBeInTheDocument()
    expect(within(diff).getByText('code_only')).toBeInTheDocument()
  })

  it('shows a prominent drift warning when expected_version mismatches', async () => {
    mockFetchInbox.mockResolvedValue(
      inbox({
        pending: [
          pendingEscalation({
            diff: {
              mutation_type: 'deploy_arc_change',
              field: 'transition_type',
              current: 'github_pr_deploy',
              requested: 'code_only',
              drift: {
                expected_version: 'sync_version:3',
                current_sync_version: '7',
                current_updated_at: '2026-07-02T04:10:00Z',
                detected: true,
              },
            },
          }),
        ],
      }),
    )
    renderPage()
    const warning = await screen.findByTestId('drift-warning')
    expect(warning.textContent).toContain('drifted')
    expect(warning.textContent).toContain('sync_version:3')
  })

  it('does not render a drift warning without drift', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(screen.queryByTestId('drift-warning')).toBeNull()
  })

  it('approve button calls approveEscalation with the escalation id', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(mockApprove).toHaveBeenCalledWith('enceladus', 'ENC-ESC-001')
  })

  it('deny button calls denyEscalation without a guidance note', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Deny' }))
    expect(mockDeny).toHaveBeenCalledWith('enceladus', 'ENC-ESC-001', undefined)
  })

  it('deny-with-guidance sends the note', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Deny with guidance' }))
    await userEvent.type(
      screen.getByLabelText('Guidance note'),
      'Open a successor task instead.',
    )
    await userEvent.click(screen.getByRole('button', { name: 'Send denial' }))
    expect(mockDeny).toHaveBeenCalledWith(
      'enceladus',
      'ENC-ESC-001',
      'Open a successor task instead.',
    )
  })

  it('terminal escalations render in the collapsed History audit section', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    const history = screen.getByTestId('terminal-section')
    expect(within(history).getByText('History (1)')).toBeInTheDocument()
    expect(within(history).getByText('ENC-ESC-000')).toBeInTheDocument()
    expect(within(history).getByText(/Use a successor task instead\./)).toBeInTheDocument()
  })

  it('renders the empty state when nothing is pending', async () => {
    mockFetchInbox.mockResolvedValue(inbox({ pending: [] }))
    mockFetchEscalations.mockResolvedValue(feed({ pending: [], terminal: [] }))
    renderPage()
    expect(await screen.findByText('No pending escalations.')).toBeInTheDocument()
  })

  // ENC-TSK-N81 / ENC-ISS-594 — the all-projects inbox.

  it('fans the pending queue out across every project from the projects feed', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(mockFetchInbox).toHaveBeenCalledWith(['enceladus', 'intelligence'])
  })

  it('renders non-ENC escalations in the same pending inbox, labelled by project', async () => {
    mockFetchInbox.mockResolvedValue(
      inbox({
        pending: [
          pendingEscalation({
            item_id: 'INT-ESC-001',
            project_id: 'intelligence',
            target_record_id: 'INT-TSK-182',
            mutation_type: 'direct_state_override',
          }),
          pendingEscalation(),
        ],
      }),
    )
    renderPage()
    const card = await screen.findByTestId('escalation-card-INT-ESC-001')
    expect(within(card).getByTestId('escalation-project').textContent).toBe('intelligence')
    expect(within(card).getByText('INT-TSK-182')).toBeInTheDocument()
    // The ENC item still renders alongside it — one inbox, not a swap.
    expect(screen.getByTestId('escalation-card-ENC-ESC-001')).toBeInTheDocument()
  })

  it('approves a non-ENC escalation against its OWN project_id', async () => {
    mockFetchInbox.mockResolvedValue(
      inbox({
        pending: [pendingEscalation({ item_id: 'INT-ESC-001', project_id: 'intelligence' })],
      }),
    )
    renderPage()
    await screen.findByTestId('escalation-card-INT-ESC-001')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(mockApprove).toHaveBeenCalledWith('intelligence', 'INT-ESC-001')
  })

  it('denies a non-ENC escalation against its OWN project_id', async () => {
    mockFetchInbox.mockResolvedValue(
      inbox({
        pending: [pendingEscalation({ item_id: 'INT-ESC-004', project_id: 'intelligence' })],
      }),
    )
    renderPage()
    await screen.findByTestId('escalation-card-INT-ESC-004')
    await userEvent.click(screen.getByRole('button', { name: 'Deny with guidance' }))
    await userEvent.type(screen.getByLabelText('Guidance note'), 'Descope instead.')
    await userEvent.click(screen.getByRole('button', { name: 'Send denial' }))
    expect(mockDeny).toHaveBeenCalledWith('intelligence', 'INT-ESC-004', 'Descope instead.')
  })

  it('warns about unreadable projects instead of blanking the whole queue', async () => {
    mockFetchInbox.mockResolvedValue(
      inbox({ scanned: ['enceladus'], failed: ['intelligence'] }),
    )
    renderPage()
    const warning = await screen.findByTestId('partial-failure-warning')
    expect(warning.textContent).toContain('intelligence')
    // The escalations that DID load are still decidable.
    expect(screen.getByTestId('escalation-card-ENC-ESC-001')).toBeInTheDocument()
    expect(screen.queryByText('Something went wrong')).toBeNull()
  })

  it('states the coverage it actually achieved', async () => {
    renderPage()
    const coverage = await screen.findByTestId('inbox-coverage')
    expect(coverage.textContent).toContain('2 projects')
  })

  it('keeps History project-scoped and switchable', async () => {
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(mockFetchEscalations).toHaveBeenCalledWith('enceladus')
    await userEvent.selectOptions(screen.getByLabelText('History project'), 'intelligence')
    expect(mockFetchEscalations).toHaveBeenCalledWith('intelligence')
  })

  it('falls back to the home project when the projects feed is unavailable', async () => {
    mockFetchProjects.mockRejectedValue(new Error('feed down'))
    renderPage()
    await screen.findByTestId('escalation-card-ENC-ESC-001')
    expect(mockFetchInbox).toHaveBeenCalledWith(['enceladus'])
  })
})
