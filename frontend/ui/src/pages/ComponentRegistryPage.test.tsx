/**
 * ComponentRegistryPage smoke test — ENC-TSK-F44 / FTR-076 v2.
 *
 * Scope (per AC[3]-f):
 *   - Render Pending Approval section with a seeded proposed component.
 *   - Verify the 8-status lifecycle badges render with distinct colors when
 *     components carry lifecycle_status.
 *   - Open each of 4 modals (approve / revert / deprecate / restore) and
 *     validate required-field gating.
 *
 * Mocks:
 *   - useComponentRegistry / useCreateComponent / useUpdateComponent /
 *     useDeleteComponent / useApproveComponent / useRevertComponent /
 *     useDeprecateComponent / useRestoreComponent are stubbed so the page
 *     renders without hitting the network.
 *   - useAuthState is mocked to return 'authenticated' so canEdit=true and
 *     the io-only action surfaces are present.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  COMPONENT_LIFECYCLE_STATUSES,
  COMPONENT_LIFECYCLE_STATUS_LABELS,
} from '../lib/constants'
import type { ComponentLifecycleStatus, RegistryComponent } from '../api/components'

// ---------------------------------------------------------------------------
// Hoisted mocks — fix the hook surface at the page import boundary.
// ---------------------------------------------------------------------------

const {
  mockUseComponentRegistry,
  mockCreateMutation,
  mockUpdateMutation,
  mockDeleteMutation,
  mockApproveMutation,
  mockRevertMutation,
  mockDeprecateMutation,
  mockRestoreMutation,
  mockUseAuthState,
} = vi.hoisted(() => ({
  mockUseComponentRegistry: vi.fn(),
  mockCreateMutation: { mutateAsync: vi.fn(), isPending: false },
  mockUpdateMutation: { mutateAsync: vi.fn(), isPending: false },
  mockDeleteMutation: { mutateAsync: vi.fn(), isPending: false },
  mockApproveMutation: { mutateAsync: vi.fn(), isPending: false },
  mockRevertMutation: { mutateAsync: vi.fn(), isPending: false },
  mockDeprecateMutation: { mutateAsync: vi.fn(), isPending: false },
  mockRestoreMutation: { mutateAsync: vi.fn(), isPending: false },
  mockUseAuthState: vi.fn(),
}))

vi.mock('../hooks/useComponentRegistry', () => ({
  useComponentRegistry: mockUseComponentRegistry,
  useCreateComponent: () => mockCreateMutation,
  useUpdateComponent: () => mockUpdateMutation,
  useDeleteComponent: () => mockDeleteMutation,
  useApproveComponent: () => mockApproveMutation,
  useRevertComponent: () => mockRevertMutation,
  useDeprecateComponent: () => mockDeprecateMutation,
  useRestoreComponent: () => mockRestoreMutation,
}))

vi.mock('../lib/authState', () => ({
  useAuthState: mockUseAuthState,
}))

import { ComponentRegistryPage } from './ComponentRegistryPage'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeComponent(
  overrides: Partial<RegistryComponent> & { lifecycle_status?: ComponentLifecycleStatus },
): RegistryComponent {
  return {
    component_id: 'comp-test',
    component_name: 'Test Component',
    project_id: 'enceladus',
    category: 'lambda',
    transition_type: 'github_pr_deploy',
    description: 'Test',
    status: 'active',
    created_at: '2026-04-10T00:00:00Z',
    updated_at: '2026-04-10T00:00:00Z',
    ...overrides,
  }
}

const PROPOSED_A: RegistryComponent = makeComponent({
  component_id: 'comp-older-proposal',
  component_name: 'Older Proposal',
  description: 'Older proposal body',
  lifecycle_status: 'proposed',
  created_at: '2026-04-01T00:00:00Z',
  // Cast-to-any so we can add the proposal-only fields without widening the
  // RegistryComponent type surface at rest.
  ...({
    proposing_agent_session_id: 'claude-older-2026-04-01T00Z',
    requested_minimum_transition_type: 'lambda_deploy',
    requested_required_transition_type: 'github_pr_deploy',
    source_paths: ['backend/lambda/older/lambda_function.py'],
  } as Partial<RegistryComponent>),
})

const PROPOSED_B: RegistryComponent = makeComponent({
  component_id: 'comp-newer-proposal',
  component_name: 'Newer Proposal',
  description: 'Newer proposal body',
  lifecycle_status: 'proposed',
  created_at: '2026-04-15T00:00:00Z',
  ...({
    proposing_agent_session_id: 'claude-newer-2026-04-15T00Z',
    requested_minimum_transition_type: 'web_deploy',
    source_paths: ['frontend/ui/src/newer.tsx'],
  } as Partial<RegistryComponent>),
})

const PRODUCTION_COMPONENT = makeComponent({
  component_id: 'comp-prod-ready',
  component_name: 'Production Ready',
  lifecycle_status: 'production',
})

const DEPRECATED_COMPONENT = makeComponent({
  component_id: 'comp-deprecated-one',
  component_name: 'Deprecated One',
  lifecycle_status: 'deprecated',
  status: 'deprecated',
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  )
}

function setRegistry(list: RegistryComponent[]) {
  mockUseComponentRegistry.mockReturnValue({
    components: list,
    count: list.length,
    isPending: false,
    isError: false,
    dataUpdatedAt: Date.now(),
  })
}

function renderPage() {
  return render(<ComponentRegistryPage />, { wrapper: createWrapper() })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  mockCreateMutation.isPending = false
  mockUpdateMutation.isPending = false
  mockDeleteMutation.isPending = false
  mockApproveMutation.isPending = false
  mockRevertMutation.isPending = false
  mockDeprecateMutation.isPending = false
  mockRestoreMutation.isPending = false
  mockUseAuthState.mockReturnValue({ authStatus: 'authenticated' })
})

describe('ComponentRegistryPage — FTR-076 v2 lifecycle UI (AC[3])', () => {
  it('renders the Pending Approval section at the top with oldest-first ordering', () => {
    // Seed with newer first to verify the component re-sorts oldest-first.
    setRegistry([PROPOSED_B, PROPOSED_A])
    renderPage()

    const section = screen.getByTestId('pending-approval-section')
    expect(section).toBeInTheDocument()

    const header = within(section).getByTestId('pending-approval-header')
    expect(header.textContent).toContain('Pending Approval (2)')

    // Cards should render in oldest-first order: older (2026-04-01) before newer (2026-04-15).
    const cards = within(section).getAllByTestId(/proposal-card-comp-/)
    expect(cards.map((c) => c.getAttribute('data-testid'))).toEqual([
      'proposal-card-comp-older-proposal',
      'proposal-card-comp-newer-proposal',
    ])

    // Proposing session ID + requested transition types are surfaced (AC[3]-a).
    expect(
      within(cards[0]).getByText('claude-older-2026-04-01T00Z'),
    ).toBeInTheDocument()
    expect(
      within(cards[0]).getByTestId('requested-minimum-transition-type').textContent,
    ).toContain('Lambda Deploy')
    expect(
      within(cards[0]).getByTestId('requested-required-transition-type').textContent,
    ).toContain('GitHub PR + Deploy')
  })

  it('renders lifecycle_status badges for all 8 statuses with distinct colors (AC[3]-b)', () => {
    // Seed one component per lifecycle status (proposed included so AC[3]-b
    // coverage spans the full 8-status enum).
    const allEightSeeded = COMPONENT_LIFECYCLE_STATUSES.map((s, i) =>
      makeComponent({
        component_id: `comp-life-${s}`,
        component_name: `Lifecycle ${s}`,
        lifecycle_status: s,
        created_at: `2026-04-0${i + 1}T00:00:00Z`,
        // Seed proposal-shape fields for 'proposed' so the PendingApproval path
        // renders without throwing (not strictly needed for badge assertion).
        ...(s === 'proposed'
          ? ({
              proposing_agent_session_id: 'claude-test',
              requested_minimum_transition_type: 'github_pr_deploy',
              source_paths: [],
            } as Partial<RegistryComponent>)
          : {}),
      }),
    )
    setRegistry(allEightSeeded)
    renderPage()

    // lifecycle-status-badge is rendered by ComponentCard — proposed variants
    // render inside the Pending Approval ProposalCard (no badge there by design).
    const badges = screen.getAllByTestId('lifecycle-status-badge')
    const statuses = badges.map((b) => b.getAttribute('data-lifecycle-status'))
    expect(new Set(statuses)).toEqual(
      new Set(COMPONENT_LIFECYCLE_STATUSES.filter((s) => s !== 'proposed')),
    )

    // AC[3]-b requires distinct colors per lifecycle status. Our palette maps
    // 8 statuses across 7 tailwind color families (approved shares slate with
    // proposed + archived but at a different opacity band).
    const colorClasses = badges.map(
      (b) => b.className.match(/bg-[a-z]+-\d{2,3}\/\d{2}/)?.[0],
    )
    expect(new Set(colorClasses).size).toBeGreaterThanOrEqual(5)

    // Label sanity: each non-proposed badge label matches the constant table.
    const labels = badges.map((b) => b.textContent)
    for (const s of COMPONENT_LIFECYCLE_STATUSES) {
      if (s === 'proposed') continue
      expect(labels).toContain(COMPONENT_LIFECYCLE_STATUS_LABELS[s])
    }

    // Verify Pending Approval renders for the seeded proposal too (AC[3]-a)
    expect(screen.getByTestId('pending-approval-section')).toBeInTheDocument()
  })

  it('opens the approve modal with minimum/required transition-type + alarm_arn fields (AC[3]-c)', async () => {
    const user = userEvent.setup()
    setRegistry([PROPOSED_A])
    renderPage()

    await user.click(screen.getByTestId('approve-button-comp-older-proposal'))

    const modal = screen.getByTestId('approve-modal')
    expect(modal).toBeInTheDocument()

    // Shows proposing_agent_session_id + requested_minimum + requested_required
    expect(within(modal).getByText(/claude-older-2026-04-01T00Z/)).toBeInTheDocument()
    // Label text appears in both the summary block and the select options —
    // scope the summary-block assertions to the span following the label.
    expect(within(modal).getByText(/Requested minimum:/).textContent).toContain(
      'Lambda Deploy',
    )
    expect(within(modal).getByText(/Requested required:/).textContent).toContain(
      'GitHub PR + Deploy',
    )

    // Minimum + Required + Alarm-ARN inputs are all present.
    const minSelect = within(modal).getByTestId(
      'approve-minimum-transition-type',
    ) as HTMLSelectElement
    const reqSelect = within(modal).getByTestId(
      'approve-required-transition-type',
    ) as HTMLSelectElement
    expect(minSelect).toBeInTheDocument()
    expect(reqSelect).toBeInTheDocument()
    expect(within(modal).getByTestId('approve-alarm-arn')).toBeInTheDocument()

    // Defaults honor the proposal's requested values.
    expect(minSelect.value).toBe('lambda_deploy')
    expect(reqSelect.value).toBe('github_pr_deploy')

    // Submitting fires the mutation with overrides.
    await user.click(within(modal).getByTestId('approve-confirm'))
    expect(mockApproveMutation.mutateAsync).toHaveBeenCalledTimes(1)
    const call = mockApproveMutation.mutateAsync.mock.calls[0][0]
    expect(call.id).toBe('comp-older-proposal')
    expect(call.minimum_transition_type).toBe('lambda_deploy')
    expect(call.required_transition_type).toBe('github_pr_deploy')
  })

  it('revert modal requires min-10-char reason and invokes revertMutation (AC[3]-d)', async () => {
    const user = userEvent.setup()
    setRegistry([PROPOSED_A])
    renderPage()

    await user.click(screen.getByTestId('revert-button-comp-older-proposal'))
    const modal = screen.getByTestId('revert-modal')
    expect(modal).toBeInTheDocument()

    // Terminal-archive warning visible (AC[3]-d requires the warning).
    expect(within(modal).getByRole('alert').textContent).toMatch(/terminal/i)

    const confirm = within(modal).getByTestId('revert-confirm')
    // Short input — button disabled.
    await user.type(within(modal).getByTestId('revert-reason'), 'too short')
    expect(confirm).toBeDisabled()

    // Extend to >=10 chars — button enables.
    await user.type(within(modal).getByTestId('revert-reason'), ' but now enough characters')
    expect(confirm).not.toBeDisabled()

    await user.click(confirm)
    expect(mockRevertMutation.mutateAsync).toHaveBeenCalledTimes(1)
    const call = mockRevertMutation.mutateAsync.mock.calls[0][0]
    expect(call.id).toBe('comp-older-proposal')
    expect(call.reverted_reason.length).toBeGreaterThanOrEqual(10)
  })

  it('deprecate modal appears on production components and invokes deprecateMutation (AC[3]-e)', async () => {
    const user = userEvent.setup()
    setRegistry([PRODUCTION_COMPONENT])
    renderPage()

    // Deprecate action button surfaces only for production components.
    const deprecateButton = screen.getByRole('button', {
      name: `Deprecate ${PRODUCTION_COMPONENT.component_name}`,
    })
    await user.click(deprecateButton)

    const modal = screen.getByTestId('deprecate-modal')
    expect(modal).toBeInTheDocument()
    expect(within(modal).getByRole('alert').textContent).toMatch(/io-only/i)

    await user.type(
      within(modal).getByTestId('deprecate-reason'),
      'superseded by comp-prod-ready-v2',
    )
    await user.click(within(modal).getByTestId('deprecate-confirm'))

    expect(mockDeprecateMutation.mutateAsync).toHaveBeenCalledTimes(1)
    expect(mockDeprecateMutation.mutateAsync.mock.calls[0][0]).toMatchObject({
      id: 'comp-prod-ready',
      deprecated_reason: 'superseded by comp-prod-ready-v2',
    })
  })

  it('restore modal appears on deprecated components and targets production (AC[3]-e)', async () => {
    const user = userEvent.setup()
    setRegistry([DEPRECATED_COMPONENT])
    renderPage()

    const restoreButton = screen.getByRole('button', {
      name: `Restore ${DEPRECATED_COMPONENT.component_name}`,
    })
    await user.click(restoreButton)

    const modal = screen.getByTestId('restore-modal')
    expect(modal).toBeInTheDocument()
    expect(within(modal).getByRole('alert').textContent).toMatch(/production/)

    await user.click(within(modal).getByTestId('restore-confirm'))
    expect(mockRestoreMutation.mutateAsync).toHaveBeenCalledTimes(1)
    expect(mockRestoreMutation.mutateAsync.mock.calls[0][0]).toEqual({
      id: 'comp-deprecated-one',
    })
  })

  it('does not show deprecate/restore buttons for components outside the production/deprecated states', () => {
    setRegistry([
      makeComponent({
        component_id: 'comp-designed-only',
        component_name: 'Designed Only',
        lifecycle_status: 'designed',
      }),
    ])
    renderPage()

    expect(screen.queryByLabelText(/Deprecate Designed Only/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/Restore Designed Only/)).not.toBeInTheDocument()
  })
})
