/**
 * ComponentRegistryPage — ENC-FTR-041 Component Registry UI
 *
 * Lists all registered components with filters for project, category, and status.
 * Authenticated users (Cognito session) can create, edit, and delete components.
 * transition_type edits are enforced server-side as Cognito-only.
 */

import { useState, useMemo, useCallback } from 'react'
import { createPortal } from 'react-dom'
import {
  useComponentRegistry,
  useCreateComponent,
  useUpdateComponent,
  useDeleteComponent,
  useApproveComponent,
  useRejectComponent,
} from '../hooks/useComponentRegistry'
import { LoadingState } from '../components/shared/LoadingState'
import { ErrorState } from '../components/shared/ErrorState'
import { EmptyState } from '../components/shared/EmptyState'
import { FreshnessBadge } from '../components/shared/FreshnessBadge'
import { useAuthState } from '../lib/authState'
import {
  COMPONENT_CATEGORIES,
  COMPONENT_CATEGORY_LABELS,
  COMPONENT_CATEGORY_COLORS,
  COMPONENT_TRANSITION_TYPES,
  COMPONENT_TRANSITION_TYPE_LABELS,
  COMPONENT_TRANSITION_TYPE_COLORS,
  COMPONENT_STATUSES,
  STATUS_COLORS,
  STATUS_LABELS,
} from '../lib/constants'
import type {
  RegistryComponent,
  ComponentCategory,
  ComponentStatus,
  ComponentTransitionType,
  ComponentProposal,
  CreateComponentInput,
  UpdateComponentInput,
} from '../api/components'

// ---------------------------------------------------------------------------
// Filter types
// ---------------------------------------------------------------------------

interface FilterState {
  project_id: string
  category: ComponentCategory | ''
  status: ComponentStatus | ''
}

const DEFAULT_FILTERS: FilterState = {
  project_id: '',
  category: '',
  status: 'active',
}

// ---------------------------------------------------------------------------
// ComponentCard
// ---------------------------------------------------------------------------

interface ComponentCardProps {
  component: RegistryComponent
  canEdit: boolean
  onEdit: (c: RegistryComponent) => void
  onDelete: (c: RegistryComponent) => void
}

function ComponentCard({ component, canEdit, onEdit, onDelete }: ComponentCardProps) {
  const categoryColor =
    COMPONENT_CATEGORY_COLORS[component.category] ?? 'bg-slate-500/20 text-slate-400'
  const transitionColor =
    COMPONENT_TRANSITION_TYPE_COLORS[component.transition_type] ??
    'bg-slate-500/20 text-slate-400'
  const statusColor =
    STATUS_COLORS[component.status] ?? 'bg-slate-500/20 text-slate-400'

  return (
    <div className="bg-slate-800/60 border border-slate-700/60 rounded-lg p-4 space-y-3 hover:border-slate-600/80 transition-colors">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-slate-100 truncate">{component.component_name}</h3>
          <p className="text-xs text-slate-500 font-mono mt-0.5 truncate">{component.component_id}</p>
        </div>
        {canEdit && (
          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={() => onEdit(component)}
              aria-label={`Edit ${component.component_name}`}
              className="p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700/60 rounded transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            </button>
            <button
              onClick={() => onDelete(component)}
              aria-label={`Delete ${component.component_name}`}
              className="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
        )}
      </div>

      {/* Badges row */}
      <div className="flex flex-wrap gap-1.5">
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${categoryColor}`}>
          {COMPONENT_CATEGORY_LABELS[component.category] ?? component.category}
        </span>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${transitionColor}`}>
          {COMPONENT_TRANSITION_TYPE_LABELS[component.transition_type] ?? component.transition_type}
        </span>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${statusColor}`}>
          {STATUS_LABELS[component.status] ?? component.status}
        </span>
      </div>

      {/* Description */}
      {component.description && (
        <p className="text-xs text-slate-400 line-clamp-2">{component.description}</p>
      )}

      {/* Footer row */}
      <div className="flex items-center justify-between text-xs text-slate-600">
        <span className="font-mono">{component.project_id}</span>
        {component.github_repo && (
          <a
            href={`https://github.com/${component.github_repo}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-slate-500 hover:text-slate-300 transition-colors truncate max-w-[180px]"
          >
            {component.github_repo}
          </a>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ComponentModal — Create / Edit
// ---------------------------------------------------------------------------

interface ComponentFormState {
  component_id: string
  component_name: string
  project_id: string
  category: ComponentCategory
  transition_type: ComponentTransitionType
  description: string
  github_repo: string
  status: ComponentStatus
}

const BLANK_FORM: ComponentFormState = {
  component_id: '',
  component_name: '',
  project_id: '',
  category: 'lambda',
  transition_type: 'github_pr_deploy',
  description: '',
  github_repo: '',
  status: 'active',
}

function componentToForm(c: RegistryComponent): ComponentFormState {
  return {
    component_id: c.component_id,
    component_name: c.component_name,
    project_id: c.project_id,
    category: c.category,
    transition_type: c.transition_type,
    description: c.description,
    github_repo: c.github_repo ?? '',
    status: c.status,
  }
}

interface ComponentModalProps {
  editing: RegistryComponent | null
  onClose: () => void
  onCreate: (data: CreateComponentInput) => Promise<void>
  onUpdate: (id: string, data: UpdateComponentInput) => Promise<void>
  isSubmitting: boolean
}

function ComponentModal({ editing, onClose, onCreate, onUpdate, isSubmitting }: ComponentModalProps) {
  const [form, setForm] = useState<ComponentFormState>(
    editing ? componentToForm(editing) : BLANK_FORM,
  )
  const [error, setError] = useState<string | null>(null)

  const set = useCallback(
    <K extends keyof ComponentFormState>(key: K, value: ComponentFormState[K]) =>
      setForm((prev) => ({ ...prev, [key]: value })),
    [],
  )

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      if (editing) {
        const update: UpdateComponentInput = {
          component_name: form.component_name,
          project_id: form.project_id,
          category: form.category,
          transition_type: form.transition_type,
          description: form.description,
          github_repo: form.github_repo || undefined,
          status: form.status,
        }
        await onUpdate(editing.component_id, update)
      } else {
        const create: CreateComponentInput = {
          component_id: form.component_id,
          component_name: form.component_name,
          project_id: form.project_id,
          category: form.category,
          transition_type: form.transition_type,
          description: form.description,
          github_repo: form.github_repo || undefined,
          status: form.status,
        }
        await onCreate(create)
      }
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4"
      role="dialog"
      aria-modal
      aria-label={editing ? 'Edit Component' : 'Register Component'}
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden
      />

      {/* Panel */}
      <form
        onSubmit={handleSubmit}
        className="relative z-10 w-full sm:max-w-lg bg-slate-900 border border-slate-700 rounded-t-2xl sm:rounded-xl shadow-2xl max-h-[90vh] overflow-y-auto"
      >
        <div className="sticky top-0 bg-slate-900 border-b border-slate-800 px-4 py-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">
            {editing ? 'Edit Component' : 'Register Component'}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 p-1 rounded"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Component ID (create only) */}
          {!editing && (
            <Field label="Component ID" hint="slug format: comp-{name}">
              <input
                type="text"
                value={form.component_id}
                onChange={(e) => set('component_id', e.target.value)}
                placeholder="comp-my-service"
                required
                pattern="comp-[a-z0-9_\-]+"
                className="input-field font-mono"
              />
            </Field>
          )}

          <Field label="Component Name">
            <input
              type="text"
              value={form.component_name}
              onChange={(e) => set('component_name', e.target.value)}
              placeholder="My Service Lambda"
              required
              className="input-field"
            />
          </Field>

          <Field label="Project ID">
            <input
              type="text"
              value={form.project_id}
              onChange={(e) => set('project_id', e.target.value)}
              placeholder="enceladus"
              required
              className="input-field font-mono"
            />
          </Field>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Category">
              <select
                value={form.category}
                onChange={(e) => set('category', e.target.value as ComponentCategory)}
                className="input-field"
              >
                {COMPONENT_CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {COMPONENT_CATEGORY_LABELS[c]}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Status">
              <select
                value={form.status}
                onChange={(e) => set('status', e.target.value as ComponentStatus)}
                className="input-field"
              >
                {COMPONENT_STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </Field>
          </div>

          <Field
            label="Transition Type"
            hint="Strictness enforced by checkout service — Cognito auth required to change"
          >
            <select
              value={form.transition_type}
              onChange={(e) => set('transition_type', e.target.value as ComponentTransitionType)}
              className="input-field"
            >
              {COMPONENT_TRANSITION_TYPES.map((t) => (
                <option key={t} value={t}>
                  {COMPONENT_TRANSITION_TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </Field>

          <Field label="Description">
            <textarea
              value={form.description}
              onChange={(e) => set('description', e.target.value)}
              placeholder="What does this component do?"
              rows={2}
              className="input-field resize-none"
            />
          </Field>

          <Field label="GitHub Repo" hint="Optional — e.g. NX-2021-L/enceladus">
            <input
              type="text"
              value={form.github_repo}
              onChange={(e) => set('github_repo', e.target.value)}
              placeholder="owner/repo"
              className="input-field font-mono"
            />
          </Field>

          {error && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded p-3">
              {error}
            </p>
          )}
        </div>

        <div className="sticky bottom-0 bg-slate-900 border-t border-slate-800 px-4 py-3 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm text-slate-300 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
          >
            {isSubmitting ? 'Saving…' : editing ? 'Save Changes' : 'Register'}
          </button>
        </div>
      </form>
    </div>
  )
}

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-slate-400">
        {label}
        {hint && <span className="ml-1 text-slate-600 font-normal">— {hint}</span>}
      </label>
      {children}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Delete Confirm Modal
// ---------------------------------------------------------------------------

interface DeleteConfirmProps {
  component: RegistryComponent
  onConfirm: () => void
  onCancel: () => void
  isDeleting: boolean
}

function DeleteConfirmModal({ component, onConfirm, onCancel, isDeleting }: DeleteConfirmProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onCancel} aria-hidden />
      <div className="relative z-10 w-full max-w-sm bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-2xl">
        <h2 className="text-sm font-semibold text-slate-100 mb-2">Delete Component</h2>
        <p className="text-xs text-slate-400 mb-1">
          Are you sure you want to delete{' '}
          <span className="text-slate-200 font-medium">{component.component_name}</span>?
        </p>
        <p className="text-xs text-slate-500 mb-4 font-mono">{component.component_id}</p>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-slate-300 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isDeleting}
            className="px-4 py-2 text-sm font-medium text-white bg-rose-600 hover:bg-rose-500 disabled:opacity-50 rounded-lg transition-colors"
          >
            {isDeleting ? 'Deleting…' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ENC-FTR-076 Phase 6: Pending Approval UI
// ---------------------------------------------------------------------------

function ProposalCard({
  proposal,
  canAct,
  onApprove,
  onReject,
}: {
  proposal: ComponentProposal
  canAct: boolean
  onApprove: (p: ComponentProposal) => void
  onReject: (p: ComponentProposal) => void
}) {
  return (
    <div className="bg-amber-900/20 border border-amber-500/30 rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-amber-200 truncate">{proposal.component_id}</h3>
          <p className="text-xs text-amber-300/60 mt-0.5 truncate">
            proposed by <span className="font-mono">{proposal.proposing_agent_session_id}</span>
          </p>
        </div>
        {canAct && (
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              onClick={() => onApprove(proposal)}
              className="px-2.5 py-1 text-xs font-medium text-white bg-emerald-700 hover:bg-emerald-600 rounded transition-colors"
            >
              Approve
            </button>
            <button
              onClick={() => onReject(proposal)}
              className="px-2.5 py-1 text-xs font-medium text-white bg-rose-700 hover:bg-rose-600 rounded transition-colors"
            >
              Reject
            </button>
          </div>
        )}
      </div>

      {proposal.description && (
        <p className="text-xs text-amber-200/70 line-clamp-2">{proposal.description}</p>
      )}

      <div className="flex flex-wrap gap-1.5">
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-800/40 text-amber-300">
          {COMPONENT_TRANSITION_TYPE_LABELS[proposal.requested_minimum_transition_type] ?? proposal.requested_minimum_transition_type}
        </span>
        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-800/40 text-amber-300/80 font-mono">
          {proposal.project_id}
        </span>
      </div>

      {proposal.source_paths && proposal.source_paths.length > 0 && (
        <div className="text-xs text-amber-200/50 font-mono truncate">
          {proposal.source_paths.join(', ')}
        </div>
      )}

      <div className="text-xs text-amber-200/40">
        {new Date(proposal.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
      </div>
    </div>
  )
}

function ApproveModal({
  proposal,
  onConfirm,
  onCancel,
  isSubmitting,
}: {
  proposal: ComponentProposal
  onConfirm: (transitionType: ComponentTransitionType) => void
  onCancel: () => void
  isSubmitting: boolean
}) {
  const [transitionType, setTransitionType] = useState<ComponentTransitionType>(
    proposal.requested_minimum_transition_type,
  )

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="relative z-10 w-full max-w-sm bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-2xl">
        <h2 className="text-sm font-semibold text-slate-100 mb-2">Approve Component</h2>
        <p className="text-xs text-slate-400 mb-3">
          Approve <span className="text-slate-200 font-medium font-mono">{proposal.component_id}</span> and set its minimum transition type.
        </p>
        <label className="block text-xs text-slate-500 mb-1">Minimum Transition Type</label>
        <select
          value={transitionType}
          onChange={(e) => setTransitionType(e.target.value as ComponentTransitionType)}
          className="w-full bg-slate-800/60 border border-slate-700/60 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-slate-500 mb-4"
        >
          {COMPONENT_TRANSITION_TYPES.map((tt) => (
            <option key={tt} value={tt}>
              {COMPONENT_TRANSITION_TYPE_LABELS[tt] ?? tt}
            </option>
          ))}
        </select>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-slate-300 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm(transitionType)}
            disabled={isSubmitting}
            className="px-4 py-2 text-sm font-medium text-white bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 rounded-lg transition-colors"
          >
            {isSubmitting ? 'Approving...' : 'Approve'}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

function RejectModal({
  proposal,
  onConfirm,
  onCancel,
  isSubmitting,
}: {
  proposal: ComponentProposal
  onConfirm: (reason: string) => void
  onCancel: () => void
  isSubmitting: boolean
}) {
  const [reason, setReason] = useState('')

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="relative z-10 w-full max-w-sm bg-slate-900 border border-slate-700 rounded-xl p-5 shadow-2xl">
        <h2 className="text-sm font-semibold text-slate-100 mb-2">Reject Component</h2>
        <p className="text-xs text-slate-400 mb-3">
          Reject <span className="text-slate-200 font-medium font-mono">{proposal.component_id}</span>. Please provide a reason (min 10 characters).
        </p>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason for rejection..."
          rows={3}
          className="w-full bg-slate-800/60 border border-slate-700/60 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-slate-500 mb-1 resize-none"
        />
        <p className="text-xs text-slate-600 mb-4">{reason.length}/10 characters minimum</p>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-slate-300 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm(reason)}
            disabled={isSubmitting || reason.length < 10}
            className="px-4 py-2 text-sm font-medium text-white bg-rose-700 hover:bg-rose-600 disabled:opacity-50 rounded-lg transition-colors"
          >
            {isSubmitting ? 'Rejecting...' : 'Reject'}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export function ComponentRegistryPage() {
  const { authStatus } = useAuthState()
  const canEdit = authStatus === 'authenticated'

  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS)
  const [showModal, setShowModal] = useState(false)
  const [editingComponent, setEditingComponent] = useState<RegistryComponent | null>(null)
  const [deletingComponent, setDeletingComponent] = useState<RegistryComponent | null>(null)
  const [approvingProposal, setApprovingProposal] = useState<ComponentProposal | null>(null)
  const [rejectingProposal, setRejectingProposal] = useState<ComponentProposal | null>(null)
  const [projectSearch, setProjectSearch] = useState('')

  const { components, isPending, isError, dataUpdatedAt } = useComponentRegistry({
    project_id: filters.project_id || undefined,
    category: filters.category || undefined,
    status: filters.status || undefined,
  })

  const createMutation = useCreateComponent()
  const updateMutation = useUpdateComponent()
  const deleteMutation = useDeleteComponent()
  const approveMutation = useApproveComponent()
  const rejectMutation = useRejectComponent()

  // Derive unique project IDs from the full (unfiltered) list for the filter dropdown
  const { components: allComponents } = useComponentRegistry()
  const projectIds = useMemo(
    () =>
      Array.from(new Set(allComponents.map((c) => c.project_id))).sort(),
    [allComponents],
  )

  // ENC-FTR-076: Pending proposals (lifecycle_status === 'proposed')
  const pendingProposals = useMemo(
    () =>
      allComponents.filter(
        (c) => (c as unknown as ComponentProposal).lifecycle_status === 'proposed',
      ) as unknown as ComponentProposal[],
    [allComponents],
  )

  const handleApproveConfirm = useCallback(
    async (transitionType: ComponentTransitionType) => {
      if (!approvingProposal) return
      await approveMutation.mutateAsync({
        id: approvingProposal.component_id,
        minimum_transition_type: transitionType,
      })
      setApprovingProposal(null)
    },
    [approvingProposal, approveMutation],
  )

  const handleRejectConfirm = useCallback(
    async (reason: string) => {
      if (!rejectingProposal) return
      await rejectMutation.mutateAsync({
        id: rejectingProposal.component_id,
        rejection_reason: reason,
      })
      setRejectingProposal(null)
    },
    [rejectingProposal, rejectMutation],
  )

  const handleOpenCreate = useCallback(() => {
    setEditingComponent(null)
    setShowModal(true)
  }, [])

  const handleOpenEdit = useCallback((c: RegistryComponent) => {
    setEditingComponent(c)
    setShowModal(true)
  }, [])

  const handleCloseModal = useCallback(() => {
    setShowModal(false)
    setEditingComponent(null)
  }, [])

  const handleCreate = useCallback(
    async (data: CreateComponentInput) => {
      await createMutation.mutateAsync(data)
    },
    [createMutation],
  )

  const handleUpdate = useCallback(
    async (id: string, data: UpdateComponentInput) => {
      await updateMutation.mutateAsync({ id, data })
    },
    [updateMutation],
  )

  const handleDeleteConfirm = useCallback(async () => {
    if (!deletingComponent) return
    await deleteMutation.mutateAsync(deletingComponent.component_id)
    setDeletingComponent(null)
  }, [deletingComponent, deleteMutation])

  const generatedAt = dataUpdatedAt ? new Date(dataUpdatedAt).toISOString() : null

  // Filter by project search input (local filter on top of server filters)
  const filteredByProject = useMemo(() => {
    if (!projectSearch.trim()) return components
    const q = projectSearch.toLowerCase()
    return components.filter(
      (c) =>
        c.project_id.includes(q) ||
        c.component_name.toLowerCase().includes(q) ||
        c.component_id.includes(q),
    )
  }, [components, projectSearch])

  return (
    <div className="p-4 space-y-4">
      {/* Top bar */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">
            {isPending ? '…' : `${filteredByProject.length} component${filteredByProject.length !== 1 ? 's' : ''}`}
          </span>
          {generatedAt && <FreshnessBadge generatedAt={generatedAt} />}
        </div>
        {canEdit && (
          <button
            onClick={handleOpenCreate}
            className="px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded hover:bg-blue-500 transition-colors"
          >
            + Register Component
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="space-y-2">
        {/* Search */}
        <input
          type="search"
          value={projectSearch}
          onChange={(e) => setProjectSearch(e.target.value)}
          placeholder="Search by name, ID, or project…"
          className="w-full bg-slate-800/60 border border-slate-700/60 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-slate-500"
        />

        {/* Category filter pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-600 mr-0.5">Category:</span>
          <FilterPill
            label="All"
            active={filters.category === ''}
            onClick={() => setFilters((f) => ({ ...f, category: '' }))}
          />
          {COMPONENT_CATEGORIES.map((cat) => (
            <FilterPill
              key={cat}
              label={COMPONENT_CATEGORY_LABELS[cat]}
              active={filters.category === cat}
              onClick={() =>
                setFilters((f) => ({
                  ...f,
                  category: f.category === cat ? '' : cat,
                }))
              }
            />
          ))}
        </div>

        {/* Status + Project filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-600">Status:</span>
            {(['', 'active', 'deprecated', 'archived'] as const).map((s) => (
              <FilterPill
                key={s || 'all'}
                label={s ? (STATUS_LABELS[s] ?? s) : 'All'}
                active={filters.status === s}
                onClick={() => setFilters((f) => ({ ...f, status: s as ComponentStatus | '' }))}
              />
            ))}
          </div>

          {projectIds.length > 1 && (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-600">Project:</span>
              <select
                value={filters.project_id}
                onChange={(e) => setFilters((f) => ({ ...f, project_id: e.target.value }))}
                className="bg-slate-800/60 border border-slate-700/60 rounded px-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-slate-500"
              >
                <option value="">All</option>
                {projectIds.map((pid) => (
                  <option key={pid} value={pid}>
                    {pid}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Pending Approval — ENC-FTR-076 Phase 6 */}
      {pendingProposals.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-xs font-semibold text-amber-200 uppercase tracking-wider">
            Pending Approval ({pendingProposals.length})
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {pendingProposals.map((p) => (
              <ProposalCard
                key={p.component_id}
                proposal={p}
                canAct={canEdit}
                onApprove={setApprovingProposal}
                onReject={setRejectingProposal}
              />
            ))}
          </div>
        </section>
      )}

      {/* Results */}
      {isPending ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState />
      ) : filteredByProject.length === 0 ? (
        <EmptyState message="No components found" />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {filteredByProject.map((c) => (
            <ComponentCard
              key={c.component_id}
              component={c}
              canEdit={canEdit}
              onEdit={handleOpenEdit}
              onDelete={setDeletingComponent}
            />
          ))}
        </div>
      )}

      {/* Create / Edit modal */}
      {showModal && (
        <ComponentModal
          editing={editingComponent}
          onClose={handleCloseModal}
          onCreate={handleCreate}
          onUpdate={handleUpdate}
          isSubmitting={createMutation.isPending || updateMutation.isPending}
        />
      )}

      {/* Delete confirm */}
      {deletingComponent && (
        <DeleteConfirmModal
          component={deletingComponent}
          onConfirm={handleDeleteConfirm}
          onCancel={() => setDeletingComponent(null)}
          isDeleting={deleteMutation.isPending}
        />
      )}

      {/* Approve modal — ENC-FTR-076 Phase 6 */}
      {approvingProposal && (
        <ApproveModal
          proposal={approvingProposal}
          onConfirm={handleApproveConfirm}
          onCancel={() => setApprovingProposal(null)}
          isSubmitting={approveMutation.isPending}
        />
      )}

      {/* Reject modal — ENC-FTR-076 Phase 6 */}
      {rejectingProposal && (
        <RejectModal
          proposal={rejectingProposal}
          onConfirm={handleRejectConfirm}
          onCancel={() => setRejectingProposal(null)}
          isSubmitting={rejectMutation.isPending}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// FilterPill helper
// ---------------------------------------------------------------------------

function FilterPill({
  label,
  active,
  onClick,
}: {
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
        active
          ? 'bg-slate-600 text-slate-100'
          : 'bg-slate-800/60 text-slate-500 hover:text-slate-300 hover:bg-slate-700/60'
      }`}
    >
      {label}
    </button>
  )
}
