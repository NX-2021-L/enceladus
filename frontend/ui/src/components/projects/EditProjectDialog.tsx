/**
 * EditProjectDialog.tsx — ENC-FTR-131 / ENC-TSK-N89
 *
 * Edits the three mutable fields of a project record: summary, status, repository URL.
 * Everything else (project_id, name, prefix, parent, path) is immutable and is shown
 * read-only so it is obvious why it cannot be changed.
 *
 * Prefill comes from GET /api/v1/projects/{projectName}, deliberately NOT from the projects
 * feed — the feed's ProjectSummary shape has no `repo`, so prefilling from it would submit an
 * empty repo and clear the very field this feature exists to set.
 */

import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { feedKeys } from '../../api/feeds'
import {
  getProject,
  updateProject,
  validateSummary,
  validateProjectStatus,
  validateRepo,
  ProjectServiceError,
  type ProjectRecord,
  type UpdateProjectRequest,
} from '../../api/projects'
import { useAuthState } from '../../lib/authState'

const STATUS_OPTIONS = [
  { value: 'planning', label: 'Planning' },
  { value: 'development', label: 'Development' },
  { value: 'active_production', label: 'Active Production' },
]

type FieldErrors = {
  summary?: string
  status?: string
  repo?: string
  submit?: string
}

export function EditProjectDialog({
  projectId,
  onClose,
}: {
  projectId: string
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const { setAuthExpired } = useAuthState()
  const dialogRef = useRef<HTMLDivElement | null>(null)
  // Held in a ref so the prefill effect depends on projectId alone. Depending on the
  // callback's identity would mean any re-render producing a new one refetches and
  // overwrites summary/status/repo — silently destroying what the user had typed.
  const authExpiredRef = useRef(setAuthExpired)
  authExpiredRef.current = setAuthExpired

  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [original, setOriginal] = useState<ProjectRecord | null>(null)
  const [summary, setSummary] = useState('')
  const [status, setStatus] = useState('')
  const [repo, setRepo] = useState('')
  const [errors, setErrors] = useState<FieldErrors>({})
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(null)
    getProject(projectId)
      .then((res) => {
        if (cancelled) return
        const p = res.project
        setOriginal(p)
        setSummary(p.summary ?? '')
        setStatus(p.status ?? '')
        setRepo(p.repo ?? '')
      })
      .catch((err: unknown) => {
        if (cancelled) return
        if (err instanceof ProjectServiceError && err.status === 401) {
          authExpiredRef.current()
        }
        setLoadError(
          err instanceof ProjectServiceError
            ? err.message
            : 'Could not load this project.'
        )
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId])

  // Escape closes; focus moves into the dialog so keyboard users are not stranded.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    dialogRef.current?.focus()
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  /** Only fields the user actually changed are sent — the backend rejects an empty patch. */
  function buildPatch(): UpdateProjectRequest {
    const patch: UpdateProjectRequest = {}
    if (!original) return patch
    if (summary.trim() !== (original.summary ?? '')) patch.summary = summary.trim()
    if (status !== (original.status ?? '')) patch.status = status
    if (repo.trim() !== (original.repo ?? '')) patch.repo = repo.trim()
    return patch
  }

  function validate(patch: UpdateProjectRequest): FieldErrors {
    const next: FieldErrors = {}
    if (patch.summary !== undefined) {
      const r = validateSummary(patch.summary)
      if (!r.valid) next.summary = r.error
    }
    if (patch.status !== undefined) {
      const r = validateProjectStatus(patch.status)
      if (!r.valid) next.status = r.error
    }
    // An empty repo is the intentional "clear it" case, which validateRepo accepts.
    if (patch.repo !== undefined) {
      const r = validateRepo(patch.repo)
      if (!r.valid) next.repo = r.error
    }
    return next
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const patch = buildPatch()

    if (Object.keys(patch).length === 0) {
      setErrors({ submit: 'No changes to save.' })
      return
    }

    const fieldErrors = validate(patch)
    if (Object.keys(fieldErrors).length > 0) {
      setErrors(fieldErrors)
      return
    }

    setErrors({})
    setSaving(true)
    try {
      await updateProject(projectId, patch)
      await queryClient.invalidateQueries({ queryKey: feedKeys.projects })
      onClose()
    } catch (err: unknown) {
      // The dialog deliberately stays open with the user's input intact so a rejected
      // save is recoverable rather than losing what they typed.
      if (err instanceof ProjectServiceError) {
        if (err.status === 401) setAuthExpired()
        setErrors({ submit: err.message })
      } else {
        setErrors({ submit: 'Something went wrong saving this project.' })
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/60 p-0 sm:p-4"
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Edit project ${projectId}`}
        tabIndex={-1}
        className="w-full sm:max-w-lg max-h-[90vh] overflow-y-auto bg-slate-800 rounded-t-2xl sm:rounded-lg p-4 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-base font-medium text-slate-100">Edit project</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="min-h-11 min-w-11 text-slate-400 hover:text-slate-200"
          >
            ✕
          </button>
        </div>

        {loading && <p className="text-sm text-slate-400">Loading project…</p>}

        {!loading && loadError && (
          <p role="alert" className="text-sm text-red-400">
            {loadError}
          </p>
        )}

        {/* noValidate on the form: type="url" is kept for the mobile keyboard, but native
            constraint validation would swallow the submit event and show a browser bubble
            instead of our inline error, leaving validateRepo unreachable. The shared
            validators are the single source of truth for what blocks a save. */}
        {!loading && !loadError && original && (
          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            <div className="text-xs text-slate-500 space-y-0.5">
              <div>
                <span className="font-mono">{original.prefix}</span> · {projectId}
              </div>
              <div>These identity fields cannot be changed.</div>
            </div>

            <div>
              <label htmlFor="edit-project-summary" className="block text-sm text-slate-300 mb-1">
                Summary
              </label>
              <textarea
                id="edit-project-summary"
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                rows={4}
                className="w-full rounded bg-slate-900 border border-slate-700 p-2 text-sm text-slate-100"
              />
              {errors.summary && (
                <p role="alert" className="text-xs text-red-400 mt-1">
                  {errors.summary}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="edit-project-status" className="block text-sm text-slate-300 mb-1">
                Status
              </label>
              <select
                id="edit-project-status"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-full min-h-11 rounded bg-slate-900 border border-slate-700 p-2 text-sm text-slate-100"
              >
                {/* A status outside the editable set (e.g. a legacy closed/archived value)
                    is preserved as an option so opening the dialog cannot silently
                    reclassify the project just by rendering. */}
                {!STATUS_OPTIONS.some((o) => o.value === status) && status && (
                  <option value={status}>{status}</option>
                )}
                {STATUS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
              {errors.status && (
                <p role="alert" className="text-xs text-red-400 mt-1">
                  {errors.status}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="edit-project-repo" className="block text-sm text-slate-300 mb-1">
                Repository URL
              </label>
              <input
                id="edit-project-repo"
                type="url"
                inputMode="url"
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="w-full min-h-11 rounded bg-slate-900 border border-slate-700 p-2 text-sm text-slate-100"
              />
              <p className="text-xs text-slate-500 mt-1">
                Leave blank to clear it.
              </p>
              {errors.repo && (
                <p role="alert" className="text-xs text-red-400 mt-1">
                  {errors.repo}
                </p>
              )}
            </div>

            {errors.submit && (
              <p role="alert" className="text-sm text-red-400">
                {errors.submit}
              </p>
            )}

            <div className="flex gap-2 justify-end pt-1">
              <button
                type="button"
                onClick={onClose}
                className="min-h-11 px-4 rounded text-sm text-slate-300 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="min-h-11 px-4 rounded bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
              >
                {saving ? 'Saving…' : 'Save changes'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
