import { useState } from 'react'
import { useRecordMutation } from '../../hooks/useRecordMutation'
import { createGitHubIssue } from '../../api/github'
import { isMutationRetryExhaustedError } from '../../api/mutations'

type GitHubOverlayMode = 'link' | 'create'

interface GitHubOverlayProps {
  projectId: string
  recordType: 'task' | 'issue' | 'feature'
  recordId: string
  recordTitle: string
  recordDescription?: string
  recordPriority?: string
  recordCategory?: string
  onClose: () => void
  onSuccess: (message: string) => void
  onError: (message: string) => void
}

const DEFAULT_OWNER = 'NX-2021-L'
const DEFAULT_REPO = 'enceladus'

export function GitHubOverlay({
  projectId,
  recordType,
  recordId,
  recordTitle,
  recordDescription,
  recordPriority,
  recordCategory,
  onClose,
  onSuccess,
  onError,
}: GitHubOverlayProps) {
  const [mode, setMode] = useState<GitHubOverlayMode>('link')
  const { mutate, isPending: isMutating } = useRecordMutation()

  // Link mode state
  const [githubUrl, setGithubUrl] = useState('')

  // Create mode state
  const [issueTitle, setIssueTitle] = useState(
    `[${recordId}] ${recordTitle}`
  )
  const [issueBody, setIssueBody] = useState(
    buildDefaultBody(recordId, projectId, recordDescription)
  )
  const [isCreating, setIsCreating] = useState(false)

  const labels = buildLabels(recordPriority, recordCategory, recordType)

  function handleSubmitLink() {
    const trimmed = githubUrl.trim()
    if (!trimmed) return
    try { new URL(trimmed) } catch { onError('Please enter a valid URL.'); return }

    mutate(
      { projectId, recordType, recordId, action: 'set_field', field: 'github_issue_url', value: trimmed },
      {
        onSuccess: () => {
          onClose()
          onSuccess('GitHub issue linked.')
        },
        onError: (err) => {
          onError(
            isMutationRetryExhaustedError(err)
              ? err.toDebugString()
              : (err.message ?? 'Link failed. Please try again.')
          )
        },
      }
    )
  }

  async function handleCreateIssue() {
    if (!issueTitle.trim()) { onError('Issue title is required.'); return }
    setIsCreating(true)

    try {
      const result = await createGitHubIssue({
        owner: DEFAULT_OWNER,
        repo: DEFAULT_REPO,
        title: issueTitle.trim(),
        body: issueBody.trim() || undefined,
        labels: labels.length > 0 ? labels : undefined,
        record_id: recordId,
        project_id: projectId,
      })

      // Auto-link the returned URL to the record
      mutate(
        { projectId, recordType, recordId, action: 'set_field', field: 'github_issue_url', value: result.issue_url },
        {
          onSuccess: () => {
            onClose()
            onSuccess(`GitHub issue #${result.issue_number} created and linked.`)
          },
          onError: () => {
            // Issue was created but linking failed — still show success with URL
            onClose()
            onSuccess(`Issue created: ${result.issue_url} (auto-link failed, paste manually)`)
          },
        }
      )
    } catch (err) {
      setIsCreating(false)
      onError(err instanceof Error ? err.message : 'Failed to create GitHub issue.')
    }
  }

  const busy = isMutating || isCreating

  return (
    <div className="fixed inset-0 z-50 flex flex-col justify-end bg-black/60">
      <div className="bg-slate-800 rounded-t-2xl p-5 space-y-3 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100">GitHub Issue</h3>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 text-lg"
          >
            ✕
          </button>
        </div>

        {/* Mode tabs */}
        <div className="flex gap-1 bg-slate-900 rounded-lg p-0.5">
          <button
            onClick={() => setMode('link')}
            className={`flex-1 text-xs py-1.5 rounded-md transition-colors ${
              mode === 'link'
                ? 'bg-slate-700 text-slate-100'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Link existing
          </button>
          <button
            onClick={() => setMode('create')}
            className={`flex-1 text-xs py-1.5 rounded-md transition-colors ${
              mode === 'create'
                ? 'bg-slate-700 text-slate-100'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Create new
          </button>
        </div>

        {/* Link mode */}
        {mode === 'link' && (
          <>
            <p className="text-xs text-slate-400">
              Paste the URL of an existing GitHub issue.
            </p>
            <input
              type="url"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/org/repo/issues/123"
              className="w-full bg-slate-700 text-slate-100 text-sm rounded-lg p-3 border border-slate-600 focus:outline-none focus:border-blue-500"
              autoFocus
            />
            <div className="flex items-center justify-end">
              <div className="flex gap-2">
                <button
                  onClick={onClose}
                  className="text-xs px-4 py-2 rounded-full text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSubmitLink}
                  disabled={!githubUrl.trim() || busy}
                  className="text-xs px-4 py-2 rounded-full bg-blue-700 text-white hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {busy ? 'Linking...' : 'Link'}
                </button>
              </div>
            </div>
          </>
        )}

        {/* Create mode */}
        {mode === 'create' && (
          <>
            <p className="text-xs text-slate-400">
              Create a new issue on {DEFAULT_OWNER}/{DEFAULT_REPO} and auto-link it.
            </p>
            <input
              type="text"
              value={issueTitle}
              onChange={(e) => setIssueTitle(e.target.value)}
              placeholder="Issue title"
              className="w-full bg-slate-700 text-slate-100 text-sm rounded-lg p-3 border border-slate-600 focus:outline-none focus:border-blue-500"
              autoFocus
            />
            <textarea
              rows={4}
              value={issueBody}
              onChange={(e) => setIssueBody(e.target.value)}
              placeholder="Issue description (markdown)..."
              className="w-full bg-slate-700 text-slate-100 text-sm rounded-lg p-3 border border-slate-600 focus:outline-none focus:border-blue-500 resize-none"
            />
            {labels.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                <span className="text-xs text-slate-500">Labels:</span>
                {labels.map((l) => (
                  <span key={l} className="text-xs px-1.5 py-0.5 bg-slate-700 text-slate-300 rounded">
                    {l}
                  </span>
                ))}
              </div>
            )}
            <div className="flex items-center justify-end">
              <div className="flex gap-2">
                <button
                  onClick={onClose}
                  className="text-xs px-4 py-2 rounded-full text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateIssue}
                  disabled={!issueTitle.trim() || busy}
                  className="text-xs px-4 py-2 rounded-full bg-emerald-700 text-white hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {busy ? 'Creating...' : 'Create Issue'}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function buildDefaultBody(recordId: string, projectId: string, description?: string): string {
  const parts: string[] = []
  if (description) {
    parts.push(description.slice(0, 2000))
    parts.push('')
  }
  parts.push('---')
  parts.push(`Enceladus Record: \`${recordId}\` (project: \`${projectId}\`)`)
  return parts.join('\n')
}

function buildLabels(priority?: string, category?: string, recordType?: string): string[] {
  const labels: string[] = []
  if (recordType) labels.push(`enceladus:${recordType}`)
  if (priority) labels.push(priority.toLowerCase())
  if (category) labels.push(category)
  return labels
}
