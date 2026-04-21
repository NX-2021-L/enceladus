// DM Gen2 — thin reader (ENC-TSK-F62).
// Zero POST/PUT to any Enceladus endpoint. All data from api.github.com.
// Action buttons are deep-links to GitHub. No state owns a deploy decision.

import { ExternalLink, GitBranch, RotateCw, Terminal, Activity, Circle } from 'lucide-react'
import { useGitHubDeployments } from '../hooks/useGitHubDeployments'
import type { DeploymentWithStatus, DesignSystemStatus } from '../types/githubDeployments'

// ---------------------------------------------------------------------------
// StatusChip — AC-5: single variant prop, no internal color switches
// ---------------------------------------------------------------------------

const STATUS_LABEL: Record<DesignSystemStatus, string> = {
  open: 'pending',
  'in-progress': 'in progress',
  blocked: 'failed',
  closed: 'deployed',
}

function StatusChip({ status }: { status: DesignSystemStatus }) {
  return (
    <span
      className="dm-status-chip"
      style={{
        color: `var(--status-${status})`,
        border: `1px solid var(--status-${status})`,
      }}
    >
      <Circle size={6} strokeWidth={0} fill={`var(--status-${status})`} style={{ flexShrink: 0 }} />
      {STATUS_LABEL[status]}
    </span>
  )
}

// ---------------------------------------------------------------------------
// DeploySteps — AC-6 Law 2: fracture as detail, segmented not continuous
// ---------------------------------------------------------------------------

const STEP_STATES = ['pending', 'in_progress', 'success'] as const

function stepIndex(state: string): number {
  if (state === 'pending' || state === 'queued') return 0
  if (state === 'in_progress') return 1
  if (state === 'success') return 2
  return -1
}

function DeploySteps({ state }: { state: string }) {
  const current = stepIndex(state)
  const isFailed = state === 'error' || state === 'failure'

  return (
    <div className="dm-steps" aria-label={`Deploy step: ${state}`}>
      {STEP_STATES.map((step, i) => {
        const filled = !isFailed && current >= i
        const isFailPoint = isFailed && i === 1
        return (
          <div key={step} className="dm-step-group">
            <div
              className="dm-step-bar"
              style={{
                width: i === 2 ? '32px' : '20px',
                background: isFailPoint
                  ? 'var(--status-blocked)'
                  : filled
                    ? 'var(--status-closed)'
                    : 'var(--enc-slate)',
              }}
            />
            {i < STEP_STATES.length - 1 && (
              <div
                className="dm-step-dot"
                style={{ background: filled ? 'var(--enc-dust)' : 'var(--enc-slate)' }}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// DeployCard — AC-6 Laws 3,4,5: elevation, orbital motion, telemetry ambient
// ---------------------------------------------------------------------------

function DeployCard({ item }: { item: DeploymentWithStatus }) {
  const { deployment: dep, latestStatus, designStatus, run } = item
  const sha = dep.sha.slice(0, 12)
  const state = latestStatus?.state ?? 'pending'
  const env = dep.environment

  const payload =
    typeof dep.payload === 'string'
      ? (() => { try { return JSON.parse(dep.payload) } catch { return {} } })()
      : dep.payload
  const prNumber: number | null =
    (payload as Record<string, unknown>)?.pr_number as number ?? null

  const ghPrUrl = prNumber
    ? `https://github.com/NX-2021-L/enceladus/pull/${prNumber}`
    : null
  const runUrl = run?.html_url ?? null

  return (
    <div
      className={`dm-card${designStatus === 'in-progress' ? ' dm-card--active' : ''}`}
    >
      {/* Header */}
      <div className="dm-card-header">
        <div style={{ minWidth: 0, flex: 1 }}>
          <div className="dm-card-title-row">
            <span
              style={{
                fontFamily: 'var(--font-heading)',
                fontWeight: 'var(--fw-medium)',
                fontSize: 'var(--text-sm)',
                color: 'var(--fg-display)',
              }}
            >
              {env}
            </span>
            {prNumber && (
              <span className="enc-record-id" style={{ fontSize: 'var(--text-xs)' }}>
                #{prNumber}
              </span>
            )}
          </div>
          <div className="dm-branch-row">
            <GitBranch size={11} strokeWidth={1.5} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
              {dep.ref}
            </span>
          </div>
        </div>
        <StatusChip status={designStatus} />
      </div>

      {/* Fracture steps — Law 2 */}
      <DeploySteps state={state} />

      {/* Telemetry row — Law 5 */}
      <div className="dm-telemetry">
        <span className="dm-telemetry-item">
          <Terminal size={11} strokeWidth={1.5} />
          <span className="enc-record-id" style={{ fontSize: 'var(--text-xs)' }}>{sha}</span>
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--fg-muted)' }}>
          {new Date(dep.created_at).toLocaleString()}
        </span>
        {dep.creator?.login && (
          <span style={{ fontFamily: 'var(--font-body)', fontSize: 'var(--text-xs)', color: 'var(--fg-muted)' }}>
            {dep.creator.login}
          </span>
        )}
        {run?.run_number && (
          <span className="dm-telemetry-item">
            <Activity size={11} strokeWidth={1.5} />
            <span className="enc-record-id" style={{ fontSize: 'var(--text-xs)' }}>
              run #{run.run_number}
            </span>
          </span>
        )}
      </div>

      {/* Deep-link buttons */}
      {(ghPrUrl || runUrl) && (
        <div className="dm-actions">
          {ghPrUrl && (
            <a href={ghPrUrl} target="_blank" rel="noopener noreferrer" className="dm-link-primary">
              View PR
              <ExternalLink size={10} strokeWidth={1.5} />
            </a>
          )}
          {runUrl && (
            <a href={runUrl} target="_blank" rel="noopener noreferrer" className="dm-link-secondary">
              View Run
              <ExternalLink size={10} strokeWidth={1.5} />
            </a>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function DeploymentManagerPage() {
  const { data: items = [], isPending, isError, refetch, isFetching } = useGitHubDeployments()

  return (
    <div className="dm-page">
      {/* Header */}
      <div className="dm-page-header">
        <div className="dm-page-title-row">
          <h2
            style={{
              fontFamily: 'var(--font-heading)',
              fontWeight: 'var(--fw-bold)',
              fontSize: 'var(--text-xl)',
              color: 'var(--fg-display)',
              margin: 0,
            }}
          >
            Deploy Timeline
          </h2>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            aria-label="Refresh deployments"
            className="dm-refresh-btn"
          >
            <RotateCw
              size={13}
              strokeWidth={1.5}
              style={{ animation: isFetching ? 'dm-spin 1s linear infinite' : 'none' }}
            />
            Refresh
          </button>
        </div>
        <p className="dm-subtitle">
          Live from GitHub Deployments API · actions via GitHub PR review
        </p>
      </div>

      {/* Body */}
      {isPending ? (
        <div className="dm-list">
          {[1, 2, 3].map((i) => <div key={i} className="dm-skeleton" />)}
        </div>
      ) : isError ? (
        <div className="dm-error">
          GitHub API unavailable — check VITE_GITHUB_READ_TOKEN or rate limits.
        </div>
      ) : items.length === 0 ? (
        <div className="dm-empty">No deployments found.</div>
      ) : (
        <div className="dm-list">
          {items.map((item) => (
            <DeployCard key={item.deployment.id} item={item} />
          ))}
        </div>
      )}

      {/* Footer telemetry — Law 5 */}
      {!isPending && !isError && (
        <div className="dm-footer">
          {items.length} deployments · refreshes every 30s
        </div>
      )}

      <style>{`
        /* AC-4: all color values via CSS vars from colors_and_type.css */
        .dm-page {
          padding: var(--space-6) var(--space-4);
          max-width: 680px;
          margin: 0 auto;
          background: var(--bg);
          min-height: 100%;
        }
        .dm-page-header { margin-bottom: var(--space-8); }
        .dm-page-title-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .dm-subtitle {
          font-family: var(--font-body);
          font-size: var(--text-xs);
          color: var(--fg-muted);
          margin-top: var(--space-1);
          margin-bottom: 0;
        }

        /* Status chip */
        .dm-status-chip {
          display: inline-flex;
          align-items: center;
          gap: var(--space-1);
          padding: var(--space-1) var(--space-2);
          border-radius: var(--radius-sm);
          font-family: var(--font-heading);
          font-size: var(--text-xs);
          font-weight: var(--fw-medium);
          letter-spacing: var(--tracking-label);
          text-transform: uppercase;
          opacity: 0.9;
        }

        /* Steps */
        .dm-steps {
          display: flex;
          align-items: center;
          gap: var(--space-1);
        }
        .dm-step-group {
          display: flex;
          align-items: center;
          gap: var(--space-1);
        }
        .dm-step-bar {
          height: 3px;
          border-radius: var(--radius-xs);
          transition: background var(--dur-base) var(--ease-orbit);
        }
        .dm-step-dot {
          width: 4px;
          height: 4px;
          border-radius: 50%;
          transition: background var(--dur-base) var(--ease-orbit);
        }

        /* Card — Law 3: subsurface depth */
        .dm-card {
          background: var(--bg-surface);
          border: var(--border-subtle);
          border-radius: var(--radius-lg);
          padding: var(--space-5);
          box-shadow: var(--shadow-sm);
          display: flex;
          flex-direction: column;
          gap: var(--space-3);
          transition:
            box-shadow var(--dur-base) var(--ease-orbit),
            border var(--dur-base) var(--ease-orbit);
        }
        .dm-card--active { box-shadow: var(--shadow-md); }
        .dm-card:hover {
          border: var(--border-hover);
          box-shadow: var(--shadow-md);
        }

        .dm-card-header {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: var(--space-3);
        }
        .dm-card-title-row {
          display: flex;
          align-items: center;
          gap: var(--space-2);
          margin-bottom: var(--space-1);
        }
        .dm-branch-row {
          display: flex;
          align-items: center;
          gap: var(--space-1);
          color: var(--fg-muted);
        }

        /* Telemetry — Law 5 */
        .dm-telemetry {
          display: flex;
          align-items: center;
          gap: var(--space-4);
          flex-wrap: wrap;
        }
        .dm-telemetry-item {
          display: flex;
          align-items: center;
          gap: var(--space-1);
          color: var(--fg-muted);
        }

        /* Deep-link buttons — Law 4: orbital motion */
        .dm-actions {
          display: flex;
          gap: var(--space-2);
          padding-top: var(--space-1);
        }
        .dm-link-primary,
        .dm-link-secondary {
          display: inline-flex;
          align-items: center;
          gap: var(--space-1);
          padding: var(--space-1) var(--space-3);
          border-radius: var(--radius-sm);
          font-family: var(--font-heading);
          font-weight: var(--fw-medium);
          font-size: var(--text-xs);
          background: transparent;
          text-decoration: none;
          transition:
            color var(--dur-fast) var(--ease-orbit),
            border var(--dur-fast) var(--ease-orbit);
        }
        .dm-link-primary {
          color: var(--accent);
          border: var(--border-subtle);
        }
        .dm-link-primary:hover {
          color: var(--accent-hover);
          border: var(--border-hover);
        }
        .dm-link-secondary {
          color: var(--fg-muted);
          border: var(--border-divider);
        }
        .dm-link-secondary:hover {
          color: var(--fg);
          border: var(--border-subtle);
        }

        /* Refresh button */
        .dm-refresh-btn {
          display: inline-flex;
          align-items: center;
          gap: var(--space-1);
          background: none;
          border: none;
          cursor: pointer;
          color: var(--fg-muted);
          font-family: var(--font-body);
          font-size: var(--text-xs);
          padding: var(--space-1);
          transition: color var(--dur-fast) var(--ease-orbit);
        }
        .dm-refresh-btn:hover { color: var(--fg); }
        .dm-refresh-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        /* Skeletons / states */
        .dm-list { display: flex; flex-direction: column; gap: var(--space-3); }
        .dm-skeleton {
          height: 120px;
          background: var(--bg-surface);
          border-radius: var(--radius-lg);
          border: var(--border-divider);
          opacity: 0.5;
        }
        .dm-error {
          padding: var(--space-5);
          border-radius: var(--radius-lg);
          border: 1px solid var(--status-blocked);
          color: var(--status-blocked);
          font-family: var(--font-body);
          font-size: var(--text-sm);
          background: var(--bg-surface);
          box-shadow: var(--shadow-sm);
        }
        .dm-empty {
          padding: var(--space-8);
          text-align: center;
          color: var(--fg-muted);
          font-family: var(--font-body);
          font-size: var(--text-sm);
        }
        .dm-footer {
          margin-top: var(--space-6);
          padding-top: var(--space-4);
          border-top: var(--border-divider);
          font-family: var(--font-mono);
          font-size: var(--text-xs);
          color: var(--fg-muted);
        }

        /* Law 4: orbital motion — spin animation */
        @keyframes dm-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
