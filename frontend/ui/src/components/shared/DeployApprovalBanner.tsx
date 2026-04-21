// Deploy activity banner — sources from GitHub Deployments API (ENC-TSK-F62 AC-1).
// Shows when in_progress/pending deployments are active on pages other than /deployments.

import { useNavigate, useLocation } from 'react-router-dom'
import { useGitHubPendingCount } from '../../hooks/useGitHubDeployments'
import { Activity } from 'lucide-react'

export function DeployApprovalBanner() {
  const pendingCount = useGitHubPendingCount().data ?? 0
  const navigate = useNavigate()
  const { pathname } = useLocation()

  if (pendingCount === 0 || pathname === '/deployments') return null

  return (
    <div
      style={{
        background: 'color-mix(in srgb, var(--enc-teal) 8%, transparent)',
        borderBottom: 'var(--border-divider)',
        padding: 'var(--space-2) var(--space-4)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', minWidth: 0 }}>
        <Activity
          size={12}
          strokeWidth={1.5}
          style={{ color: 'var(--accent)', flexShrink: 0 }}
        />
        <span
          style={{
            fontFamily: 'var(--font-body)',
            fontSize: 'var(--text-xs)',
            color: 'var(--fg-muted)',
          }}
        >
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              color: 'var(--accent)',
              fontWeight: 'var(--fw-medium)',
            }}
          >
            {pendingCount}
          </span>
          {pendingCount === 1 ? ' deployment' : ' deployments'} in progress
        </span>
      </div>
      <button
        onClick={() => navigate('/deployments')}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          fontFamily: 'var(--font-heading)',
          fontWeight: 'var(--fw-medium)',
          fontSize: 'var(--text-xs)',
          color: 'var(--accent)',
          padding: 'var(--space-1) var(--space-2)',
          borderRadius: 'var(--radius-sm)',
          flexShrink: 0,
          transition: `color var(--dur-fast) var(--ease-orbit)`,
        }}
        onMouseEnter={(e) => {
          ;(e.currentTarget as HTMLButtonElement).style.color = 'var(--accent-hover)'
        }}
        onMouseLeave={(e) => {
          ;(e.currentTarget as HTMLButtonElement).style.color = 'var(--accent)'
        }}
      >
        View →
      </button>
    </div>
  )
}
