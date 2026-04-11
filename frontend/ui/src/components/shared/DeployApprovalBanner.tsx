/**
 * DeployApprovalBanner — Non-dismissable notification banner shown across all pages
 * when production deployments are pending approval (DOC-63420302EF65 §6.1).
 *
 * Renders above the main content in AppShell when pendingCount > 0.
 * Links to /deployments for the full Deployment Manager surface.
 */

import { useNavigate, useLocation } from 'react-router-dom'
import { useDeployPendingCount } from '../../hooks/useDeploymentManager'

export function DeployApprovalBanner() {
  const pendingCount = useDeployPendingCount()
  const navigate = useNavigate()
  const { pathname } = useLocation()

  // Don't show banner if no pending deployments or already on the deployments page
  if (pendingCount === 0 || pathname === '/deployments') return null

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-2 flex items-center justify-between">
      <div className="flex items-center gap-2 min-w-0">
        <span className="flex-shrink-0 w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
        <span className="text-xs text-amber-300 truncate">
          <span className="font-semibold">{pendingCount}</span>
          {pendingCount === 1 ? ' deployment' : ' deployments'} awaiting approval
        </span>
      </div>
      <button
        onClick={() => navigate('/deployments')}
        className="flex-shrink-0 text-xs font-medium text-amber-400 hover:text-amber-300 active:text-amber-200 transition-colors"
      >
        Review Now &rarr;
      </button>
    </div>
  )
}
