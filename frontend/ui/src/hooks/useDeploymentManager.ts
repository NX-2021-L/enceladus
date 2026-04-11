/**
 * React Query hook for the Deployment Manager — GMF (DOC-63420302EF65 §6).
 *
 * Polls the deploy queue every 5 seconds when the page is active.
 * Provides mutation helpers for approve/divert/revert actions.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { deployKeys, fetchDeployQueue, submitDeployDecision } from '../api/deploy'
import type { DeployDecideRequest, DeploymentDecision } from '../types/deployments'
import { isSessionExpiredError } from '../lib/authSession'

const POLL_INTERVAL = 5_000

export function useDeployQueue(projectId: string = 'enceladus') {
  const query = useQuery({
    queryKey: deployKeys.queue(projectId),
    queryFn: () => fetchDeployQueue(projectId),
    refetchInterval: POLL_INTERVAL,
    retry: (count, error) => (isSessionExpiredError(error) ? false : count < 2),
    meta: { suppressSessionExpired: true },
  })

  return {
    decisions: query.data?.decisions ?? [],
    count: query.data?.count ?? 0,
    isPending: query.isPending,
    isError: query.isError,
    refetch: query.refetch,
  }
}

export function useDeployDecision() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (request: DeployDecideRequest) => submitDeployDecision(request),
    onSuccess: () => {
      // Invalidate the queue to refresh immediately after a decision
      queryClient.invalidateQueries({ queryKey: ['deploy', 'queue'] })
    },
  })
}

/**
 * Lightweight hook for the notification banner — just the pending count.
 * Used in AppShell to show the deploy approval banner across all pages.
 */
export function useDeployPendingCount(projectId: string = 'enceladus') {
  const query = useQuery({
    queryKey: [...deployKeys.queue(projectId), 'count'],
    queryFn: async () => {
      const data = await fetchDeployQueue(projectId)
      return data.count
    },
    refetchInterval: POLL_INTERVAL,
    retry: (count, error) => (isSessionExpiredError(error) ? false : count < 1),
    meta: { suppressSessionExpired: true },
  })

  return query.data ?? 0
}

/**
 * Helper to compute time-in-queue for display.
 */
export function timeInQueue(createdAt: string): string {
  const created = new Date(createdAt)
  const now = new Date()
  const diffMs = now.getTime() - created.getTime()
  const mins = Math.floor(diffMs / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ${mins % 60}m`
  const days = Math.floor(hours / 24)
  return `${days}d ${hours % 24}h`
}
