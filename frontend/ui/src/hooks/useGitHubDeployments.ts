// React Query hooks for DM Gen2 thin reader (ENC-TSK-F62).

import { useQuery } from '@tanstack/react-query'
import {
  fetchDeployments,
  fetchDeploymentStatuses,
  fetchRecentRuns,
} from '../api/githubDeployments'
import { githubStateToDesignStatus } from '../types/githubDeployments'
import type { DeploymentWithStatus } from '../types/githubDeployments'

const REFRESH_MS = 30_000
const STALE_MS = 15_000

export const ghKeys = {
  deployments: () => ['github', 'deployments'] as const,
  pendingCount: () => ['github', 'deployments', 'pending'] as const,
}

export function useGitHubDeployments() {
  return useQuery({
    queryKey: ghKeys.deployments(),
    queryFn: async (): Promise<DeploymentWithStatus[]> => {
      const [deployments, runs] = await Promise.all([fetchDeployments(20), fetchRecentRuns(40)])

      // Index runs by SHA for O(1) lookup
      const runsBySha = new Map<string, typeof runs[number]>()
      for (const run of runs) {
        if (!runsBySha.has(run.head_sha)) runsBySha.set(run.head_sha, run)
      }

      return Promise.all(
        deployments.map(async (dep) => {
          const statuses = await fetchDeploymentStatuses(dep.id)
          const latestStatus = statuses[0] ?? null
          return {
            deployment: dep,
            latestStatus,
            designStatus: latestStatus
              ? githubStateToDesignStatus(latestStatus.state)
              : 'open',
            run: runsBySha.get(dep.sha) ?? null,
          }
        }),
      )
    },
    refetchInterval: REFRESH_MS,
    staleTime: STALE_MS,
  })
}

export function useGitHubPendingCount() {
  return useQuery({
    queryKey: ghKeys.pendingCount(),
    queryFn: async (): Promise<number> => {
      const deployments = await fetchDeployments(30)
      const statuses = await Promise.all(
        deployments.map((d) => fetchDeploymentStatuses(d.id).then((s) => s[0] ?? null)),
      )
      return statuses.filter(
        (s) => s && (s.state === 'pending' || s.state === 'queued' || s.state === 'in_progress'),
      ).length
    },
    refetchInterval: REFRESH_MS,
    staleTime: STALE_MS,
  })
}
