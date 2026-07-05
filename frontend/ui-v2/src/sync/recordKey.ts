export function cacheKey(projectId: string, recordId: string): string {
  return `${projectId || 'global'}:${recordId}`
}

export function versionSeqFromUpdatedAt(updatedAt?: string | null): string {
  return updatedAt?.trim() || '0'
}

export function shouldAcceptVersion(current: string | undefined, incoming: string): boolean {
  if (!current) return true
  if (current === incoming) return true
  return incoming >= current
}
