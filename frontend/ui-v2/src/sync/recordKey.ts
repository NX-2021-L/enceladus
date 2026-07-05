export function cacheKey(projectId: string, recordId: string): string {
  return `${projectId || 'global'}:${recordId}`
}

export function versionSeqFromUpdatedAt(updatedAt?: string | null): string {
  return updatedAt?.trim() || '0'
}

export function versionSeqFromItem(item: { version_seq?: number; updated_at?: string | null }): string {
  if (item.version_seq != null && Number.isFinite(item.version_seq)) {
    return String(item.version_seq)
  }
  return versionSeqFromUpdatedAt(item.updated_at)
}

export function shouldAcceptVersion(current: string | undefined, incoming: string): boolean {
  if (!current) return true
  if (current === incoming) return true
  return incoming >= current
}
