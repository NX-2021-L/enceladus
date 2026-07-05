import type { RecordType } from '../types/records'
import type { SearchResultHit } from '../types/search'

export interface RecentlyViewedEntry {
  recordId: string
  recordType: RecordType
  projectId: string
  title: string
  viewedAt: number
}

const STORAGE_KEY = 'enceladus-ui-v2:recently-viewed'
const MAX_PER_TYPE = 50

type Store = Partial<Record<RecordType, RecentlyViewedEntry[]>>

function readStore(): Store {
  if (typeof localStorage === 'undefined') return {}
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Store
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function writeStore(store: Store): void {
  if (typeof localStorage === 'undefined') return
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store))
}

/** Track a record view; keeps last 50 distinct ids per record type (last-viewed desc). */
export function trackRecentlyViewed(hit: SearchResultHit): RecentlyViewedEntry[] {
  const store = readStore()
  const list = store[hit.recordType] ?? []
  const entry: RecentlyViewedEntry = {
    recordId: hit.recordId,
    recordType: hit.recordType,
    projectId: hit.projectId,
    title: hit.title,
    viewedAt: Date.now(),
  }
  const without = list.filter((row) => row.recordId !== hit.recordId)
  const next = [entry, ...without].slice(0, MAX_PER_TYPE)
  store[hit.recordType] = next
  writeStore(store)
  return next
}

export function getRecentlyViewed(recordType: RecordType): RecentlyViewedEntry[] {
  return readStore()[recordType] ?? []
}

export function hitFromRecent(entry: RecentlyViewedEntry): SearchResultHit {
  return {
    recordId: entry.recordId,
    recordType: entry.recordType,
    projectId: entry.projectId,
    title: entry.title,
    tier: 'local',
  }
}
