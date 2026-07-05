import type { ProjectSummary } from '../api/projects'
import { resolveProjectFromRecordId } from '../api/projectRegistry'
import type { FeedRealtimeEvent } from '../types/feedEvents'
import type { RecordType } from '../types/records'
import type { LocalSearchRecord } from '../types/search'

const VALID_TYPES: RecordType[] = ['task', 'issue', 'feature', 'plan', 'lesson', 'document']

function normalizeRecordType(raw: string): RecordType | null {
  const t = raw.toLowerCase() as RecordType
  return VALID_TYPES.includes(t) ? t : null
}

/** Build the local search corpus from feed snapshot / realtime events. */
export function buildSearchCorpus(
  events: FeedRealtimeEvent[],
  projects: ProjectSummary[],
): LocalSearchRecord[] {
  const byId = new Map<string, LocalSearchRecord>()

  for (const event of events) {
    const recordType = normalizeRecordType(event.record_type)
    if (!recordType) continue
    const projectId =
      resolveProjectFromRecordId(event.recordId, projects) ?? 'enceladus'
    byId.set(event.recordId, {
      recordId: event.recordId,
      recordType,
      projectId,
      title: event.summary,
      status: event.action,
    })
  }

  return [...byId.values()]
}
