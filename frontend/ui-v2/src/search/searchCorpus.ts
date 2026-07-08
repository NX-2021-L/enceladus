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
    // ENC-FTR-130 Band-B: `record` (full body) is only present on per-record
    // subscription events (ENC-TSK-L29) -- best-effort only. The warm cache
    // path (sync/searchIndex.ts::tier1ToLocalSearchRecord) is the reliable
    // source for priority/checkout_state; this just avoids a cold-start gap.
    const fullRecord = event.record
    byId.set(event.recordId, {
      recordId: event.recordId,
      recordType,
      projectId,
      title: event.summary,
      status: event.action,
      priority: typeof fullRecord?.priority === 'string' ? fullRecord.priority : undefined,
      checkoutState:
        typeof fullRecord?.checkout_state === 'string' ? fullRecord.checkout_state : undefined,
    })
  }

  return [...byId.values()]
}
