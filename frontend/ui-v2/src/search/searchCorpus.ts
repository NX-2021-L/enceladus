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
    // ENC-TSK-P60 (ENC-ISS-719): the event ACTION ("updated"/"closed") is NOT
    // a lifecycle status — deriving status from it painted every plan/lesson
    // card with an "UPDATED" chip. Use the governed status the snapshot row
    // or full record body carries; leave undefined when neither does.
    const bodyStatus = typeof fullRecord?.status === 'string' ? fullRecord.status : undefined
    const bodyUpdatedAt =
      typeof fullRecord?.updated_at === 'string' ? fullRecord.updated_at : undefined
    byId.set(event.recordId, {
      recordId: event.recordId,
      recordType,
      projectId,
      title: event.recordTitle ?? event.summary,
      status: bodyStatus ?? event.recordStatus,
      priority:
        typeof fullRecord?.priority === 'string' ? fullRecord.priority : event.recordPriority,
      updatedAt: bodyUpdatedAt ?? event.recordUpdatedAt,
      checkoutState:
        typeof fullRecord?.checkout_state === 'string' ? fullRecord.checkout_state : undefined,
    })
  }

  return [...byId.values()]
}

/**
 * ENC-TSK-P60 (ENC-ISS-718/719): overlay an event-derived row onto the warm
 * cache row for the same record WITHOUT destroying the cache row's governed
 * metadata. The old Feed merge replaced the whole cache row, so any record
 * that appeared in the realtime stream lost status/priority/updatedAt and
 * shuffled the sort order on every event batch. Event fields win only when
 * they are actually present; updatedAt takes the newer of the two.
 */
export function mergeEventRowOntoCache(
  cacheRow: LocalSearchRecord,
  eventRow: LocalSearchRecord,
): LocalSearchRecord {
  const newerUpdatedAt =
    eventRow.updatedAt && (!cacheRow.updatedAt || eventRow.updatedAt > cacheRow.updatedAt)
      ? eventRow.updatedAt
      : cacheRow.updatedAt
  return {
    ...cacheRow,
    status: eventRow.status ?? cacheRow.status,
    priority: eventRow.priority ?? cacheRow.priority,
    checkoutState: eventRow.checkoutState ?? cacheRow.checkoutState,
    updatedAt: newerUpdatedAt,
  }
}
