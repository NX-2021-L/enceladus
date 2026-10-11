import type { FeedCorpusRecord } from './enceladusFeedSource'

/** Same-shape records as backend/lambda/feed_query's /feed/corpus, newest first; one has a multi-line title. */
export const ITEMS: FeedCorpusRecord[] = [
  { record_id: 'ENC-TSK-1120', record_key: 'tracker:enceladus:ENC-TSK-1120', record_type: 'task', project_id: 'enceladus', title: 'Task 1120', updated_at: '2026-09-01T04:00:00Z', version_seq: 4, attrs: { status: 'in-progress', priority: 'P1', checkout_state: 'checked_out' } },
  { record_id: 'ENC-ISS-0042', record_key: 'tracker:enceladus:ENC-ISS-0042', record_type: 'issue', project_id: 'enceladus', title: 'A deliberately long issue title that wraps onto several lines at the narrow widths so the old fixed-height rows would have overlapped the meta line below it', updated_at: '2026-09-01T03:00:00Z', version_seq: 3, attrs: { status: 'open', priority: 'P0' } },
  { record_id: 'ENC-FTR-0007', record_key: 'tracker:enceladus:ENC-FTR-0007', record_type: 'feature', project_id: 'enceladus', title: 'Feature 7', updated_at: '2026-09-01T02:00:00Z', version_seq: 2, attrs: { status: 'planned' } },
  { record_id: 'DOC-ABC123456789', record_key: 'document:enceladus:DOC-ABC123456789', record_type: 'document', project_id: 'enceladus', title: 'A document', updated_at: '2026-09-01T01:00:00Z', version_seq: 1, attrs: {} },
]
