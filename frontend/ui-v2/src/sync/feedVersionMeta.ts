import { getMeta, setMeta } from './idbStore'

const META_KEY = 'feed_version_seq'
// ENC-TSK-Q34: document_api numbers document writes from its own counter, a
// sequence space independent of the tracker's, so it gets its own cursor.
const DOC_META_KEY = 'feed_doc_version_seq'

/** Per-space delta cursors. Never compared or max()-merged across spaces. */
export interface FeedCursors {
  tracker: number
  document: number
}

async function readCursor(key: string): Promise<number | null> {
  const raw = await getMeta(key)
  if (raw == null) return null
  const value = Number(raw)
  return Number.isFinite(value) ? value : null
}

export async function getFeedCursors(): Promise<{ tracker: number | null; document: number | null }> {
  return { tracker: await readCursor(META_KEY), document: await readCursor(DOC_META_KEY) }
}

export async function setFeedCursors(cursors: FeedCursors): Promise<void> {
  await setMeta(META_KEY, cursors.tracker)
  await setMeta(DOC_META_KEY, cursors.document)
}

/** ENC-TSK-Q34 (AC-2): highest version_seq per sequence space in a corpus page. */
export function maxVersionSeqBySource(
  items: Array<{ version_seq?: number; source?: string }>,
  current: FeedCursors = { tracker: 0, document: 0 },
): FeedCursors {
  let { tracker, document } = current
  for (const item of items) {
    if (item.version_seq == null || !Number.isFinite(item.version_seq)) continue
    if (item.source === 'document') document = Math.max(document, item.version_seq)
    else tracker = Math.max(tracker, item.version_seq)
  }
  return { tracker, document }
}

const CORPUS_SEEDED_AT_KEY = 'corpus_seeded_at'

/** ENC-TSK-Q33: when the last corpus seed completed on this device, so a
 *  failed refresh can say how old the cached list is. */
export async function getCorpusSeededAt(): Promise<string | null> {
  const raw = await getMeta(CORPUS_SEEDED_AT_KEY)
  return typeof raw === 'string' && raw ? raw : null
}

export async function setCorpusSeededAt(iso: string): Promise<void> {
  await setMeta(CORPUS_SEEDED_AT_KEY, iso)
}
