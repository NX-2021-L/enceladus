import { fetchFeedDelta } from '../api/client'
import type { CacheEngine } from './cacheEngine'
import { getFeedCursors, setFeedCursors, type FeedCursors } from './feedVersionMeta'

const MAX_DELTA_PAGES = 20

/**
 * Pull tracker and document changes newer than the stored (or given) cursors.
 * ENC-TSK-Q34: the two sequence spaces travel as separate cursors (since /
 * doc_since) and are persisted separately; the server windows each response
 * and flags `truncated` / `doc_truncated` when more remain.
 */
export async function healCacheFromDelta(
  engine: CacheEngine,
  start: Partial<FeedCursors> = {},
): Promise<FeedCursors> {
  const stored = await getFeedCursors()
  let tracker = start.tracker ?? stored.tracker ?? 0
  let document = start.document ?? stored.document ?? 0

  for (let pageNum = 0; pageNum < MAX_DELTA_PAGES; pageNum += 1) {
    const page = await fetchFeedDelta({ since: tracker, docSince: document })
    if (page.items.length > 0) {
      await engine.ingestCorpusPage(page.items)
    }
    for (const tombstone of page.tombstones) {
      await engine.markTombstone(tombstone.record_key, tombstone.record_id, {
        versionSeq: String(tombstone.version_seq),
        projectId: tombstone.project_id || (tombstone.record_type === 'document' ? 'global' : undefined),
      })
    }
    const nextTracker = Math.max(tracker, page.latest_version_seq ?? tracker)
    const nextDocument = Math.max(document, page.latest_doc_version_seq ?? document)
    const advanced = nextTracker > tracker || nextDocument > document
    tracker = nextTracker
    document = nextDocument
    // Pre-Q34 servers send no window flags: keep paging while it advances.
    const windowed = page.truncated !== undefined || page.doc_truncated !== undefined
    const more = windowed
      ? Boolean(page.truncated || page.doc_truncated)
      : page.items.length > 0 || page.tombstones.length > 0
    if (!advanced || !more) break
  }

  await setFeedCursors({ tracker, document })
  return { tracker, document }
}
