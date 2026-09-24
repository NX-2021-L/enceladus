import { fetchFeedDelta } from '../api/client'
import type { CacheEngine } from './cacheEngine'
import { getFeedVersionSeq, setFeedVersionSeq } from './feedVersionMeta'

export async function healCacheFromDelta(engine: CacheEngine, since?: number): Promise<number> {
  let cursor = since ?? (await getFeedVersionSeq()) ?? 0
  let latest = cursor

  for (let pageNum = 0; pageNum < 20; pageNum += 1) {
    const page = await fetchFeedDelta(cursor)
    if (page.items.length > 0) {
      await engine.ingestCorpusPage(page.items)
    }
    for (const tombstone of page.tombstones) {
      await engine.markTombstone(tombstone.record_key, tombstone.record_id)
    }
    latest = Math.max(latest, page.latest_version_seq ?? cursor)
    if (page.latest_version_seq <= cursor) break
    if (page.items.length === 0 && page.tombstones.length === 0) break
    cursor = page.latest_version_seq
  }

  await setFeedVersionSeq(latest)
  return latest
}
