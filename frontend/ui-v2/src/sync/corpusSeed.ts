import { fetchFeedCorpusPage } from '../api/client'
import { getCacheEngine } from './cacheEngine'
import { healCacheFromDelta } from './deltaHeal'
import { maxVersionSeqBySource, type FeedCursors } from './feedVersionMeta'

export async function seedCacheFromCorpus(): Promise<{ pages: number; records: number; durationMs: number }> {
  const engine = getCacheEngine()
  const startedAt = performance.now()
  let cursor: string | undefined
  let pages = 0
  let records = 0
  // ENC-TSK-Q34 (AC-2): corpus items carry version_seq per sequence space, so
  // the heal below resumes from what this snapshot already contains instead
  // of replaying the whole history from since=0.
  let cursors: FeedCursors = { tracker: 0, document: 0 }

  for (;;) {
    const page = await fetchFeedCorpusPage({ cursor, limit: 200 })
    pages += 1
    records += await engine.ingestCorpusPage(page.items)
    cursors = maxVersionSeqBySource(page.items, cursors)
    if (!page.next_cursor) break
    cursor = page.next_cursor
  }

  await engine.finalizeWarm()
  engine.markWarmComplete(startedAt)
  await healCacheFromDelta(engine, cursors)
  return {
    pages,
    records,
    durationMs: Math.round(performance.now() - startedAt),
  }
}
