import { fetchFeedCorpusPage } from '../api/client'
import { getCacheEngine } from './cacheEngine'
import { healCacheFromDelta } from './deltaHeal'
import { maxVersionSeqFromItems, setFeedVersionSeq } from './feedVersionMeta'

export async function seedCacheFromCorpus(): Promise<{ pages: number; records: number; durationMs: number }> {
  const engine = getCacheEngine()
  const startedAt = performance.now()
  let cursor: string | undefined
  let pages = 0
  let records = 0
  let versionSeq = 0

  for (;;) {
    const page = await fetchFeedCorpusPage({ cursor, limit: 200 })
    pages += 1
    records += await engine.ingestCorpusPage(page.items)
    versionSeq = maxVersionSeqFromItems(page.items, versionSeq)
    if (!page.next_cursor) break
    cursor = page.next_cursor
  }

  await engine.finalizeWarm()
  engine.markWarmComplete(startedAt)
  if (versionSeq > 0) {
    await setFeedVersionSeq(versionSeq)
  }
  await healCacheFromDelta(engine, versionSeq)
  return {
    pages,
    records,
    durationMs: Math.round(performance.now() - startedAt),
  }
}
