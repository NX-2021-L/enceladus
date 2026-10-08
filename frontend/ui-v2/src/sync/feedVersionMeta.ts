import { getMeta, setMeta } from './idbStore'

const META_KEY = 'feed_version_seq'

export async function getFeedVersionSeq(): Promise<number | null> {
  const raw = await getMeta(META_KEY)
  if (raw == null) return null
  const value = Number(raw)
  return Number.isFinite(value) ? value : null
}

export async function setFeedVersionSeq(value: number): Promise<void> {
  await setMeta(META_KEY, value)
}

export function maxVersionSeqFromItems(items: Array<{ version_seq?: number }>, current = 0): number {
  let latest = current
  for (const item of items) {
    if (item.version_seq != null) {
      latest = Math.max(latest, item.version_seq)
    }
  }
  return latest
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
