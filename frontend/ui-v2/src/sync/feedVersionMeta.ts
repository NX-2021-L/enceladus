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
