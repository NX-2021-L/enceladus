import type { FeedRealtimeEvent, FeedSnapshot } from '../types/feedEvents'

const FEED_BASE = (import.meta.env.VITE_FEED_BASE_URL ?? '/mobile/v1').replace(/\/$/, '')

async function fetchJson<T>(path: string): Promise<T> {
  const url = `${FEED_BASE}/${path}?_t=${Date.now()}`
  const res = await fetch(url, {
    credentials: 'include',
    cache: 'no-store',
    headers: {
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    },
  })
  if (!res.ok) throw new Error(`Feed fetch failed (${path}): ${res.status}`)
  return res.json() as Promise<T>
}

/** Minimal S3 snapshot row used to seed the feed before WSS connects. */
interface SnapshotTask {
  item_id?: string
  id?: string
  title?: string
  status?: string
  record_type?: string
  updated_at?: string
}

interface TasksSnapshot {
  tasks?: SnapshotTask[]
  generated_at?: string
}

function taskToFeedEvent(task: SnapshotTask, cursor: number): FeedRealtimeEvent | null {
  const recordId = task.item_id ?? task.id
  if (!recordId) return null
  const title = task.title ?? recordId
  const status = task.status ?? 'open'
  return {
    eventId: `snapshot-${recordId}`,
    recordId,
    record_type: task.record_type ?? 'task',
    action: status === 'closed' ? 'closed' : 'updated',
    actorType: 'agent',
    actorId: 'feed-snapshot',
    summary: `${recordId}: ${title}`,
    cursor,
    channels: ['/feed/updates'],
  }
}

/**
 * Cold-start hydrate from the pre-computed S3 feed (B67 AC-4).
 * Uses tasks.json as the primary snapshot; other feeds can extend this later.
 */
export async function fetchFeedSnapshot(): Promise<FeedSnapshot> {
  const data = await fetchJson<TasksSnapshot>('tasks.json')
  const baseCursor = data.generated_at
    ? Date.parse(data.generated_at) * 1000
    : Date.now() * 1000

  const events = (data.tasks ?? [])
    .map((task, index) => taskToFeedEvent(task, baseCursor + index))
    .filter((event): event is FeedRealtimeEvent => event !== null)
    .sort((a, b) => b.cursor - a.cursor)
    .slice(0, 50)

  return {
    events,
    hydratedAt: new Date().toISOString(),
    source: 's3',
  }
}
