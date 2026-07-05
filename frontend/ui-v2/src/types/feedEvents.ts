/** AppSync Events payload contract (B67 AC-10 / appsync_feed_publisher). */

export type FeedAction = 'created' | 'updated' | 'closed' | 'removed'
export type FeedActorType = 'human' | 'agent'

export interface FeedRealtimeEvent {
  eventId: string
  recordId: string
  record_type: string
  action: FeedAction
  actorType: FeedActorType
  actorId: string
  summary: string
  cursor: number
  channels: string[]
  /**
   * ENC-TSK-L29: the full current record body, present ONLY on events
   * delivered over a per-record `/records/{recordId}` subscription (never on
   * the `/feed/updates` or `/projects/{id}` channels, which keep the fixed
   * AC-23 payload budget). Lets the client mirror (ENC-TSK-L24) upsert
   * directly with no follow-up fetch.
   */
  record?: Record<string, unknown>
}

export interface FeedSnapshot {
  events: FeedRealtimeEvent[]
  hydratedAt: string
  source: 's3' | 'realtime'
}

export type RealtimeConnectionPhase =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'disconnected'
  | 'manual_retry'

/** Client-side signal when cursor gap exceeds replay threshold (DOC-E470AC8CE9A8 §5.4). */
export interface GapTooLargeSignal {
  type: 'gap_too_large'
  lastCursor: number
  reason: string
}
