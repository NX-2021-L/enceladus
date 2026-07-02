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
