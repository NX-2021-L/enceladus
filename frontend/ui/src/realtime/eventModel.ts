/**
 * Feed event data model + runtime validator (ENC-TSK-B67 AC-10 / AC-23).
 *
 * North Star contract (DOC-E470AC8CE9A8): the client is a thin reactive
 * rendering surface. Every WebSocket message arriving from AppSync Events is a
 * fully pre-rendered payload computed by the FeedPublisher Lambda. The client's
 * ONLY responsibilities are `JSON.parse()` (done by the transport) and a cheap
 * structural validation here — zero text generation, zero aggregation, zero
 * diffing, zero summary computation.
 *
 * The shape mirrors backend `realtime_payload.build_event_payload` exactly.
 */

import type { ContextNodeMeta } from '../types/feeds'

export type ActorType = 'human' | 'agent'

export type FeedAction =
  | 'created'
  | 'updated'
  | 'closed'
  | 'status_changed'
  | 'worklog_appended'
  | 'create_relationship'
  | 'removed'
  | string

/** The exact event contract delivered over AppSync Events (AC-10). */
export interface FeedEvent {
  /** UUID v7 — timestamp-sortable, globally unique (dedup + ordering). */
  eventId: string
  recordId: string
  record_type: string
  action: FeedAction
  actorType: ActorType
  actorId: string
  /** Pre-rendered, ready-to-render display string. Backend computes it. */
  summary: string
  /** Monotonically increasing integer for pagination + gap detection. */
  cursor: number
  /** Absolute per-record context-node scores (AC-22). */
  context_node?: ContextNodeMeta
  /** Transport metadata (not part of the AC-10 core render model). */
  projectId?: string
  occurred_at?: string
  version?: string
  /** Client-only marker for an optimistic, not-yet-confirmed event. */
  pending?: boolean
}

/** Control frames the server can push on the same channel. */
export interface GapTooLargeSignal {
  type: 'gap_too_large'
  /** The cursor the client last saw; gap exceeds the replay threshold. */
  lastReceivedCursor?: number
}

export type RealtimeFrame = FeedEvent | GapTooLargeSignal

const UUID_V7_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function isGapTooLarge(frame: unknown): frame is GapTooLargeSignal {
  return (
    typeof frame === 'object' &&
    frame !== null &&
    (frame as { type?: unknown }).type === 'gap_too_large'
  )
}

/**
 * Validate-and-narrow an already-JSON-parsed frame into a FeedEvent.
 *
 * Returns null when the payload does not satisfy the AC-10 contract, so the
 * client can drop malformed frames rather than rendering garbage. This is the
 * full extent of client-side "processing" allowed by the North Star contract.
 */
export function parseFeedEvent(raw: unknown): FeedEvent | null {
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw)
    } catch {
      return null
    }
  }
  if (typeof raw !== 'object' || raw === null) return null
  const o = raw as Record<string, unknown>

  if (typeof o.eventId !== 'string' || !UUID_V7_RE.test(o.eventId)) return null
  if (typeof o.recordId !== 'string' || !o.recordId) return null
  if (typeof o.record_type !== 'string') return null
  if (typeof o.action !== 'string') return null
  if (o.actorType !== 'human' && o.actorType !== 'agent') return null
  if (typeof o.actorId !== 'string') return null
  if (typeof o.summary !== 'string') return null
  if (typeof o.cursor !== 'number' || !Number.isFinite(o.cursor)) return null

  const event: FeedEvent = {
    eventId: o.eventId,
    recordId: o.recordId,
    record_type: o.record_type,
    action: o.action,
    actorType: o.actorType,
    actorId: o.actorId,
    summary: o.summary,
    cursor: o.cursor,
  }
  if (isContextNode(o.context_node)) event.context_node = o.context_node
  if (typeof o.projectId === 'string') event.projectId = o.projectId
  if (typeof o.occurred_at === 'string') event.occurred_at = o.occurred_at
  if (typeof o.version === 'string') event.version = o.version
  return event
}

function isContextNode(v: unknown): v is ContextNodeMeta {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  return (
    typeof o.freshness_score === 'number' &&
    typeof o.structural_importance === 'number' &&
    typeof o.information_density === 'number' &&
    typeof o.access_frequency === 'number'
  )
}
