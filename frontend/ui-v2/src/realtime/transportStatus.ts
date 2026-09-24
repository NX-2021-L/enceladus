import type { RealtimeConnectionPhase } from '../types/feedEvents'

/**
 * ENC-TSK-M82 (AC-3): the single source of truth for the feed header's
 * transport label. The header must claim `LIVE` ONLY when the AppSync WSS is
 * actually connected — i.e. the socket is open AND `connection_ack` has been
 * received, which is precisely the moment the client emits `connected` and the
 * connection store transitions to phase `'connected'`. Every other phase
 * (idle, connecting, reconnecting, disconnected, manual_retry) means the feed
 * is being served from the S3 snapshot + delta-poll fallback, so the label is
 * an honest `SNAPSHOT` rather than a decorative, always-on `LIVE`.
 *
 * Before this task the eyebrow rendered a hardcoded `FEED · LIVE`, which masked
 * a total transport failure from human observation (io probe 2026-07-12).
 */
export function feedTransportLabel(phase: RealtimeConnectionPhase): 'LIVE' | 'SNAPSHOT' {
  return phase === 'connected' ? 'LIVE' : 'SNAPSHOT'
}
