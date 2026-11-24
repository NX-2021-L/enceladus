/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): time text of the Plans page, in Pacific time (ruling D-19: the axis, the tick labels
 * and every stamp the page prints are Pacific wall clock; governed records keep UTC).
 *
 * Pure: the zone rules come from Intl, no clock is read. Durations are not formatted here: the lens already owns
 * `formatSkipped` ("3h 1m", "2d 4h"), and the page prints every duration with it so a fold label, a wait and a work time
 * read the same way.
 */
import { TICK_TIME_ZONE } from './lens/layoutTime'

const day = new Intl.DateTimeFormat('en-US', { timeZone: TICK_TIME_ZONE, month: 'short', day: 'numeric' })
const clock = new Intl.DateTimeFormat('en-US', { timeZone: TICK_TIME_ZONE, hourCycle: 'h23', hour: '2-digit', minute: '2-digit' })
const clockSeconds = new Intl.DateTimeFormat('en-US', { timeZone: TICK_TIME_ZONE, hourCycle: 'h23', hour: '2-digit', minute: '2-digit', second: '2-digit' })
const zone = new Intl.DateTimeFormat('en-US', { timeZone: TICK_TIME_ZONE, timeZoneName: 'short' })

/** "Nov 13": the Pacific calendar day. */
export const formatDay = (ms: number): string => day.format(ms)

/** "15:31": the Pacific wall clock. */
export const formatClock = (ms: number): string => clock.format(ms)

/** "PST" or "PDT" at that instant. */
export const formatZone = (ms: number): string => zone.formatToParts(ms).find((p) => p.type === 'timeZoneName')?.value ?? ''

/** "Nov 13 15:31": the stamp inside a task's tooltip. */
export const formatStamp = (ms: number): string => `${formatDay(ms)} ${formatClock(ms)}`

/** "Nov 13 15:31 PST": the plan card's created text. */
export const formatStampZone = (ms: number): string => `${formatStamp(ms)} ${formatZone(ms)}`

/** "15:59:12 PST": the corpus freshness text. */
export const formatClockSecondsZone = (ms: number): string => `${clockSeconds.format(ms)} ${formatZone(ms)}`

/** Epoch ms of an ISO string, a number or a Date; null when it is absent or does not parse. */
export function toMs(v: string | number | Date | null | undefined): number | null {
  if (v === null || v === undefined || v === '') return null
  const ms = v instanceof Date ? v.getTime() : typeof v === 'number' ? v : Date.parse(v)
  return Number.isFinite(ms) ? ms : null
}
