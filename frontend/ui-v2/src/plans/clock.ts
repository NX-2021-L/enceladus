/**
 * ENC-TSK-S99-0B (ENC-PLN-108 W4.2): the now edge, DOC-5E1E205FA664 section 5.8.
 *
 * An open bar runs to now and a hot wave's window runs to now, so the page has one time-dependent quantity. It is
 * moved by a sixty second tick that does ARITHMETIC AND NOTHING ELSE: no fetch, no corpus call, no cache touch.
 *
 * That restraint is criterion 12 ("an idle Plans page issues only the application's heal deltas for 10 minutes").
 * Freshness is not this timer's job and never was -- it belongs to the corpus heal loop, which already runs on every
 * route, and the page reports it from `lastSeededAt`. This timer exists only so a bar that has been open for four
 * minutes does not keep drawing as though it were one minute long.
 */

import { useEffect, useState } from 'react'

/** Section 5.8: the now edge moves on a one minute tick. The bars are days wide; a faster tick would buy nothing. */
export const NOW_TICK_MS = 60_000

/**
 * The current instant, re-read every `periodMs`.
 *
 * Reading the clock in render instead (`now={Date.now()}`) is what the W3 route did, and it is wrong in both
 * directions: a page that never re-renders freezes its open bars at the instant it mounted, and a page that
 * re-renders for an unrelated reason moves every bar by a few milliseconds and invalidates every memo. A single
 * state value moved on a timer makes the edge move exactly when it should and at no other time.
 */
export function useNowTick(periodMs: number = NOW_TICK_MS): number {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (!Number.isFinite(periodMs) || periodMs <= 0) return
    const id = setInterval(() => {
      setNow(Date.now())
    }, periodMs)
    return () => clearInterval(id)
  }, [periodMs])

  return now
}
