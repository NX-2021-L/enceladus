import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { FeedPane } from './FeedPane'
import { useFeedBufferStore } from '../store/feedBufferStore'
import type { FeedRealtimeEvent } from '../types/feedEvents'

/**
 * ENC-TSK-K24 (B67 AC-11). No @testing-library/react in this package —
 * react-dom/client createRoot + act, matching the established convention.
 */

const mergeBufferedEvents = vi.fn(() => 0)

vi.mock('../realtime/RealtimeFeedProvider', () => ({
  useRealtimeFeed: () => ({
    isHydrating: false,
    isSnapshotError: false,
    refetchSnapshot: () => {},
    manualReconnect: () => {},
    mergeBufferedEvents,
    watchRecord: () => () => {},
  }),
  // ENC-TSK-M73 (B67 AC-13): the visible list now comes from the
  // REALTIME_FEED_QUERY_KEY cache via this hook, not from the context.
  useRealtimeFeedEvents: () => [] as FeedRealtimeEvent[],
}))

describe('FeedPane — new-activities banner (ENC-TSK-K24 / B67 AC-11)', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    useFeedBufferStore.getState().clear()
    mergeBufferedEvents.mockClear()
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('reserves the banner slot even with zero buffered events (CLS 0.0 — the slot never appears/disappears)', () => {
    act(() => {
      root.render(<FeedPane />)
    })
    const slot = container.querySelector('[data-testid="new-activities-banner-slot"]')
    expect(slot).not.toBeNull()
    expect((slot as HTMLElement).style.height).not.toBe('')
    expect(container.querySelector('[data-testid="new-activities-banner"]')).toBeNull()
  })

  it('shows the "{N} new activities" banner once events are buffered, inside the SAME reserved slot', () => {
    act(() => {
      root.render(<FeedPane />)
    })

    act(() => {
      useFeedBufferStore.getState().bufferEvent({
        eventId: 'e1',
        recordId: 'ENC-TSK-K24',
        record_type: 'task',
        action: 'updated',
        actorType: 'agent',
        actorId: 'ENC-SES-001',
        summary: 'test',
        cursor: 1,
        channels: ['/feed/updates'],
      })
    })

    const slot = container.querySelector('[data-testid="new-activities-banner-slot"]')
    const banner = container.querySelector('[data-testid="new-activities-banner"]')
    expect(banner).not.toBeNull()
    expect(slot?.contains(banner)).toBe(true)
    expect(banner?.textContent).toContain('1 new activity')
  })

  it('pluralizes correctly and clicking Show calls mergeBufferedEvents', () => {
    act(() => {
      root.render(<FeedPane />)
    })

    act(() => {
      useFeedBufferStore.getState().bufferEvent({
        eventId: 'e1',
        recordId: 'ENC-TSK-K24',
        record_type: 'task',
        action: 'updated',
        actorType: 'agent',
        actorId: 'ENC-SES-001',
        summary: 'a',
        cursor: 1,
        channels: [],
      })
      useFeedBufferStore.getState().bufferEvent({
        eventId: 'e2',
        recordId: 'ENC-TSK-K24',
        record_type: 'task',
        action: 'updated',
        actorType: 'agent',
        actorId: 'ENC-SES-001',
        summary: 'b',
        cursor: 2,
        channels: [],
      })
    })

    expect(container.querySelector('[data-testid="new-activities-banner"]')?.textContent).toContain('2 new activities')

    const showButton = container.querySelector('[data-testid="new-activities-banner"] button')
    act(() => {
      showButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(mergeBufferedEvents).toHaveBeenCalledTimes(1)
  })
})
