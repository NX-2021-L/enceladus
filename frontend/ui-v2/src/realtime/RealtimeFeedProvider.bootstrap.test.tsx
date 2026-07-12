import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RealtimeFeedProvider } from './RealtimeFeedProvider'

/**
 * ENC-TSK-M82 (AC-2) — realtime bootstrap regression guard.
 *
 * The field defect: the AppSync client was NEVER constructed on PWA load even
 * though the deployed bundle carried complete, enabled config (httpHost +
 * realtimeHost + `da2-…` apiKey). Root cause: the connect effect depended on
 * the (unstable) `snapshotQuery` result object, so it churned — tearing the
 * socket down and rebuilding it on every snapshot state change — instead of
 * initiating one stable connection on mount.
 *
 * These tests fail if RealtimeFeedProvider mounts without initiating a
 * connection attempt, and if it rebuilds the client when the snapshot query
 * settles (the exact coupling that caused the regression). No
 * @testing-library/react in this package — react-dom/client createRoot + act,
 * matching RealtimeFeedProvider.test.tsx.
 */

let constructCount = 0
let startCount = 0
let stopCount = 0
let resolveSnapshot: (() => void) | null = null

vi.mock('../api/appsyncConfig', () => ({
  getAppSyncEventsConfig: () => ({
    httpHost: 'oymlzdcptfhuff3egfyt473nrm.appsync-api.us-west-2.amazonaws.com',
    realtimeHost: 'oymlzdcptfhuff3egfyt473nrm.appsync-realtime-api.us-west-2.amazonaws.com',
    apiKey: 'da2-testkeytestkeytestkey',
    region: 'us-west-2',
    feedChannel: '/feed/updates',
    enabled: true,
  }),
}))

// Snapshot resolves only when the test allows it — this lets us drive the
// pending→success transition explicitly and assert the socket is NOT rebuilt
// when `snapshotQuery` changes identity.
vi.mock('../api/feeds', () => ({
  fetchFeedSnapshot: () =>
    new Promise((resolve) => {
      resolveSnapshot = () =>
        resolve({ events: [], hydratedAt: '2026-07-12T00:00:00Z', source: 's3' as const })
    }),
}))

vi.mock('./appsyncRealtimeClient', () => ({
  AppSyncRealtimeClient: class {
    constructor() {
      constructCount += 1
    }
    start() {
      startCount += 1
    }
    stop() {
      stopCount += 1
    }
    manualRetry() {}
    watchRecord() {
      return () => {}
    }
  },
}))

vi.mock('../sync/cacheEngine', () => ({
  getCacheEngine: () => ({
    upsertTier1: () => Promise.resolve(),
    markTombstone: () => Promise.resolve(),
  }),
  tier1FromFeedEvent: () => null,
}))

describe('RealtimeFeedProvider — bootstrap connection attempt (ENC-TSK-M82 AC-2)', () => {
  let qc: QueryClient
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    constructCount = 0
    startCount = 0
    stopCount = 0
    resolveSnapshot = null
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
    qc.clear()
  })

  function mount() {
    act(() => {
      root.render(
        <QueryClientProvider client={qc}>
          <RealtimeFeedProvider>
            <div />
          </RealtimeFeedProvider>
        </QueryClientProvider>,
      )
    })
  }

  it('mounting the provider (config enabled) initiates a connection attempt', () => {
    mount()
    // The regression this guards: zero sockets constructed on load.
    expect(constructCount).toBeGreaterThanOrEqual(1)
    expect(startCount).toBeGreaterThanOrEqual(1)
  })

  it('constructs exactly ONE client on mount — the socket is not coupled to the snapshot query', async () => {
    mount()
    expect(constructCount).toBe(1)
    expect(startCount).toBe(1)

    // Drive the snapshot pending→success transition. Pre-fix, `snapshotQuery`
    // was a connect-effect dependency, so this re-render tore down and rebuilt
    // the client (constructCount would climb). The socket must stay put.
    await act(async () => {
      resolveSnapshot?.()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    expect(constructCount).toBe(1)
    expect(stopCount).toBe(0)
  })
})
