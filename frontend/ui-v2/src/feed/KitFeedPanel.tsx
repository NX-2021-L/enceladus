import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { createFeed, FeedList, useFeed } from '@io-kit/feed/react'
import { createIdbStorage } from '@io-kit/feed/idb'
import { useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { useFeedConnectionStore } from '../store/feedConnectionStore'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { feedCorpusQueryOptions } from '../api/feedCorpusQueryOptions'
import { relateRecords } from '../api/actions'
import { Alert } from '../design-system'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { FeedReadingPane } from '../routes/FeedReadingPane'
import { RecentlyViewedNav } from '../routes/RecentlyViewedNav'
import { applyPropertyFilter } from '../search/applyPropertyFilter'
import { FeedPropertyFilter } from '../search/FeedPropertyFilter'
import { parseFilterQuery, persistFeedReturnSearch, serializeFilterQuery, type FeedRouteSearch } from '../search/feedSearchParams'
import { getRecentlyViewed, hitFromRecent, trackRecentlyViewed } from '../search/recentlyViewed'
import { sortSearchHits } from '../search/sortSearchHits'
import { useTieredSearch } from '../search/useTieredSearch'
import { useKeystrokeSuggestionTelemetry, useRequestFirstPageTelemetry } from '../search/useSearchTelemetry'
import { useUiStore } from '../store/uiStore'
import type { LocalSearchRecord, SearchResultHit } from '../types/search'
import type { RecordType } from '../types/records'
import { createEnceladusFeedSource, createSignalBridge, type FeedCorpusRecord } from './enceladusFeedSource'
import { FeedHeader, FeedMeta, FeedToolbar, useSavedSearches } from './FeedChrome'
import { renderFeedRow, type PinState } from './FeedRowCard'
import { createHitView, feedHitCount } from './hitView'

const WIDE_MEDIA = '(min-width: 64rem)'
const VALID_TYPES: RecordType[] = ['task', 'issue', 'feature', 'plan', 'lesson', 'document']
const WARM_START_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

/** feed_query corpus record -> the host's search row (status/priority/checkout_state ride in attrs). */
export function toSearchRow(r: FeedCorpusRecord): LocalSearchRecord | null {
  const recordType = String(r.record_type).toLowerCase() as RecordType
  if (!VALID_TYPES.includes(recordType)) return null
  const attrs = (r.attrs ?? {}) as Record<string, unknown>
  const str = (k: string): string | undefined => {
    const v = r[k] ?? attrs[k]
    return typeof v === 'string' && v ? v : undefined
  }
  const status = str('status')
  const priority = str('priority')
  const checkoutState = str('checkout_state')
  const updatedAt = str('updated_at')
  return {
    recordId: r.record_id,
    recordType,
    projectId: r.project_id ?? 'enceladus',
    title: r.title ?? '',
    ...(status ? { status } : {}),
    ...(priority ? { priority } : {}),
    ...(checkoutState ? { checkoutState } : {}),
    ...(updatedAt ? { updatedAt } : {}),
  }
}

/**
 * DVP-TSK-919 (DVP-PLN-011 E3-W2.6) / DVP-TSK-931: /feed on @io-kit/feed -- keyset paging over signed cursors,
 * since-seq deltas, insert buffer + newer-items pill, IndexedDB warm start, scroll restore and measured-height
 * virtualization (feed 1.1) from the kit. The page itself is the legacy design: the same header, toolbar,
 * property filter, record cards (renderFeedRow through FeedList's renderCard/as/itemAs slots), reading pane and
 * pin action. Search, property filters and sort run host-side over the loaded corpus (hitView).
 */
export default function KitFeedPanel() {
  useDocumentTitle('Feed')
  const feedSearch = useSearch({ from: '/feed' })
  const navigate = useNavigate({ from: '/feed' })
  const { q, f, op, sort } = feedSearch
  const filterQuery = parseFilterQuery(f, op)
  const patchFeedSearch = (patch: Partial<FeedRouteSearch>, replace = true) => {
    navigate({
      search: (prev) => {
        const next = { ...prev, ...patch }
        persistFeedReturnSearch(next)
        return next
      },
      replace,
    })
  }
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const [bridge] = useState(() => createSignalBridge())
  const [feed] = useState(() =>
    createFeed<FeedCorpusRecord, { sort: string }>({
      source: createEnceladusFeedSource({ subscribe: bridge.subscribe }),
      filter: { sort: 'updated_at_desc' },
      pageSize: 50,
      buffer: 'pill',
      persist: { idb: 'enceladus-feed', maxAgeMs: WARM_START_MAX_AGE_MS, storage: createIdbStorage({ dbName: 'ev2-feed' }) },
    }),
  )

  useEffect(() => {
    void feed.start()
    const onVisible = () => {
      if (document.visibilityState === 'visible') void feed.resume()
    }
    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('pageshow', onVisible)
    return () => {
      document.removeEventListener('visibilitychange', onVisible)
      window.removeEventListener('pageshow', onVisible)
      feed.dispose()
    }
  }, [feed])

  // The existing AppSync provider (reconnect backoff + liveness watchdog now come from the kit /appsync policy)
  // reports connection phase and delivers events; both become kit signals, never items.
  const phase = useFeedConnectionStore((s) => s.phase)
  const events = useRealtimeFeedEvents()
  useEffect(() => {
    bridge.status(phase === 'connected' ? 'live' : phase === 'connecting' ? 'connecting' : 'snapshot')
  }, [bridge, phase])
  useEffect(() => {
    if (events.length > 0) bridge.emit()
  }, [bridge, events.length])

  const state = useFeed(feed)
  const [view] = useState(() => createHitView<FeedCorpusRecord>(feed as never))

  // Host-side search over the loaded corpus, identical to LegacyFeedRoute: tiered (local + hybrid) search,
  // property filter, sort.
  const rows = state.items.map(toSearchRow).filter((r): r is LocalSearchRecord => r !== null)
  const projectId = projects[0]?.project_id ?? 'enceladus'
  const tiered = useTieredSearch({ projectId, query: q }, rows)
  const filteredHits = sortSearchHits(applyPropertyFilter(tiered.hits, filterQuery), sort)
  useLayoutEffect(() => view.setHits(filteredHits))
  useRequestFirstPageTelemetry(`${q}|${f}|${op}|${sort}`, Boolean(q.trim()), tiered.hybridPending)

  const serverCorpusTotal = useQuery(feedCorpusQueryOptions({ limit: 1 })).data?.total_matches ?? null

  const needle = q.trim().toLowerCase()
  const suggestions = rows
    .filter((r) => !needle || r.recordId.toLowerCase().includes(needle) || r.title.toLowerCase().includes(needle))
    .slice(0, 12)
    .map((r) => ({ value: r.recordId, description: r.title, tag: r.recordType }))
  const { markKeystroke } = useKeystrokeSuggestionTelemetry(suggestions.map((s) => s.value).join(','))
  const { savedItems, handleSavedClick } = useSavedSearches(q, filterQuery, patchFeedSearch)

  const [isWide, setIsWide] = useState(false)
  const [chosen, setChosen] = useState<SearchResultHit | null>(null)
  const recentItems = useUiStore((s) => s.recentItems)
  const setRecentItems = useUiStore((s) => s.setRecentItems)
  const listRef = useRef<HTMLDivElement>(null)
  // Wide: the reader's pick if it is still listed, else the first hit (derived, not synced through an effect).
  const selectedHit: SearchResultHit | null =
    isWide && filteredHits.length > 0
      ? (chosen && filteredHits.find((h) => h.recordId === chosen.recordId)) || filteredHits[0]!
      : null
  const selectHit = (hit: SearchResultHit) => setChosen(hit)
  const selectedId = selectedHit?.recordId ?? null
  const selectedType = selectedHit?.recordType
  useEffect(() => {
    if (!selectedHit) return
    trackRecentlyViewed(selectedHit)
    setRecentItems(getRecentlyViewed(selectedHit.recordType))
    // keyed on the selection identity, not the hit object (rebuilt every render)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, selectedType])
  useEffect(() => {
    persistFeedReturnSearch(feedSearch)
  }, [feedSearch])
  useEffect(() => {
    const mq = window.matchMedia(WIDE_MEDIA)
    const sync = () => setIsWide(mq.matches)
    sync()
    mq.addEventListener('change', sync)
    return () => mq.removeEventListener('change', sync)
  }, [])
  const [pins, setPins] = useState<Record<string, PinState>>({})
  function pinToSelected(sourceId: string, targetId: string) {
    setPins((p) => ({ ...p, [targetId]: 'pending' }))
    relateRecords(sourceId, targetId).then(
      () => setPins((p) => ({ ...p, [targetId]: 'done' })),
      () => setPins((p) => ({ ...p, [targetId]: 'error' })),
    )
  }

  const split = isWide && filteredHits.length > 0
  const list = (
    <FeedList<SearchResultHit>
      feed={view}
      as="div"
      itemAs="div"
      {...(split ? {} : { className: 'ev2-rc-grid' })}
      estimateSize={split ? 96 : 120}
      renderCard={(hit) =>
        renderFeedRow(hit, {
          projects,
          isWide,
          selectedHit,
          onSelect: selectHit,
          onLeave: () => persistFeedReturnSearch(feedSearch),
          tiered,
          pins,
          onPin: pinToSelected,
        })
      }
      renderStatus={{
        // Legacy shows no notice while a cached snapshot refreshes (its stale alert is for seed errors only).
        stale: () => null,
        gap: (ack) => (
          <div className="feed-route__stale">
            <Alert type="warning" header="Some updates were missed">
              The feed resynced.{' '}
              <button type="button" className="feed-route__empty-action" onClick={ack}>
                Dismiss
              </button>
            </Alert>
          </div>
        ),
        error: (retry) => (
          <p className="feed-route__empty">
            Couldn&apos;t load the feed.
            <button type="button" className="feed-route__empty-action" onClick={retry}>
              Retry
            </button>
          </p>
        ),
        moreError: (retry) => (
          <p className="feed-route__empty">
            <button type="button" className="feed-route__empty-action" onClick={retry}>
              Retry loading more
            </button>
          </p>
        ),
        pill: (n, flush) => (
          <button type="button" className="feed-route__empty-action" onClick={flush}>
            {n} new {n === 1 ? 'item' : 'items'}
          </button>
        ),
      }}
    />
  )

  return (
    <div className="feed-route" data-feed-engine="kit">
      <FeedHeader />
      <FeedToolbar
        q={q}
        sort={sort}
        suggestions={suggestions}
        savedItems={savedItems}
        onSavedItemClick={handleSavedClick}
        onQueryChange={(value) => {
          markKeystroke()
          patchFeedSearch({ q: value, scroll: 0 })
        }}
        onSortChange={(next) => patchFeedSearch({ sort: next, scroll: 0 })}
      />
      <FeedPropertyFilter
        query={filterQuery}
        corpus={rows}
        onChange={(next) => patchFeedSearch({ f: serializeFilterQuery(next), op: next.operation ?? 'and', scroll: 0 })}
      />
      <FeedMeta count={feedHitCount(filteredHits.length, serverCorpusTotal, q ?? '', f ?? '')} serverCorpusTotal={serverCorpusTotal} tiered={tiered} />
      {state.status === 'loading' && filteredHits.length === 0 ? <p className="feed-route__empty">Loading feed snapshot…</p> : null}
      {state.status === 'ready' && state.items.length === 0 ? <p className="feed-route__empty">No results — adjust search or filters.</p> : null}
      {state.items.length > 0 && filteredHits.length === 0 ? (
        <p className="feed-route__empty">
          No results — adjust search or filters.
          {(q || f) && (
            <button type="button" className="feed-route__empty-action" onClick={() => patchFeedSearch({ q: '', f: '' })}>
              Clear filters
            </button>
          )}
        </p>
      ) : null}
      {split ? (
        <div className="feed-route__split">
          <div
            className="feed-route__list-scroll"
            ref={listRef}
            // The kit windows against window scroll; a scrolling container re-announces itself as one.
            onScroll={() => window.dispatchEvent(new Event('scroll'))}
          >
            {list}
          </div>
          <div className="feed-route__pane">
            <RecentlyViewedNav
              items={recentItems}
              currentRecordId={selectedHit?.recordId ?? null}
              onSelect={(entry) => selectHit(hitFromRecent(entry))}
            />
            <FeedReadingPane hit={selectedHit} />
          </div>
        </div>
      ) : (
        list
      )}
    </div>
  )
}
