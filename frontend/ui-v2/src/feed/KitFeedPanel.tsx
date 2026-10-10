import { useEffect, useState } from 'react'
import { createFeed, FeedList, useFeed } from '@io-kit/feed/react'
import { createIdbStorage } from '@io-kit/feed/idb'
import { useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { useFeedConnectionStore } from '../store/feedConnectionStore'
import { resolveRecordTarget } from '../routes/recordLink'
import { useQuery } from '@tanstack/react-query'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { formatRelativeTime } from '../format/relativeTime'
import { createEnceladusFeedSource, createSignalBridge, type FeedCorpusRecord } from './enceladusFeedSource'
import './kitFeed.css'

/** Fixed row height: FeedList windows rows above DEFAULT_VIRTUALIZE_ABOVE (100) and needs fixed-height cards. */
const ROW_HEIGHT = 72
const WARM_START_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

/**
 * DVP-TSK-919 (DVP-PLN-011 E3-W2.6): /feed on @io-kit/feed -- keyset paging over signed cursors, since-seq
 * deltas with gap handling, insert buffer + newer-items pill, IndexedDB warm start, scroll restore and
 * virtualization from the kit. Mounted behind ?feed=kit (see feedEngine.ts).
 */
export default function KitFeedPanel() {
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

  function hrefFor(r: FeedCorpusRecord): string | null {
    const t = resolveRecordTarget(r.record_id, projects, r.record_type)
    return t ? t.to.replace(/\$(\w+)/g, (_m, k: string) => encodeURIComponent(t.params[k] ?? '')) : null
  }

  return (
    <section className="ev2-kitfeed" data-feed-engine="kit" aria-label="Feed">
      <p className="ev2-kitfeed__status" role="status">
        {state.transport === 'live' ? 'LIVE' : 'SNAPSHOT'}
        {state.stale ? ' (refreshing)' : ''}
        {state.gap ? ' (resynced)' : ''}
      </p>
      {state.error && (
        <p className="ev2-kitfeed__error" role="alert">
          Couldn&apos;t load the feed.{' '}
          <button type="button" onClick={() => void state.retry()}>
            Retry
          </button>
        </p>
      )}
      <FeedList<FeedCorpusRecord>
        feed={feed as never}
        estimateSize={ROW_HEIGHT}
        renderPill={(n, flush) => (
          <button type="button" className="ev2-kitfeed__pill" onClick={flush}>
            {n} new {n === 1 ? 'item' : 'items'}
          </button>
        )}
        renderCard={(r) => {
          const href = hrefFor(r)
          return (
            <article className="ev2-kitfeed__row" style={{ height: ROW_HEIGHT }} key={r.record_id}>
              <span className="ev2-kitfeed__id">{href ? <a href={href}>{r.record_id}</a> : r.record_id}</span>
              <span className="ev2-kitfeed__title">{r.title ?? ''}</span>
              <span className="ev2-kitfeed__meta">
                {r.record_type}
                {r.updated_at ? ` · ${formatRelativeTime(r.updated_at)}` : ''}
              </span>
            </article>
          )
        }}
      />
      {state.loadMoreError && (
        <p className="ev2-kitfeed__error" role="alert">
          <button type="button" onClick={() => void state.retry()}>
            Retry loading more
          </button>
        </p>
      )}
    </section>
  )
}
