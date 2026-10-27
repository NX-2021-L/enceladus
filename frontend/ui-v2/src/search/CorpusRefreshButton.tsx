import { FeedRefreshButton, type FeedRefreshAdapter } from '@io-kit/feed/react'
import { useEnceladusCorpus } from './CorpusProvider'
import { withDocsDelta } from './corpusSource'

/**
 * ENC-TSK-R56-0A (@io-kit/feed 1.2 manual refresh): the adapter behind the Feed and Docs header button.
 *
 * An authoritative refresh re-seeds the corpus from the origin (`refresh({ seed: true })`: GET /feed/corpus pages,
 * NetworkOnly + no-store) and upserts every page over the persisted IndexedDB rows, then runs the delta (with
 * doc_since: a manual refresh is the one non-Docs caller allowed to scan documents, P101-R15). The corpus
 * swallows sync failures into its status, so success is read from the stored `seededAt` stamp, which only a
 * completed sync advances; `asOf` is that stamp. No navigation, no reload: scroll, filters and route stay.
 */
export function useCorpusRefreshAdapter(): FeedRefreshAdapter {
  // store and refresh are identity-stable (refresh is a useCallback keyed on the store); React Compiler memoizes the adapter.
  const { store, refresh } = useEnceladusCorpus()
  return {
    async refresh({ authoritative }) {
      const before = store ? await store.getSeededAt() : null
      await withDocsDelta(() => refresh(authoritative ? { seed: true } : undefined))
      const after = store ? await store.getSeededAt() : new Date().toISOString()
      if (!after || (store && after === before)) throw new Error('Refresh did not complete')
      return { asOf: after }
    },
  }
}

export function CorpusRefreshButton() {
  const adapter = useCorpusRefreshAdapter()
  return <FeedRefreshButton adapter={adapter} />
}
