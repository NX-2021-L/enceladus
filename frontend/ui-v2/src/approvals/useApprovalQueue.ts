import { useCallback, useEffect, useRef, useState } from 'react'
import { ApprovalDecisionError, type ApprovalAdapter, type DecisionResult, type Verdict } from './types'

export interface ApprovalQueue<T, P, O> {
  items: T[]
  loading: boolean
  loadError: string | null
  selected: ReadonlySet<string>
  selectedItems: T[]
  setSelection(keys: Iterable<string>): void
  /** Results of the last bulk run, one per item, in decision order. */
  results: DecisionResult<O>[]
  progress: { running: boolean; done: number; total: number }
  reload(): Promise<void>
  /** One decide() call per selected item, sequential; a failure never stops the rest. */
  decideSelected(verdict: Verdict, payloadFor: (item: T) => P): Promise<DecisionResult<O>[]>
  clearResults(): void
}

export function useApprovalQueue<T, P = unknown, O = unknown>(adapter: ApprovalAdapter<T, P, O>): ApprovalQueue<T, P, O> {
  const adapterRef = useRef(adapter)
  adapterRef.current = adapter
  const [items, setItems] = useState<T[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [results, setResults] = useState<DecisionResult<O>[]>([])
  const [progress, setProgress] = useState({ running: false, done: 0, total: 0 })
  const itemsRef = useRef<T[]>([])
  itemsRef.current = items

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const next = await adapterRef.current.list()
      setItems(next)
      const keys = new Set(next.map((i) => adapterRef.current.key(i)))
      setSelected((s) => new Set([...s].filter((k) => keys.has(k))))
      setLoadError(null)
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : 'Could not load the queue')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void reload() }, [reload])

  const setSelection = useCallback((keys: Iterable<string>) => setSelected(new Set(keys)), [])

  const decideSelected = useCallback(async (verdict: Verdict, payloadFor: (item: T) => P) => {
    const a = adapterRef.current
    const batch = itemsRef.current.filter((i) => selected.has(a.key(i)))
    const out: DecisionResult<O>[] = []
    setResults([])
    setProgress({ running: true, done: 0, total: batch.length })
    for (const item of batch) {
      const key = a.key(item)
      let r: DecisionResult<O>
      try {
        const outcome = await a.decide(item, verdict, payloadFor(item))
        r = { key, verdict, state: 'ok', outcome }
        setItems((cur) => cur.filter((i) => a.key(i) !== key))
        setSelected((s) => { const n = new Set(s); n.delete(key); return n })
      } catch (e) {
        if (e instanceof ApprovalDecisionError) {
          const stale = e.status === 412
          r = { key, verdict, state: stale || e.status === 409 ? 'conflict' : 'error', status: e.status, message: e.message }
          if (stale && e.refreshed !== undefined) {
            const fresh = e.refreshed as T
            setItems((cur) => cur.map((i) => (a.key(i) === key ? fresh : i)))
          }
        } else {
          r = { key, verdict, state: 'error', message: e instanceof Error ? e.message : 'Decision failed' }
        }
      }
      out.push(r)
      setResults([...out])
      setProgress({ running: true, done: out.length, total: batch.length })
    }
    setProgress({ running: false, done: out.length, total: batch.length })
    return out
  }, [selected])

  const selectedItems = items.filter((i) => selected.has(adapter.key(i)))
  return {
    items, loading, loadError, selected, selectedItems, setSelection, results, progress, reload,
    decideSelected, clearResults: () => setResults([]),
  }
}
