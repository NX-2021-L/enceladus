import type { QueryClient } from '@tanstack/react-query'
import { dehydrate, hydrate } from '@tanstack/react-query'
import * as idb from './idbStore'

const PERSIST_KEY = 'queryCache'

export async function restorePersistedQueryClient(client: QueryClient): Promise<void> {
  const payload = await idb.loadQueryCache<{ clientState?: unknown }>()
  if (!payload?.clientState) return
  hydrate(client, payload as Parameters<typeof hydrate>[1])
}

export function attachQueryClientPersist(client: QueryClient): () => void {
  let timer: number | null = null

  const persist = () => {
    if (timer !== null) window.clearTimeout(timer)
    timer = window.setTimeout(() => {
      const payload = dehydrate(client)
      void idb.saveQueryCache({ clientState: payload })
    }, 400)
  }

  const unsubscribe = client.getQueryCache().subscribe(persist)
  return () => {
    if (timer !== null) window.clearTimeout(timer)
    unsubscribe()
  }
}

export async function clearPersistedQueryClient(): Promise<void> {
  await idb.saveQueryCache(null)
}

export { PERSIST_KEY }
