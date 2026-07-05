/**
 * Application-layer offline mutation queue (B67 AC-18 / DOC-E470AC8CE9A8 §7.2).
 * Complements Workbox BackgroundSync with UI-visible pendingCount.
 */

const DB_NAME = 'enceladus-ui-v2-offline'
const STORE = 'pendingMutations'

export interface QueuedMutation {
  id: string
  url: string
  method: 'PATCH' | 'POST' | 'DELETE'
  body: Record<string, unknown>
  headers: Record<string, string>
  enqueuedAt: string
}

type MemoryQueue = QueuedMutation[]

let memoryQueue: MemoryQueue = []

function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new Error('indexedDB unavailable'))
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'id' })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('indexedDB open failed'))
  })
}

async function listAll(): Promise<QueuedMutation[]> {
  try {
    const db = await openDb()
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly')
      const store = tx.objectStore(STORE)
      const req = store.getAll()
      req.onsuccess = () => resolve((req.result as QueuedMutation[]) ?? [])
      req.onerror = () => reject(req.error ?? new Error('indexedDB read failed'))
    })
  } catch {
    return [...memoryQueue]
  }
}

async function put(entry: QueuedMutation): Promise<void> {
  try {
    const db = await openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).put(entry)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('indexedDB write failed'))
    })
  } catch {
    memoryQueue = [...memoryQueue.filter((m) => m.id !== entry.id), entry]
  }
}

async function remove(id: string): Promise<void> {
  try {
    const db = await openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).delete(id)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('indexedDB delete failed'))
    })
  } catch {
    memoryQueue = memoryQueue.filter((m) => m.id !== id)
  }
}

export async function getPendingMutationCount(): Promise<number> {
  const rows = await listAll()
  return rows.length
}

export async function enqueueMutation(
  input: Omit<QueuedMutation, 'id' | 'enqueuedAt'>,
): Promise<QueuedMutation> {
  const entry: QueuedMutation = {
    ...input,
    id: crypto.randomUUID(),
    enqueuedAt: new Date().toISOString(),
  }
  await put(entry)
  return entry
}

export async function drainMutationQueue(
  send: (entry: QueuedMutation) => Promise<boolean>,
): Promise<number> {
  const rows = await listAll()
  let replayed = 0
  for (const entry of rows.sort((a, b) => a.enqueuedAt.localeCompare(b.enqueuedAt))) {
    const ok = await send(entry)
    if (!ok) break
    await remove(entry.id)
    replayed += 1
  }
  return replayed
}

/** Test-only reset */
export async function clearMutationQueueForTests(): Promise<void> {
  memoryQueue = []
  try {
    const db = await openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).clear()
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('indexedDB clear failed'))
    })
  } catch {
    /* memory fallback already cleared */
  }
}
