import type { Tier1Record, Tier2Record, TombstoneRecord } from './types'
import { cacheKey } from './recordKey'

const DB_NAME = 'enceladus-ui-v2-sync'
const DB_VERSION = 1

type MemoryDb = {
  tier1: Map<string, Tier1Record>
  tier2: Map<string, Tier2Record>
  tombstones: Map<string, TombstoneRecord>
  queryCache: unknown | null
}

let memoryDb: MemoryDb | null = null

function getMemoryDb(): MemoryDb {
  if (!memoryDb) {
    memoryDb = {
      tier1: new Map(),
      tier2: new Map(),
      tombstones: new Map(),
      queryCache: null,
    }
  }
  return memoryDb
}

function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new Error('indexedDB unavailable'))
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains('tier1')) db.createObjectStore('tier1')
      if (!db.objectStoreNames.contains('tier2')) db.createObjectStore('tier2')
      if (!db.objectStoreNames.contains('tombstones')) db.createObjectStore('tombstones')
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta')
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('indexedDB open failed'))
  })
}

async function withStore<T>(
  storeName: string,
  mode: IDBTransactionMode,
  fn: (store: IDBObjectStore) => IDBRequest<T> | void,
): Promise<T | void> {
  try {
    const db = await openDb()
    return await new Promise<T | void>((resolve, reject) => {
      const tx = db.transaction(storeName, mode)
      const store = tx.objectStore(storeName)
      const request = fn(store)
      tx.oncomplete = () => resolve(request ? request.result : undefined)
      tx.onerror = () => reject(tx.error ?? new Error('indexedDB tx failed'))
    })
  } catch (error) {
    throw error
  }
}

export async function putTier1(record: Tier1Record): Promise<void> {
  const key = cacheKey(record.projectId, record.recordId)
  try {
    await withStore('tier1', 'readwrite', (store) => store.put(record, key))
  } catch {
    getMemoryDb().tier1.set(key, record)
  }
}

export async function getTier1(projectId: string, recordId: string): Promise<Tier1Record | null> {
  const key = cacheKey(projectId, recordId)
  try {
    const result = (await withStore('tier1', 'readonly', (store) => store.get(key))) as
      | Tier1Record
      | undefined
    if (result) return result
  } catch {
    /* fall through */
  }
  return getMemoryDb().tier1.get(key) ?? null
}

export async function listTier1(limit: number): Promise<Tier1Record[]> {
  const rows: Tier1Record[] = []
  try {
    const db = await openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tier1', 'readonly')
      const store = tx.objectStore('tier1')
      const request = store.openCursor()
      request.onsuccess = () => {
        const cursor = request.result
        if (!cursor || rows.length >= limit) {
          resolve()
          return
        }
        rows.push(cursor.value as Tier1Record)
        cursor.continue()
      }
      request.onerror = () => reject(request.error ?? new Error('cursor failed'))
    })
    if (rows.length > 0) return rows
  } catch {
    /* fall through */
  }
  return [...getMemoryDb().tier1.values()].slice(0, limit)
}

export async function putTier2(record: Tier2Record): Promise<void> {
  const key = cacheKey(record.projectId, record.recordId)
  try {
    await withStore('tier2', 'readwrite', (store) => store.put(record, key))
  } catch {
    getMemoryDb().tier2.set(key, record)
  }
}

export async function deleteTier2(projectId: string, recordId: string): Promise<void> {
  const key = cacheKey(projectId, recordId)
  try {
    await withStore('tier2', 'readwrite', (store) => store.delete(key))
  } catch {
    getMemoryDb().tier2.delete(key)
  }
}

export async function getTier2(projectId: string, recordId: string): Promise<Tier2Record | null> {
  const key = cacheKey(projectId, recordId)
  try {
    const result = (await withStore('tier2', 'readonly', (store) => store.get(key))) as
      | Tier2Record
      | undefined
    if (result) return result
  } catch {
    /* fall through */
  }
  return getMemoryDb().tier2.get(key) ?? null
}

export async function listTier2(): Promise<Tier2Record[]> {
  const rows: Tier2Record[] = []
  try {
    const db = await openDb()
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('tier2', 'readonly')
      const store = tx.objectStore('tier2')
      const request = store.openCursor()
      request.onsuccess = () => {
        const cursor = request.result
        if (!cursor) {
          resolve()
          return
        }
        rows.push(cursor.value as Tier2Record)
        cursor.continue()
      }
      request.onerror = () => reject(request.error ?? new Error('cursor failed'))
    })
    if (rows.length > 0) return rows
  } catch {
    /* fall through */
  }
  return [...getMemoryDb().tier2.values()]
}

export async function putTombstone(record: TombstoneRecord): Promise<void> {
  try {
    await withStore('tombstones', 'readwrite', (store) => store.put(record, record.recordKey))
  } catch {
    getMemoryDb().tombstones.set(record.recordKey, record)
  }
}

export async function hasTombstone(recordKey: string): Promise<boolean> {
  try {
    const result = (await withStore('tombstones', 'readonly', (store) => store.get(recordKey))) as
      | TombstoneRecord
      | undefined
    if (result) return true
  } catch {
    /* fall through */
  }
  return getMemoryDb().tombstones.has(recordKey)
}

export async function saveQueryCache(payload: unknown): Promise<void> {
  try {
    await withStore('meta', 'readwrite', (store) => store.put(payload, 'queryCache'))
  } catch {
    getMemoryDb().queryCache = payload
  }
}

export async function loadQueryCache<T>(): Promise<T | null> {
  try {
    const result = (await withStore('meta', 'readonly', (store) => store.get('queryCache'))) as T | undefined
    if (result) return result
  } catch {
    /* fall through */
  }
  return (getMemoryDb().queryCache as T | null) ?? null
}

export function resetMemoryStoreForTests(): void {
  memoryDb = null
}
