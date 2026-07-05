import { create } from 'zustand'
import { drainMutationQueue, getPendingMutationCount } from '../offline/mutationQueue'
import type { QueuedMutation } from '../offline/mutationQueue'

interface OfflineState {
  pendingCount: number
  swUpdateReady: boolean
  refreshPendingCount: () => Promise<void>
  setSwUpdateReady: (ready: boolean) => void
  replayQueue: (send: (entry: QueuedMutation) => Promise<boolean>) => Promise<number>
}

export const useOfflineStore = create<OfflineState>((set) => ({
  pendingCount: 0,
  swUpdateReady: false,
  refreshPendingCount: async () => {
    const pendingCount = await getPendingMutationCount()
    set({ pendingCount })
  },
  setSwUpdateReady: (ready) => set({ swUpdateReady: ready }),
  replayQueue: async (send) => {
    const replayed = await drainMutationQueue(send)
    const pendingCount = await getPendingMutationCount()
    set({ pendingCount })
    return replayed
  },
}))
