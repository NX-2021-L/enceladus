/**
 * UI-only realtime connection surface (AC-13).
 * Connection phase, reconnect attempt counts, and latency samples are ephemeral
 * client telemetry — not server record fields.
 */

import { create } from 'zustand'
import type { RealtimeConnectionPhase } from '../types/feedEvents'

interface FeedConnectionState {
  phase: RealtimeConnectionPhase
  reconnectAttempt: number
  failedReconnects: number
  lastLatencyMs: number | null
  p50LatencyMs: number | null
  p99LatencyMs: number | null
  latencySamples: number[]
  errorMessage: string | null

  setPhase: (phase: RealtimeConnectionPhase) => void
  setReconnectAttempt: (attempt: number) => void
  incrementFailedReconnects: () => void
  resetFailedReconnects: () => void
  recordLatency: (latencyMs: number) => void
  setErrorMessage: (message: string | null) => void
  resetLatency: () => void
}

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[index] ?? null
}

export const useFeedConnectionStore = create<FeedConnectionState>((set, get) => ({
  phase: 'idle',
  reconnectAttempt: 0,
  failedReconnects: 0,
  lastLatencyMs: null,
  p50LatencyMs: null,
  p99LatencyMs: null,
  latencySamples: [],
  errorMessage: null,

  setPhase: (phase) => set({ phase }),
  setReconnectAttempt: (attempt) => set({ reconnectAttempt: attempt }),
  incrementFailedReconnects: () =>
    set((state) => ({ failedReconnects: state.failedReconnects + 1 })),
  resetFailedReconnects: () => set({ failedReconnects: 0, reconnectAttempt: 0 }),
  recordLatency: (latencyMs) => {
    const samples = [...get().latencySamples, latencyMs].slice(-200)
    set({
      lastLatencyMs: latencyMs,
      latencySamples: samples,
      p50LatencyMs: percentile(samples, 50),
      p99LatencyMs: percentile(samples, 99),
    })
  },
  setErrorMessage: (message) => set({ errorMessage: message }),
  resetLatency: () =>
    set({
      lastLatencyMs: null,
      p50LatencyMs: null,
      p99LatencyMs: null,
      latencySamples: [],
    }),
}))
