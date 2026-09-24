/**
 * UI-only state (AC-13). This store holds NOTHING that comes from the server —
 * no record fields, no fetched lists. Server state lives exclusively in
 * TanStack Query (see src/api/queryOptions.ts). Everything here is ephemeral
 * client interaction state: sidebar visibility, the currently-selected record
 * id, the command palette, and active feed filters.
 */

import { create } from 'zustand'
import type { RecordType } from '../types/records'
import type { RecentlyViewedEntry } from '../search/recentlyViewed'

export interface ActiveFilters {
  /** Record types the feed pane is scoped to. Empty = show all. */
  recordTypes: RecordType[]
  /** Free-text status filter token, or null for no status filter. */
  status: string | null
}

interface UiState {
  // Sidebar
  sidebarOpen: boolean
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void

  // Selected record (drives feed highlight / deep-link affordances)
  selectedRecordId: string | null
  selectRecord: (recordId: string | null) => void

  // Recently-viewed record-reference nav state (ENC-TSK-M73 / B67 AC-13).
  // This is UI navigation state, not server-state: the durable copy lives in
  // localStorage via search/recentlyViewed.ts, and this is only its reactive
  // in-memory holder — it replaces FeedRoute's former component-local
  // useState<RecentlyViewedEntry[]>, keeping record-reference nav data in
  // Zustand per the AC-13 ownership rule.
  recentItems: RecentlyViewedEntry[]
  setRecentItems: (items: RecentlyViewedEntry[]) => void

  // Command palette. `commandPaletteAnchored` selects the render mode: false
  // (default) is the full-screen mobile overlay; true is the small dropdown
  // anchored under the top-nav search box (desktop widen-in-place), opened
  // by AppShell based on viewport width at focus time (ENC-TSK-N46).
  commandPaletteOpen: boolean
  commandPaletteAnchored: boolean
  commandQuery: string
  openCommandPalette: (anchored?: boolean) => void
  closeCommandPalette: () => void
  setCommandQuery: (query: string) => void

  // Active filters
  filters: ActiveFilters
  toggleFilterType: (type: RecordType) => void
  setStatusFilter: (status: string | null) => void
  clearFilters: () => void
}

const EMPTY_FILTERS: ActiveFilters = { recordTypes: [], status: null }

export const useUiStore = create<UiState>((set) => ({
  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  setSidebarOpen: (open) => set({ sidebarOpen: open }),

  selectedRecordId: null,
  selectRecord: (recordId) => set({ selectedRecordId: recordId }),

  recentItems: [],
  setRecentItems: (items) => set({ recentItems: items }),

  commandPaletteOpen: false,
  commandPaletteAnchored: false,
  commandQuery: '',
  openCommandPalette: (anchored = false) => set({ commandPaletteOpen: true, commandPaletteAnchored: anchored }),
  closeCommandPalette: () => set({ commandPaletteOpen: false, commandPaletteAnchored: false, commandQuery: '' }),
  setCommandQuery: (query) => set({ commandQuery: query }),

  filters: EMPTY_FILTERS,
  toggleFilterType: (type) =>
    set((s) => {
      const has = s.filters.recordTypes.includes(type)
      const recordTypes = has
        ? s.filters.recordTypes.filter((t) => t !== type)
        : [...s.filters.recordTypes, type]
      return { filters: { ...s.filters, recordTypes } }
    }),
  setStatusFilter: (status) =>
    set((s) => ({ filters: { ...s.filters, status } })),
  clearFilters: () => set({ filters: EMPTY_FILTERS }),
}))
