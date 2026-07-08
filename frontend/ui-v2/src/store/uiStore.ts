/**
 * UI-only state (AC-13). This store holds NOTHING that comes from the server —
 * no record fields, no fetched lists. Server state lives exclusively in
 * TanStack Query (see src/api/queryOptions.ts). Everything here is ephemeral
 * client interaction state: sidebar visibility, the currently-selected record
 * id, the command palette, and active feed filters.
 */

import { create } from 'zustand'
import type { RecordType } from '../types/records'

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

  // Feed rail (ENC-ISS-513 / FND-01): opt-in, dismissible tools panel.
  // Closed by default -- it echoes the /feed destination's own content, so
  // it should only show when the operator asks for it, not on every page.
  feedRailOpen: boolean
  toggleFeedRail: () => void
  setFeedRailOpen: (open: boolean) => void

  // Selected record (drives feed highlight / deep-link affordances)
  selectedRecordId: string | null
  selectRecord: (recordId: string | null) => void

  // Command palette
  commandPaletteOpen: boolean
  commandQuery: string
  openCommandPalette: () => void
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

  feedRailOpen: false,
  toggleFeedRail: () => set((s) => ({ feedRailOpen: !s.feedRailOpen })),
  setFeedRailOpen: (open) => set({ feedRailOpen: open }),

  selectedRecordId: null,
  selectRecord: (recordId) => set({ selectedRecordId: recordId }),

  commandPaletteOpen: false,
  commandQuery: '',
  openCommandPalette: () => set({ commandPaletteOpen: true }),
  closeCommandPalette: () => set({ commandPaletteOpen: false, commandQuery: '' }),
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
