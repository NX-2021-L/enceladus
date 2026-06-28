/**
 * UI-only client state (ENC-TSK-B67 AC-13).
 *
 * State ownership boundary: server state (record fields, feed events, plan
 * hierarchy, document content) lives exclusively in TanStack Query / the
 * normalized entity store. UI-only state — sidebar open/closed, selected record
 * IDs, command palette open/query, Cytoscape viewport/zoom, and filter/sort
 * preferences — flows exclusively through this Zustand store. No record field
 * data is permitted here.
 */

import { create } from 'zustand'

export interface CytoscapeViewport {
  zoom: number
  pan: { x: number; y: number }
}

interface UIState {
  sidebarOpen: boolean
  commandPaletteOpen: boolean
  commandPaletteQuery: string
  selectedRecordIds: string[]
  graphViewport: CytoscapeViewport
  filters: Record<string, string>
  sort: string

  setSidebarOpen: (open: boolean) => void
  toggleSidebar: () => void
  setCommandPaletteOpen: (open: boolean) => void
  setCommandPaletteQuery: (q: string) => void
  setSelectedRecordIds: (ids: string[]) => void
  setGraphViewport: (vp: CytoscapeViewport) => void
  setFilter: (key: string, value: string) => void
  setSort: (sort: string) => void
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  commandPaletteOpen: false,
  commandPaletteQuery: '',
  selectedRecordIds: [],
  graphViewport: { zoom: 1, pan: { x: 0, y: 0 } },
  filters: {},
  sort: 'updated_at',

  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),
  setCommandPaletteQuery: (q) => set({ commandPaletteQuery: q }),
  setSelectedRecordIds: (ids) => set({ selectedRecordIds: ids }),
  setGraphViewport: (vp) => set({ graphViewport: vp }),
  setFilter: (key, value) => set((s) => ({ filters: { ...s.filters, [key]: value } })),
  setSort: (sort) => set({ sort }),
}))
