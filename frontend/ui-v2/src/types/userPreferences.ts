/**
 * ENC-TSK-L25 (B67 Search2.0 WaveB / FTR-127 AC-10/16/17). Locked payload
 * schema, DOC-77D6C714867E §15h — must match backend/lambda/user_preferences_api
 * exactly.
 */

export interface SavedSearch {
  name: string
  query: string
  filters: Record<string, unknown>
  sort: string
}

export interface RecentlyViewedEntry {
  record_id: string
  project_id: string
  viewed_at: string
}

export interface UserPreferences {
  saved_searches: SavedSearch[]
  recently_viewed: Record<string, RecentlyViewedEntry[]>
  prefs: Record<string, unknown>
}

export const EMPTY_USER_PREFERENCES: UserPreferences = {
  saved_searches: [],
  recently_viewed: {},
  prefs: {},
}
