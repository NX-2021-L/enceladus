/**
 * ENC-TSK-L25 (B67 Search2.0 WaveB / FTR-127 AC-10/16/17). Offline local
 * mirror for user preferences — the server (GET/PUT /api/v1/user/preferences)
 * is canonical for cross-device sync; localStorage is a same-device fallback
 * so saved searches / recently-viewed still work offline and paint instantly
 * before the network round-trip resolves.
 */

import type { UserPreferences } from '../types/userPreferences'
import { EMPTY_USER_PREFERENCES } from '../types/userPreferences'

const STORAGE_KEY = 'enceladus.userPreferences.v1'

export function readCachedPreferences(): UserPreferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...EMPTY_USER_PREFERENCES }
    const parsed = JSON.parse(raw) as Partial<UserPreferences>
    return {
      saved_searches: Array.isArray(parsed.saved_searches) ? parsed.saved_searches : [],
      recently_viewed:
        parsed.recently_viewed && typeof parsed.recently_viewed === 'object'
          ? parsed.recently_viewed
          : {},
      prefs: parsed.prefs && typeof parsed.prefs === 'object' ? parsed.prefs : {},
    }
  } catch {
    // Corrupt/unavailable storage (private browsing, quota, malformed JSON) —
    // fail open to empty prefs rather than throw; this is a cache, not a source of truth.
    return { ...EMPTY_USER_PREFERENCES }
  }
}

export function writeCachedPreferences(preferences: UserPreferences): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences))
  } catch {
    // Quota exceeded or storage disabled — the server copy remains canonical.
  }
}
