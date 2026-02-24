/**
 * timeFormat.ts — Time formatting utilities for feed display
 *
 * Provides human-readable time elapsed formatting (e.g., "2m ago", "1h ago")
 */

/**
 * Format time elapsed since a given date/timestamp
 *
 * @param date - Date object or millisecond timestamp
 * @returns Formatted string like "2m ago", "1h ago", "2d ago"
 */
export function formatTimeSince(date: Date | number): string {
  const now = Date.now();
  const targetTime = typeof date === "number" ? date : date.getTime();
  const elapsedMs = now - targetTime;

  // Handle edge case: future dates or very recent (within 1 second)
  if (elapsedMs < 1000) {
    return "now";
  }

  const seconds = Math.floor(elapsedMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const weeks = Math.floor(days / 7);
  const months = Math.floor(days / 30);
  const years = Math.floor(days / 365);

  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  if (hours < 24) {
    return `${hours}h ago`;
  }
  if (days < 7) {
    return `${days}d ago`;
  }
  if (weeks < 4) {
    return `${weeks}w ago`;
  }
  if (months < 12) {
    return `${months}mo ago`;
  }
  return `${years}y ago`;
}

/**
 * Format an ISO date string to a readable format
 *
 * @param isoString - ISO 8601 date string
 * @returns Formatted string like "2m ago"
 */
export function formatTimeSinceIso(isoString: string): string {
  try {
    const date = new Date(isoString);
    return formatTimeSince(date);
  } catch {
    return "unknown";
  }
}
