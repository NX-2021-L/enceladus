const API_BASE = '/api/v1'
export function getAlpha() { return fetchJson(`${API_BASE}/alpha`) }
export function postBeta() { return fetchJson(`${API_BASE}/beta`, { method: 'POST' }) }
export function mixed() {
  fetchJson(`${API_BASE}/m1`)
  return fetchJson(`${API_BASE}/m2/${encodeURIComponent(id)}`, { method: 'DELETE' })
}
