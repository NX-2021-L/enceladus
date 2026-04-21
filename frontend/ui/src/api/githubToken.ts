// Runtime GitHub App installation token vending — ENC-TSK-F62 AC-3.
// Fetches a short-lived token from the Enceladus auth Lambda so the PWA
// never needs a build-time PAT (VITE_GITHUB_READ_TOKEN).

let _cachedToken: string | null = null
let _cachedAt = 0
const TOKEN_TTL_MS = 50 * 60 * 1000 // 50 min — conservative vs 60-min GitHub expiry

export async function getGitHubToken(): Promise<string> {
  const now = Date.now()
  if (_cachedToken && now - _cachedAt < TOKEN_TTL_MS) {
    return _cachedToken
  }

  const res = await fetch('/api/v1/auth/github-token', {
    method: 'GET',
    credentials: 'include',
  })

  if (!res.ok) {
    throw new Error(`GitHub token fetch failed: ${res.status}`)
  }

  const data = (await res.json()) as { token: string }
  _cachedToken = data.token
  _cachedAt = now
  return _cachedToken
}
