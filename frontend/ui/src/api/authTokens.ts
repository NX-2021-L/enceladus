import { fetchWithAuth } from './client'

export type ManagedAuthToken = {
  token_id: string
  service_name: string
  status: string
  permissions: string[]
  created_at: string
  updated_at: string
  last_used_at: string
  token_age_seconds: number | null
  token_masked: string
}

export async function listManagedAuthTokens(): Promise<ManagedAuthToken[]> {
  const res = await fetchWithAuth('/api/v1/coordination/auth/tokens')
  if (!res.ok) {
    throw new Error(`Failed to list auth tokens: ${res.status}`)
  }
  const body = (await res.json()) as { tokens?: ManagedAuthToken[] }
  return Array.isArray(body.tokens) ? body.tokens : []
}

export async function createManagedAuthToken(input: {
  service_name: string
  permissions: string[]
}): Promise<{ token: ManagedAuthToken & { token: string } }> {
  const res = await fetchWithAuth('/api/v1/coordination/auth/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  const body = (await res.json().catch(() => ({}))) as {
    token?: ManagedAuthToken & { token: string }
    error?: string
  }
  if (!res.ok || !body.token) {
    throw new Error(body.error || `Failed to create auth token: ${res.status}`)
  }
  return { token: body.token }
}

export async function deleteManagedAuthToken(tokenId: string): Promise<void> {
  const res = await fetchWithAuth(`/api/v1/coordination/auth/tokens/${encodeURIComponent(tokenId)}`, {
    method: 'DELETE',
  })
  if (!res.ok) {
    throw new Error(`Failed to delete token ${tokenId}: ${res.status}`)
  }
}

export async function updateManagedAuthPermissions(
  tokenId: string,
  permissions: string[],
): Promise<void> {
  const res = await fetchWithAuth(
    `/api/v1/coordination/auth/permissions/${encodeURIComponent(tokenId)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ permissions }),
    },
  )
  if (!res.ok) {
    throw new Error(`Failed to update permissions for ${tokenId}: ${res.status}`)
  }
}

export type OAuthClient = {
  client_id: string
  service_name: string
  grant_types: string[]
  redirect_uris: string[]
  status: string
  created_at: string
  updated_at: string
  last_used_at: string
}

export async function listOAuthClients(): Promise<OAuthClient[]> {
  const res = await fetchWithAuth('/api/v1/coordination/auth/oauth-clients')
  if (!res.ok) {
    throw new Error(`Failed to list OAuth clients: ${res.status}`)
  }
  const body = (await res.json()) as { oauth_clients?: OAuthClient[] }
  return Array.isArray(body.oauth_clients) ? body.oauth_clients : []
}

export async function createOAuthClient(input: {
  client_id: string
  service_name: string
  grant_types?: string[]
  redirect_uris?: string[]
}): Promise<OAuthClient> {
  const res = await fetchWithAuth('/api/v1/coordination/auth/oauth-clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  const body = (await res.json().catch(() => ({}))) as {
    oauth_client?: OAuthClient
    error?: string
  }
  if (!res.ok || !body.oauth_client) {
    throw new Error(body.error || `Failed to create OAuth client: ${res.status}`)
  }
  return body.oauth_client
}
