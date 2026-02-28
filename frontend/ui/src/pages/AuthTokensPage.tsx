import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  createManagedAuthToken,
  createOAuthClient,
  deleteManagedAuthToken,
  listManagedAuthTokens,
  listOAuthClients,
  updateManagedAuthPermissions,
  updateOAuthClientPermissions,
  type ManagedAuthToken,
  type OAuthClient,
  type OAuthEndpoints,
} from '../api/authTokens'

const PERMISSION_OPTIONS = ['read', 'write', 'put', 'delete', 'admin'] as const
const GATEWAY_URL = 'https://jreese.net/api/v1/coordination/mcp'

type Tab = 'tokens' | 'oauth' | 'permissions'

interface CreatedClientCreds {
  client_id: string
  client_secret: string
  service_name: string
  api_key?: string
  oauth_endpoints?: OAuthEndpoints
}

function formatAge(seconds: number | null): string {
  if (seconds == null || seconds < 0) return 'n/a'
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h`
  const days = Math.floor(hours / 24)
  return `${days}d`
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [text])
  return (
    <button
      className="rounded bg-slate-700 px-2 py-1 text-xs hover:bg-slate-600 transition-colors"
      onClick={handleCopy}
    >
      {copied ? 'Copied!' : label ?? 'Copy'}
    </button>
  )
}

function ClientConfigBlock({ creds }: { creds: CreatedClientCreds }) {
  const endpoints = creds.oauth_endpoints

  const mcpConfigJson = JSON.stringify(
    {
      gateway_url: GATEWAY_URL,
      transport: 'streamable-http',
      auth_header: 'X-Coordination-Internal-Key',
      auth_value: creds.api_key || creds.client_secret,
      client_id: creds.client_id,
    },
    null,
    2,
  )

  return (
    <div className="space-y-4">
      {/* OAuth Credentials (Cognito) */}
      {endpoints && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-cyan-400">OAuth Credentials (copy now — secret shown once)</h4>
          <div className="grid gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-36 text-slate-400">Client ID:</span>
              <code className="flex-1 overflow-x-auto">{creds.client_id}</code>
              <CopyButton text={creds.client_id} />
            </div>
            <div className="flex items-center gap-2">
              <span className="w-36 text-slate-400">Client Secret:</span>
              <code className="flex-1 overflow-x-auto">{creds.client_secret}</code>
              <CopyButton text={creds.client_secret} />
            </div>
            <div className="flex items-center gap-2">
              <span className="w-36 text-slate-400">Authorization URL:</span>
              <code className="flex-1 overflow-x-auto">{endpoints.authorization_url}</code>
              <CopyButton text={endpoints.authorization_url} />
            </div>
            <div className="flex items-center gap-2">
              <span className="w-36 text-slate-400">Token URL:</span>
              <code className="flex-1 overflow-x-auto">{endpoints.token_url}</code>
              <CopyButton text={endpoints.token_url} />
            </div>
          </div>
        </div>
      )}

      {/* API Key (service token) */}
      {creds.api_key && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-amber-300">API Key (for header-based auth)</h4>
          <div className="grid gap-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-36 text-slate-400">API Key:</span>
              <code className="flex-1 overflow-x-auto">{creds.api_key}</code>
              <CopyButton text={creds.api_key} />
            </div>
            <div className="flex items-center gap-2">
              <span className="w-36 text-slate-400">Header:</span>
              <code className="flex-1 overflow-x-auto">X-Coordination-Internal-Key</code>
              <CopyButton text="X-Coordination-Internal-Key" />
            </div>
          </div>
        </div>
      )}

      {/* MCP Server URL */}
      <div className="space-y-2">
        <h4 className="text-sm font-medium text-emerald-400">MCP Server URL</h4>
        <div className="flex items-center gap-2 rounded-md bg-slate-950 border border-emerald-700/50 p-3">
          <code className="flex-1 text-sm text-emerald-300 overflow-x-auto">{GATEWAY_URL}</code>
          <CopyButton text={GATEWAY_URL} label="Copy URL" />
        </div>
      </div>

      {/* ChatGPT OAuth Setup */}
      {endpoints && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-slate-200">ChatGPT / OpenAI OAuth Setup</h4>
          <div className="rounded-md bg-slate-950 border border-slate-700 p-3 text-xs space-y-1">
            <div><span className="text-slate-400">Auth Type:</span> OAuth</div>
            <div><span className="text-slate-400">Client ID:</span> <code>{creds.client_id}</code></div>
            <div><span className="text-slate-400">Client Secret:</span> <code>{creds.client_secret}</code></div>
            <div><span className="text-slate-400">Authorization URL:</span> <code>{endpoints.authorization_url}</code></div>
            <div><span className="text-slate-400">Token URL:</span> <code>{endpoints.token_url}</code></div>
            <div><span className="text-slate-400">Scope:</span> <code>openid email profile</code></div>
          </div>
        </div>
      )}

      {/* MCP Configuration (API Key) */}
      <div className="space-y-2">
        <h4 className="text-sm font-medium text-slate-200">MCP Connection Config (API Key)</h4>
        <div className="relative">
          <pre className="rounded-md bg-slate-950 border border-slate-700 p-3 text-xs overflow-x-auto">
            {mcpConfigJson}
          </pre>
          <div className="absolute top-2 right-2">
            <CopyButton text={mcpConfigJson} label="Copy JSON" />
          </div>
        </div>
      </div>
    </div>
  )
}

export function AuthTokensPage() {
  const [tab, setTab] = useState<Tab>('tokens')
  const [tokens, setTokens] = useState<ManagedAuthToken[]>([])
  const [oauthClients, setOauthClients] = useState<OAuthClient[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Create Token state
  const [tokenServiceName, setTokenServiceName] = useState('')
  const [tokenPerms, setTokenPerms] = useState<string[]>(['read'])
  const [createdTokenSecret, setCreatedTokenSecret] = useState('')

  // Create Client state
  const [clientName, setClientName] = useState('')
  const [clientRedirectUri, setClientRedirectUri] = useState('')
  const [createdClientCreds, setCreatedClientCreds] = useState<CreatedClientCreds | null>(null)

  async function reload() {
    setLoading(true)
    setError(null)
    try {
      const [items, clients] = await Promise.all([listManagedAuthTokens(), listOAuthClients()])
      setTokens(items)
      setOauthClients(clients)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tokens')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void reload()
  }, [])

  const sorted = useMemo(
    () => [...tokens].sort((a, b) => a.service_name.localeCompare(b.service_name)),
    [tokens],
  )

  const sortedClients = useMemo(
    () => [...oauthClients].sort((a, b) => a.service_name.localeCompare(b.service_name)),
    [oauthClients],
  )

  async function onCreateToken() {
    if (!tokenServiceName.trim()) return
    setError(null)
    try {
      const result = await createManagedAuthToken({
        service_name: tokenServiceName.trim(),
        permissions: tokenPerms,
      })
      setCreatedTokenSecret(result.token.token)
      setTokenServiceName('')
      setTokenPerms(['read'])
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create token failed')
    }
  }

  async function onCreateClient() {
    const name = clientName.trim()
    if (!name) return
    setError(null)
    try {
      // Create service token for API key auth
      const tokenResult = await createManagedAuthToken({
        service_name: name,
        permissions: [...PERMISSION_OPTIONS],
      })
      const slugId = `enceladus-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')}`
      const redirectUris = clientRedirectUri.trim()
        ? clientRedirectUri.trim().split(/[,\s]+/).filter(Boolean)
        : []
      // Create OAuth client — backend registers with Cognito and returns real client_id
      const oauthClient = await createOAuthClient({
        client_id: slugId,
        service_name: name,
        grant_types: ['authorization_code'],
        redirect_uris: redirectUris,
        permissions: [...PERMISSION_OPTIONS],
      })
      setCreatedClientCreds({
        client_id: oauthClient.cognito_client_id || oauthClient.client_id,
        client_secret: oauthClient.cognito_client_secret || tokenResult.token.token,
        service_name: name,
        api_key: tokenResult.token.token,
        oauth_endpoints: oauthClient.oauth_endpoints,
      })
      setClientName('')
      setClientRedirectUri('')
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create client failed')
    }
  }

  async function onDelete(tokenId: string) {
    setError(null)
    try {
      await deleteManagedAuthToken(tokenId)
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
    }
  }

  async function onToggleTokenPermission(tokenId: string, existing: string[], perm: string, checked: boolean) {
    const next = checked ? [...new Set([...existing, perm])] : existing.filter((p) => p !== perm)
    const safe = next.length ? next : ['read']
    setError(null)
    try {
      await updateManagedAuthPermissions(tokenId, safe)
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Permission update failed')
    }
  }

  async function onToggleClientPermission(clientId: string, existing: string[], perm: string, checked: boolean) {
    const next = checked ? [...new Set([...existing, perm])] : existing.filter((p) => p !== perm)
    const safe = next.length ? next : ['read']
    setError(null)
    try {
      await updateOAuthClientPermissions(clientId, safe)
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Permission update failed')
    }
  }

  return (
    <main className="mx-auto max-w-6xl px-4 py-4 space-y-4 text-slate-100">
      {/* Tabs */}
      <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 space-y-3">
        <h2 className="text-lg font-semibold">Unified Service Auth</h2>
        <div className="flex gap-2">
          <button
            className={`rounded-md px-3 py-1 text-sm ${tab === 'tokens' ? 'bg-slate-200 text-slate-900' : 'bg-slate-700'}`}
            onClick={() => setTab('tokens')}
          >
            Tokens
          </button>
          <button
            className={`rounded-md px-3 py-1 text-sm ${tab === 'oauth' ? 'bg-slate-200 text-slate-900' : 'bg-slate-700'}`}
            onClick={() => setTab('oauth')}
          >
            OAuth Clients
          </button>
        </div>
        <div>
          <button
            className={`rounded-md px-3 py-1 text-sm ${tab === 'permissions' ? 'bg-blue-500 text-white' : 'bg-blue-900/40 text-blue-300 border border-blue-700/50'}`}
            onClick={() => setTab('permissions')}
          >
            Permissions
          </button>
        </div>
      </section>

      {/* Create Token */}
      <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 space-y-3">
        <h3 className="text-sm font-medium">Create Token</h3>
        <div className="grid gap-3 md:grid-cols-3">
          <input
            value={tokenServiceName}
            onChange={(e) => setTokenServiceName(e.target.value)}
            placeholder="Service name"
            className="rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm"
            onKeyDown={(e) => { if (e.key === 'Enter') void onCreateToken() }}
          />
          <div className="md:col-span-2 flex flex-wrap gap-3">
            {PERMISSION_OPTIONS.map((perm) => (
              <label key={perm} className="text-xs flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={tokenPerms.includes(perm)}
                  onChange={(e) => {
                    setTokenPerms((current) =>
                      e.target.checked ? [...new Set([...current, perm])] : current.filter((p) => p !== perm),
                    )
                  }}
                />
                {perm}
              </label>
            ))}
          </div>
        </div>
        <button onClick={() => void onCreateToken()} className="rounded-md bg-emerald-500 px-3 py-2 text-sm text-slate-900 font-medium">
          Create Token
        </button>
        {createdTokenSecret && (
          <div className="rounded-md border border-amber-700 bg-amber-950/40 p-2 text-xs">
            <div className="mb-1">New token (copy now; shown once):</div>
            <div className="flex items-center gap-2">
              <code className="overflow-x-auto">{createdTokenSecret}</code>
              <CopyButton text={createdTokenSecret} />
            </div>
          </div>
        )}
      </section>

      {/* Create Client */}
      <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 space-y-3">
        <h3 className="text-sm font-medium">Create Client</h3>
        <p className="text-xs text-slate-400">Creates an OAuth client registered with Cognito for MCP-compatible agents (ChatGPT, Claude, etc.)</p>
        <div className="grid gap-3 md:grid-cols-2">
          <input
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
            placeholder="Client name (e.g. ChatGPT Connector)"
            className="rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm"
            onKeyDown={(e) => { if (e.key === 'Enter') void onCreateClient() }}
          />
          <input
            value={clientRedirectUri}
            onChange={(e) => setClientRedirectUri(e.target.value)}
            placeholder="OAuth Redirect URI (from ChatGPT setup)"
            className="rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm"
            onKeyDown={(e) => { if (e.key === 'Enter') void onCreateClient() }}
          />
        </div>
        <div className="flex gap-3 items-center">
          <button onClick={() => void onCreateClient()} className="rounded-md bg-emerald-500 px-3 py-2 text-sm text-slate-900 font-medium">
            Create Client
          </button>
          <button onClick={() => void reload()} className="rounded-md bg-slate-700 px-3 py-2 text-sm">
            Refresh
          </button>
        </div>
        {!clientRedirectUri.trim() && clientName.trim() && (
          <div className="text-xs text-slate-500">
            No redirect URI provided — a default test URI will be used. You can get the redirect URI from ChatGPT&apos;s OAuth setup page.
          </div>
        )}
        {createdClientCreds && (
          <div className="rounded-md border border-amber-700 bg-amber-950/40 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-amber-300">
                Client created: {createdClientCreds.service_name}
              </span>
              <button
                className="rounded bg-slate-700 px-2 py-1 text-xs hover:bg-slate-600"
                onClick={() => setCreatedClientCreds(null)}
              >
                Dismiss
              </button>
            </div>
            <ClientConfigBlock creds={createdClientCreds} />
          </div>
        )}
      </section>

      {error && <section className="rounded-md border border-rose-700 bg-rose-900/40 p-3 text-sm">{error}</section>}

      {/* Data table */}
      <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-4">
        {loading ? (
          <div className="text-sm text-slate-300">Loading...</div>
        ) : tab === 'tokens' ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="py-2 pr-4">Service</th>
                  <th className="py-2 pr-4">Token ID</th>
                  <th className="py-2 pr-4">Token</th>
                  <th className="py-2 pr-4">Age</th>
                  <th className="py-2 pr-4">Last Used</th>
                  <th className="py-2 pr-4">Action</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((token) => (
                  <tr key={token.token_id} className="border-t border-slate-800">
                    <td className="py-2 pr-4">{token.service_name}</td>
                    <td className="py-2 pr-4">
                      <code className="text-xs">{token.token_id}</code>
                    </td>
                    <td className="py-2 pr-4">
                      <code>{token.token_masked || 'hidden'}</code>
                    </td>
                    <td className="py-2 pr-4">{formatAge(token.token_age_seconds)}</td>
                    <td className="py-2 pr-4">{token.last_used_at || 'never'}</td>
                    <td className="py-2 pr-4">
                      <button
                        className="rounded bg-rose-600 px-2 py-1 text-xs"
                        onClick={() => void onDelete(token.token_id)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {sorted.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-4 text-center text-slate-400">
                      No tokens created yet
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : tab === 'oauth' ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="py-2 pr-4">Service Name</th>
                  <th className="py-2 pr-4">Client ID</th>
                  <th className="py-2 pr-4">Grant Types</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Last Used</th>
                </tr>
              </thead>
              <tbody>
                {sortedClients.map((client) => (
                  <tr key={client.client_id} className="border-t border-slate-800">
                    <td className="py-2 pr-4">{client.service_name}</td>
                    <td className="py-2 pr-4">
                      <div className="flex items-center gap-2">
                        <code className="text-xs">{client.client_id}</code>
                        <CopyButton text={client.client_id} />
                      </div>
                    </td>
                    <td className="py-2 pr-4">{client.grant_types.join(', ')}</td>
                    <td className="py-2 pr-4">
                      <span className="inline-flex items-center gap-1.5">
                        <span
                          className={`inline-block h-2 w-2 rounded-full ${client.status === 'active' ? 'bg-emerald-400' : 'bg-rose-400'}`}
                        />
                        {client.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4">{client.last_used_at || 'never'}</td>
                  </tr>
                ))}
                {sortedClients.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-4 text-center text-slate-400">
                      No OAuth clients registered
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          /* Permissions tab — tokens + OAuth clients */
          <div className="space-y-6">
            {/* Token permissions */}
            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-2">Token Permissions</h4>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-slate-400">
                      <th className="py-2 pr-4">Service</th>
                      {PERMISSION_OPTIONS.map((perm) => (
                        <th key={perm} className="py-2 pr-4 capitalize">{perm}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((token) => (
                      <tr key={token.token_id} className="border-t border-slate-800">
                        <td className="py-2 pr-4">{token.service_name}</td>
                        {PERMISSION_OPTIONS.map((perm) => (
                          <td key={perm} className="py-2 pr-4">
                            <input
                              type="checkbox"
                              checked={token.permissions.includes(perm)}
                              onChange={(e) =>
                                void onToggleTokenPermission(token.token_id, token.permissions, perm, e.target.checked)
                              }
                            />
                          </td>
                        ))}
                      </tr>
                    ))}
                    {sorted.length === 0 && (
                      <tr>
                        <td colSpan={1 + PERMISSION_OPTIONS.length} className="py-3 text-center text-slate-500 text-xs">
                          No tokens
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* OAuth client permissions */}
            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-2">OAuth Client Permissions</h4>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-slate-400">
                      <th className="py-2 pr-4">Client</th>
                      {PERMISSION_OPTIONS.map((perm) => (
                        <th key={perm} className="py-2 pr-4 capitalize">{perm}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sortedClients.map((client) => (
                      <tr key={client.client_id} className="border-t border-slate-800">
                        <td className="py-2 pr-4">
                          <div>{client.service_name}</div>
                          <div className="text-xs text-slate-500">{client.client_id}</div>
                        </td>
                        {PERMISSION_OPTIONS.map((perm) => (
                          <td key={perm} className="py-2 pr-4">
                            <input
                              type="checkbox"
                              checked={(client.permissions || []).includes(perm)}
                              onChange={(e) =>
                                void onToggleClientPermission(client.client_id, client.permissions || [], perm, e.target.checked)
                              }
                            />
                          </td>
                        ))}
                      </tr>
                    ))}
                    {sortedClients.length === 0 && (
                      <tr>
                        <td colSpan={1 + PERMISSION_OPTIONS.length} className="py-3 text-center text-slate-500 text-xs">
                          No OAuth clients
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </section>
    </main>
  )
}
