import { useEffect, useMemo, useState } from 'react'
import {
  createManagedAuthToken,
  deleteManagedAuthToken,
  listManagedAuthTokens,
  listOAuthClients,
  updateManagedAuthPermissions,
  type ManagedAuthToken,
  type OAuthClient,
} from '../api/authTokens'

const PERMISSION_OPTIONS = ['read', 'write', 'put', 'delete', 'admin'] as const

type Tab = 'tokens' | 'permissions' | 'oauth'

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

export function AuthTokensPage() {
  const [tab, setTab] = useState<Tab>('tokens')
  const [tokens, setTokens] = useState<ManagedAuthToken[]>([])
  const [oauthClients, setOauthClients] = useState<OAuthClient[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [serviceName, setServiceName] = useState('')
  const [createPerms, setCreatePerms] = useState<string[]>(['read'])
  const [createdSecret, setCreatedSecret] = useState<string>('')

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

  async function onCreate() {
    if (!serviceName.trim()) return
    setError(null)
    try {
      const result = await createManagedAuthToken({
        service_name: serviceName.trim(),
        permissions: createPerms,
      })
      setCreatedSecret(result.token.token)
      setServiceName('')
      await reload()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create failed')
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

  async function onTogglePermission(tokenId: string, existing: string[], perm: string, checked: boolean) {
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

  return (
    <main className="mx-auto max-w-6xl px-4 py-4 space-y-4 text-slate-100">
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
            className={`rounded-md px-3 py-1 text-sm ${tab === 'permissions' ? 'bg-slate-200 text-slate-900' : 'bg-slate-700'}`}
            onClick={() => setTab('permissions')}
          >
            Permissions
          </button>
          <button
            className={`rounded-md px-3 py-1 text-sm ${tab === 'oauth' ? 'bg-slate-200 text-slate-900' : 'bg-slate-700'}`}
            onClick={() => setTab('oauth')}
          >
            OAuth Clients
          </button>
        </div>
      </section>

      <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 space-y-3">
        <h3 className="text-sm font-medium">Generate Token</h3>
        <div className="grid gap-3 md:grid-cols-3">
          <input
            value={serviceName}
            onChange={(e) => setServiceName(e.target.value)}
            placeholder="Service name"
            className="rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm"
          />
          <div className="md:col-span-2 flex flex-wrap gap-3">
            {PERMISSION_OPTIONS.map((perm) => (
              <label key={perm} className="text-xs flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={createPerms.includes(perm)}
                  onChange={(e) => {
                    setCreatePerms((current) =>
                      e.target.checked ? [...new Set([...current, perm])] : current.filter((p) => p !== perm),
                    )
                  }}
                />
                {perm}
              </label>
            ))}
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={onCreate} className="rounded-md bg-emerald-500 px-3 py-2 text-sm text-slate-900 font-medium">
            Create Token
          </button>
          <button onClick={() => void reload()} className="rounded-md bg-slate-700 px-3 py-2 text-sm">
            Refresh
          </button>
        </div>
        {createdSecret && (
          <div className="rounded-md border border-amber-700 bg-amber-950/40 p-2 text-xs">
            <div className="mb-1">New token (copy now; shown once):</div>
            <div className="flex items-center gap-2">
              <code className="overflow-x-auto">{createdSecret}</code>
              <button
                className="rounded bg-slate-700 px-2 py-1"
                onClick={() => navigator.clipboard.writeText(createdSecret)}
              >
                Copy
              </button>
            </div>
          </div>
        )}
      </section>

      {error && <section className="rounded-md border border-rose-700 bg-rose-900/40 p-3 text-sm">{error}</section>}

      <section className="rounded-xl border border-slate-700 bg-slate-900/60 p-4">
        {loading ? (
          <div className="text-sm text-slate-300">Loading tokens...</div>
        ) : tab === 'tokens' ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="py-2 pr-4">Service</th>
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
                      <div className="flex items-center gap-2">
                        <code>{token.token_masked || 'hidden'}</code>
                        <button className="rounded bg-slate-700 px-2 py-1 text-xs" disabled>
                          Copy
                        </button>
                      </div>
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
              </tbody>
            </table>
          </div>
        ) : tab === 'permissions' ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="py-2 pr-4">Service</th>
                  {PERMISSION_OPTIONS.map((perm) => (
                    <th key={perm} className="py-2 pr-4 capitalize">
                      {perm}
                    </th>
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
                            void onTogglePermission(token.token_id, token.permissions, perm, e.target.checked)
                          }
                        />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
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
                {oauthClients.map((client) => (
                  <tr key={client.client_id} className="border-t border-slate-800">
                    <td className="py-2 pr-4">{client.service_name}</td>
                    <td className="py-2 pr-4">
                      <code className="text-xs">{client.client_id}</code>
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
                {oauthClients.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-4 text-center text-slate-400">
                      No OAuth clients registered
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  )
}
