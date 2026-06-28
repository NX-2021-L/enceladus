/**
 * Live governance documentation reader (ENC-TSK-B67 AC-20, ENC-ISS-121).
 *
 * The PWA 2.0 serves ALL governance documentation — agents.md,
 * lifecycle-primer.md, the governance data dictionary, and every docstore
 * document — from the live governed store via the MCP read path. There is NO
 * bundled/static mirror file imported anywhere: editing a governance document
 * via `documents.patch` (or the §13 governance-sync path) is reflected on the
 * next read with no PWA redeploy.
 *
 * This module deliberately contains zero `import './something.md'` static
 * imports — the content always comes over the network from the governed read
 * endpoints, satisfying the ENC-ISS-121 resolution required by AC-20.
 */

import { fetchWithAuth } from '../api/client'

/** Governed read endpoints (backed by the MCP governance.get / documents.get). */
const GOVERNANCE_BASE = '/api/v1/governance'
const DOCUMENTS_BASE = '/api/v1/documents'

export const governanceDocKeys = {
  file: (fileName: string) => ['governance', 'file', fileName] as const,
  dictionary: ['governance', 'dictionary'] as const,
  document: (documentId: string) => ['governance', 'document', documentId] as const,
}

export interface GovernanceFile {
  file_name: string
  content: string
  source: 'live-governed-store'
  fetched_at: string
}

/**
 * Fetch a live governance file (e.g. "agents.md", "agents/lifecycle-primer.md")
 * from the governed store via the MCP read path.
 */
export async function fetchGovernanceFile(fileName: string): Promise<GovernanceFile> {
  const res = await fetchWithAuth(`${GOVERNANCE_BASE}/${encodeURIComponent(fileName)}`, {
    headers: { Accept: 'text/markdown,application/json;q=0.9,*/*;q=0.8' },
  })
  if (!res.ok) throw new Error(`Failed to fetch governance file ${fileName}: ${res.status}`)
  const contentType = res.headers.get('content-type') ?? ''
  const content = contentType.includes('application/json')
    ? ((await res.json()).content ?? '')
    : await res.text()
  return {
    file_name: fileName,
    content,
    source: 'live-governed-store',
    fetched_at: new Date().toISOString(),
  }
}

/** Fetch the live governance data dictionary (entity index). */
export async function fetchGovernanceDictionary(): Promise<unknown> {
  const res = await fetchWithAuth(`${GOVERNANCE_BASE}/dictionary`)
  if (!res.ok) throw new Error(`Failed to fetch governance dictionary: ${res.status}`)
  return res.json()
}

/** Fetch any docstore document live by id (e.g. DOC-FFB4C9D87BCC). */
export async function fetchGovernedDocument(documentId: string): Promise<{ content: string }> {
  const res = await fetchWithAuth(`${DOCUMENTS_BASE}/${encodeURIComponent(documentId)}`)
  if (!res.ok) throw new Error(`Failed to fetch document ${documentId}: ${res.status}`)
  const data = await res.json()
  const doc = data.document ?? data
  return { content: doc.content ?? '' }
}
