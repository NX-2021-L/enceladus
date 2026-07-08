/**
 * Skill Library reads — GET /api/v1/documents?project=&document_subtype=skill&
 * include_content=false (document_api Lambda). ENC-TSK-L94 / FTR-129.
 *
 * Sources from the body-excluded metadata-only projection shipped by
 * ENC-TSK-L93 (governance_hash-tracked, gamma): a `document_subtype=skill`
 * list request with `include_content=false` returns only
 * `{ document_id, title, description, version, updated_at, runtime_hint,
 * document_subtype }` — no `full_description`/`claude_description`/`content`
 * body fields, no `keywords`. That last point matters for the AC-4 filter
 * below: `keywords` isn't available on this projection, so the test-fixture
 * exclusion below matches on `document_id`, not on the seed's
 * `keywords: ["enc-ftr-078", "e2e", "skill-seed"]`.
 */

import { queryOptions } from '@tanstack/react-query'
import { API_BASE, SessionExpiredError } from './client'

export interface SkillListItem {
  document_id: string
  title: string
  description: string
  version: string
  updated_at: string
  runtime_hint: string
  document_subtype: string
}

/**
 * ENC-TSK-L94 AC-4: `ftr-078-e2e-skill` (DOC-82D57A4FE6DC, agentskills_manifest
 * name `ftr-078-e2e-skill`) is a smoke-test fixture seeded to verify the
 * ENC-FTR-078 post-deploy `documents.put` validators — not a reusable skill
 * for engineers to browse. Default, absent an explicit io decision: EXCLUDE
 * it from the Skill Library page. Documented here (and in the task worklog)
 * per the AC's "chosen default is documented" requirement — update this set
 * if io decides to include it, or if more e2e fixtures get seeded.
 */
const EXCLUDED_SKILL_DOCUMENT_IDS = new Set<string>(['DOC-82D57A4FE6DC'])

export function isTestSkillRecord(item: Pick<SkillListItem, 'document_id'>): boolean {
  return EXCLUDED_SKILL_DOCUMENT_IDS.has(item.document_id)
}

export async function fetchSkillLibrary(
  projectId: string,
  init?: { signal?: AbortSignal },
): Promise<SkillListItem[]> {
  const qs = new URLSearchParams({
    project: projectId,
    document_subtype: 'skill',
    include_content: 'false',
  })
  const res = await fetch(`${API_BASE}/documents?${qs.toString()}`, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: {
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    },
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new Error(`Failed to fetch skill library (${res.status})`)
  const body = (await res.json()) as { documents?: SkillListItem[] }
  return (body.documents ?? []).filter((item) => !isTestSkillRecord(item))
}

export const skillLibraryKeys = {
  list: (projectId: string) => ['skill-library', projectId] as const,
}

/**
 * No `staleTime` — every mount is treated as fresh (AC-2: "resolved on page
 * mount; no client-side persistent catalog or cache of the skill list").
 * TanStack Query's in-memory query cache is not persisted to disk/localStorage
 * and refetches on mount by default (staleTime 0), matching the existing
 * DocsRoute/ChangelogRoute/GovernanceRoute convention.
 */
export const skillLibraryQueryOptions = (projectId: string) =>
  queryOptions({
    queryKey: skillLibraryKeys.list(projectId),
    queryFn: ({ signal }) => fetchSkillLibrary(projectId, { signal }),
  })
