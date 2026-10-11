import { documentHref, recordHref } from '../routes/recordLink'

type TrackerType = 'task' | 'issue' | 'feature' | 'plan' | 'lesson'

// DVP-TSK-935: governed-ID linking shared by the markdown renderer and the frozen legacy parity oracle.
const TRACKER_PREFIX_TO_TYPE: Record<string, TrackerType> = {
  TSK: 'task',
  ISS: 'issue',
  FTR: 'feature',
  PLN: 'plan',
  LSN: 'lesson',
}

/** Matches every governed ID shape (ENC-<2-5 letter code>-<alnum>, DOC-<hex>)
 *  so every record-ID mention gets the SS2 mono/teal "Record ID" treatment --
 *  not just the five routable tracker types. Only the recognized prefixes
 *  resolve to an actual href (see resolveIdHref); everything else still
 *  renders styled, just unlinked. */
export const ID_TOKEN_SOURCE = String.raw`\b(?:ENC-[A-Z]{2,5}-[A-Za-z0-9]+|DOC-[A-Za-z0-9]+)\b`

/** Resolves a governed record-ID token to its detail route, or null when the
 *  prefix isn't one of the five routable tracker types / documents (e.g.
 *  ENC-SES-*, ENC-ESC-*, ENC-AGT-* have no detail route today -- render as
 *  plain mono text rather than a dead link) or, for a tracker prefix,
 *  no projectId was supplied to resolve the project-scoped route against.
 *  Exported as a pure function so it's unit-testable without a
 *  RouterProvider (this package's tests are logic-level, not
 *  component-level -- see primitives/SessionPrimitive.test.tsx). */
export function resolveIdHref(token: string, projectId: string | undefined): string | null {
  if (token.startsWith('DOC-')) return documentHref(token)
  const match = /^ENC-(TSK|ISS|FTR|PLN|LSN)-/.exec(token)
  if (match && projectId) {
    return recordHref(projectId, TRACKER_PREFIX_TO_TYPE[match[1]], token)
  }
  return null
}
