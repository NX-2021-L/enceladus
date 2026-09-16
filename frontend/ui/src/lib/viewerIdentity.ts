/**
 * viewerIdentity.ts — best-effort client-side lookup of the viewing user's
 * Cognito `sub`, for attribution fields like documents.patch_section's
 * `caused_by` (ENC-TSK-P80 AC-2).
 *
 * KNOWN GAP (see task notes / blockers): frontend/ui's session lives entirely
 * in the HttpOnly `enceladus_id_token` cookie (backend/lambda/auth_refresh/
 * lambda_function.py sets it `HttpOnly`), and there is no whoami/session
 * endpoint that echoes decoded claims back to the client — grepping this app
 * confirms no existing `idToken`/`.sub` client-side pattern; only the plain
 * timestamp cookie `enceladus_session_at` is JS-readable. Every other PWA
 * mutation lets the server derive identity from the JWT itself
 * (backend/lambda/document_api/lambda_function.py: `claims.get('sub',
 * 'unknown')`) rather than trusting a client-supplied identity field.
 *
 * The section-patch contract nonetheless asks the CLIENT to send `caused_by`,
 * so this reads a forward-compatible, non-HttpOnly identity cookie if one is
 * ever introduced by a backend lane, and otherwise falls back to the same
 * `'unknown'` sentinel the backend already uses when a claim is absent — a
 * safe, honest degrade rather than fabricating an identity.
 */
const IDENTITY_COOKIE_NAME = 'enceladus_viewer_sub'
const UNKNOWN_SUB = 'unknown'

export function getViewingUserSub(): string {
  if (typeof document === 'undefined') return UNKNOWN_SUB
  const cookies = document.cookie ? document.cookie.split(';') : []
  for (const part of cookies) {
    const trimmed = part.trim()
    if (!trimmed.startsWith(`${IDENTITY_COOKIE_NAME}=`)) continue
    const raw = trimmed.slice(IDENTITY_COOKIE_NAME.length + 1)
    try {
      const value = decodeURIComponent(raw).trim()
      if (value) return value
    } catch {
      // malformed cookie value — fall through to sentinel
    }
  }
  return UNKNOWN_SUB
}
