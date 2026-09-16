/**
 * viewerIdentity.ts — best-effort client-side lookup of the viewing user's
 * Cognito `sub`, for attribution fields like documents.patch_section's
 * `caused_by` (ENC-TSK-P92, ports ENC-TSK-P80).
 *
 * KNOWN GAP (see task notes / blockers): the cockpit's session lives entirely
 * in an HttpOnly `enceladus_id_token`-style cookie set by the auth callback
 * (src/auth/authConfig.ts — Cognito Hosted-UI code exchange happens
 * server-side), and there is no whoami/session endpoint that echoes decoded
 * claims back to the client — grepping src/auth confirms no existing
 * `idToken`/`.sub` client-side pattern. Every other PWA mutation lets the
 * server derive identity from the JWT itself rather than trusting a
 * client-supplied identity field.
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
