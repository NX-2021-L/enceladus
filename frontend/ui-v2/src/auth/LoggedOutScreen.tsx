import { redirectToLogin } from './authConfig'

/**
 * ENC-TSK-K95 — full-screen sign-in prompt.
 *
 * Rendered by the router's defaultErrorComponent when a loader/query throws
 * SessionExpiredError (a 401 from the API). Replaces the generic
 * "Something went wrong!" crash the cockpit used to show on every record click
 * for an unauthenticated visitor. Design tokens only (no hardcoded hex).
 */
export function LoggedOutScreen() {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: 'var(--space-6)',
        background: 'var(--enc-void)',
      }}
    >
      <p
        style={{
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-xs)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--tracking-label)',
          color: 'var(--fg-muted)',
          margin: '0 0 var(--space-2)',
        }}
      >
        Enceladus · Governance Cockpit
      </p>
      <h1
        style={{
          fontFamily: 'var(--font-heading)',
          fontWeight: 'var(--fw-bold)',
          fontSize: 'var(--text-2xl)',
          lineHeight: 'var(--lh-tight)',
          color: 'var(--fg-display)',
          margin: '0 0 var(--space-2)',
        }}
      >
        Sign in to continue
      </h1>
      <p
        style={{
          color: 'var(--fg-muted)',
          fontSize: 'var(--text-sm)',
          lineHeight: 'var(--lh-relaxed)',
          margin: '0 0 var(--space-6)',
          maxWidth: '38ch',
        }}
      >
        Your session isn't active. Sign in with your Enceladus account to view
        live records, plans, and documents.
      </p>
      <button
        type="button"
        onClick={redirectToLogin}
        style={{
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-sm)',
          fontWeight: 'var(--fw-medium)',
          color: 'var(--enc-void)',
          background: 'var(--accent)',
          border: '1px solid var(--accent)',
          borderRadius: 'var(--radius-md)',
          padding: 'var(--space-3) var(--space-6)',
          cursor: 'pointer',
          boxShadow: 'var(--glow-teal)',
        }}
      >
        Sign In
      </button>
    </div>
  )
}
