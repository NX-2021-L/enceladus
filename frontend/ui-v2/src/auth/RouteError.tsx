import type { ErrorComponentProps } from '@tanstack/react-router'
import { SessionExpiredError } from '../api/client'
import { LoggedOutScreen } from './LoggedOutScreen'

/**
 * ENC-TSK-K95 — router-wide error component.
 *
 * A 401 from any loader/query surfaces as SessionExpiredError; instead of the
 * generic crash, prompt sign-in. Everything else falls back to a minimal,
 * design-token error card (no raw stack, no white screen).
 */
export function RouteError({ error }: ErrorComponentProps) {
  if (error instanceof SessionExpiredError) {
    return <LoggedOutScreen />
  }

  const message =
    error instanceof Error ? error.message : 'An unexpected error occurred.'

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: 'var(--space-8) var(--space-6)',
        color: 'var(--fg)',
      }}
    >
      <h1
        style={{
          fontFamily: 'var(--font-heading)',
          fontWeight: 'var(--fw-bold)',
          fontSize: 'var(--text-lg)',
          color: 'var(--fg-display)',
          margin: '0 0 var(--space-2)',
        }}
      >
        Something went wrong
      </h1>
      <p
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-xs)',
          color: 'var(--fg-muted)',
          margin: '0 0 var(--space-4)',
          maxWidth: '52ch',
          wordBreak: 'break-word',
        }}
      >
        {message}
      </p>
      <button
        type="button"
        onClick={() => window.location.assign('/')}
        style={{
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-sm)',
          color: 'var(--fg)',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-md)',
          padding: 'var(--space-2) var(--space-5)',
          cursor: 'pointer',
        }}
      >
        Back to cockpit
      </button>
    </div>
  )
}
