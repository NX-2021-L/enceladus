import { APP_VERSION } from '../../lib/version'
import {
  COGNITO_DOMAIN,
  COGNITO_CLIENT_ID,
  COGNITO_REDIRECT_URI,
  COGNITO_SCOPES,
} from '../../lib/constants'

/**
 * Full-screen "logged out" landing page.
 *
 * Rendered by AppShell when authStatus === 'logged-out'. Matches the app's
 * dark-mode slate-900 aesthetic and provides a single "Sign In" button that
 * starts the Cognito OAuth2 authorization-code flow.
 *
 * The `state` query parameter carries the user's current path so Lambda@Edge
 * can redirect them back to the right page after login.
 */
export function LoggedOutScreen() {
  function handleSignIn() {
    const currentPath = window.location.pathname + window.location.search
    // Use base64url encoding to match Lambda@Edge which decodes via
    // Buffer.from(state, 'base64url'). Standard btoa() produces '+', '/'
    // and '=' which base64url silently corrupts.
    const state = btoa(currentPath)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')

    const loginUrl =
      `${COGNITO_DOMAIN}/oauth2/authorize` +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(COGNITO_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(COGNITO_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(COGNITO_SCOPES)}` +
      `&state=${encodeURIComponent(state)}`

    window.location.assign(loginUrl)
  }

  return (
    <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-slate-900 text-center px-6">
      {/* App icon / title */}
      <div className="mb-8">
        <h1 className="text-lg font-semibold text-slate-100">Project Status</h1>
        <p className="text-sm text-slate-400 mt-1">You've been logged out</p>
        <p className="text-xs text-slate-500 mt-2">Sign in to continue where you left off</p>
      </div>

      {/* Sign In button */}
      <button
        type="button"
        onClick={handleSignIn}
        className="px-8 py-3 rounded-full bg-emerald-700 text-emerald-100 border border-emerald-600 text-sm font-medium hover:bg-emerald-600 active:bg-emerald-800 transition-colors"
      >
        Sign In
      </button>

      {/* Version */}
      <p className="text-xs text-slate-500 mt-12">v{APP_VERSION}</p>
    </div>
  )
}
