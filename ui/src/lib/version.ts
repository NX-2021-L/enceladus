/**
 * Enceladus PWA Version & Release Notes
 *
 * Versioning convention (X.Y.Z):
 *   X (major)  — incremented only when explicitly instructed by the end user
 *   Y (minor)  — incremented when a deployment significantly changes or enhances
 *                 the product experience (new feature, major UX overhaul)
 *   Z (patch)  — incremented on every deployment at minimum (bug fix, tweak, etc.)
 *
 * The first version of any major product or feature starts at 0.1.0.
 * Agents may suggest the next version but should ask the user if uncertain
 * whether a change warrants a minor vs. patch bump.
 *
 * This version string is baked into the JS bundle at build time.
 * When a new build is deployed and the user clicks REFRESH, the new bundle
 * loads and the version in the header updates — confirming the latest code
 * is active in the browser.
 */

/** Current release version — update this on every deployment */
export const APP_VERSION = '0.17.0'

/** Structured release history — newest first */
export interface ReleaseNote {
  version: string
  date: string            // ISO-8601 date (YYYY-MM-DD)
  type: 'major' | 'minor' | 'patch'
  summary: string         // One-line human-readable summary
  changes: string[]       // Bullet-point list of individual changes
}

export const RELEASE_NOTES: ReleaseNote[] = [
  {
    version: '0.17.0',
    date: '2026-02-23',
    type: 'minor',
    summary: 'Active session and coordination badges with feed_query boolean fix (ENC-TSK-488)',
    changes: [
      'ActiveSessionBadge component (green animated pill) on task cards',
      'CoordinationFlagBadge component (blue animated pill) on all card types',
      'Type extensions for Task/Issue/Feature with boolean badge fields',
      'feed_query Lambda: add _ddb_bool() helper for DynamoDB BOOL and string type handling',
      'feed_query Lambda: surface active_agent_session, active_agent_session_parent, coordination fields in task transform',
      'feed_query Lambda: surface coordination field in issue and feature transforms',
      'feed_utils.py: harden _ddb_item_to_yaml_record() with explicit _to_bool() on boolean fields',
      'feed_query Lambda source added to repo as api/lambda/feed_query/',
    ],
  },
  {
    version: '0.16.1',
    date: '2026-02-20',
    type: 'patch',
    summary: 'Fix React error #310: move useMemo before early returns in detail pages',
    changes: [
      'Move useMemo above early returns in TaskDetailPage to fix hooks ordering',
      'Move useMemo above early returns in IssueDetailPage to fix hooks ordering',
    ],
  },
  {
    version: '0.16.0',
    date: '2026-02-20',
    type: 'minor',
    summary: 'Closed-Status Firewall: add Reopen button to PWA detail pages',
    changes: [
      'Add Reopen button with confirm flow to TaskDetailPage',
      'Add Reopen button with confirm flow to IssueDetailPage',
      'Add Reopen button with confirm flow to FeatureDetailPage',
      'Add reopenRecord API function in mutations.ts',
      'Update useRecordMutation hook for reopen action with optimistic update',
    ],
  },
  {
    version: '0.15.0',
    date: '2026-02-20',
    type: 'minor',
    summary: 'MCP server v0.4.0 deployment-service adapter tools; Parent/child hierarchy and rich RelatedItems on detail pages',
    changes: [
      'MCP deploy_submit: submit deployment requests via MCP',
      'MCP deploy_state_set: toggle ACTIVE/PAUSED state',
      'MCP deploy_status: check spec status by ID',
      'MCP deploy_trigger: manual SQS pipeline trigger',
      'MCP deploy_pending_requests: list pending requests',
      'Add parent field to feed pipeline (feed_utils.py + feed_query Lambda)',
      'New ParentRecord component shows parent record with title and status',
      'New ChildRecords component finds and displays child records grouped by type',
      'Upgrade RelatedItems from ID chips to rich display with title and status',
    ],
  },
  {
    version: '0.14.1',
    date: '2026-02-19',
    type: 'patch',
    summary: 'UI Deployment Manager integration test + MarkdownRenderer TS fix (DVP-FTR-028)',
    changes: [
      'First automated deployment via UI Deployment Manager pipeline',
      'Fix extractText type assertion in MarkdownRenderer',
      'Deployment manager infrastructure and API Gateway routes',
    ],
  },
  {
    version: '0.14.0',
    date: '2026-02-19',
    type: 'minor',
    summary: 'Rich markdown rendering on all detail pages and document content (DVP-FTR-027)',
    changes: [
      'Shared MarkdownRenderer component extracted from ProjectReferencePage with full GitHub-flavored markdown support',
      'Internal anchor links on headings with smooth scroll-to-hash navigation',
      'DocumentDetailPage content rendered as rich markdown instead of raw monospace text',
      'Feature/Task/Issue detail page descriptions rendered with full markdown formatting',
      'Record ID auto-linking (DVP-TSK-xxx, DVP-FTR-xxx, etc.) preserved in all markdown content',
      'Support for headings, bold, italic, code blocks, tables, blockquotes, lists, and external links',
      'ProjectReferencePage refactored to use shared MarkdownRenderer (DRY)',
    ],
  },
  {
    version: '0.13.2',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Suppress session-expired overlay during live feed polling',
    changes: [
      'Live feed polling 401s no longer trigger SessionExpiredOverlay (silently retries on next poll cycle)',
      'QueryCache.onError respects suppressSessionExpired meta flag on background polling queries',
      'Session refresh overlay only appears for user-initiated actions and initial data loads',
    ],
  },
  {
    version: '0.13.1',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Fix Feed page blinking — single polling observer + animated item transitions (DVP-ISS-021)',
    changes: [
      'useFeed: single useQuery observer for live feed (was 4 observers × 3s = ~750ms effective poll rate)',
      'useStableArray: stabilise array references across polls when data is unchanged',
      'AnimatedList: FLIP-based item transitions — moved items slide, new items fade in',
      'useInfiniteList: removed auto page-reset on length change to prevent scroll jumps during live updates',
    ],
  },
  {
    version: '0.13.0',
    date: '2026-02-19',
    type: 'minor',
    summary: 'Fix document detail loading after opening Docs tab (DVP-ISS-020)',
    changes: [
      'Document API client now accepts both single-document response shapes (document envelope and direct object)',
      'Document detail page adds defensive fallback for missing keywords/related_items arrays to prevent render-time failures',
      'Complements backend path parsing compatibility fix for /api/v1/documents/{id} retrieval',
    ],
  },
  {
    version: '0.12.1',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Fix Feed page blinking caused by live polling re-renders (DVP-ISS-021)',
    changes: [
      'useFeed: split live feed query into per-array selectors so TanStack structural sharing preserves stable references when data is unchanged',
      'Lambda: sort tasks/issues/features by item ID for deterministic array ordering across poll cycles',
      'Eliminates full component tree re-render on every 3-second poll when no data has changed',
    ],
  },
  {
    version: '0.12.0',
    date: '2026-02-19',
    type: 'minor',
    summary: 'Real-time Feed via direct DynamoDB API (DVP-FTR-025 completion)',
    changes: [
      'New feed_query Lambda reads DynamoDB directly for 3-second real-time polling',
      'Feed page now shows live data instead of S3 pipeline feeds (~6 min latency eliminated)',
      'Hybrid data strategy: S3 feeds for fast initial load, DynamoDB API for live updates',
      'API Gateway GET /api/v1/feed with Cognito JWT auth and CORS',
      'CloudFront behavior /api/v1/feed* with CachingDisabled for real-time freshness',
    ],
  },
  {
    version: '0.11.2',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Safari cache-busting fixes for reliable version updates (DVP-FTR-026)',
    changes: [
      'Manual SW registration with updateViaCache:none to bypass Safari disk cache for sw.js',
      'REFRESH button uses cache-busting URL redirect instead of location.reload()',
      'Custom CloudFront cache policy (MinTTL=0, DefaultTTL=60s) honors S3 Cache-Control headers',
      'Disabled vite-plugin-pwa auto-registration in favor of manual registration',
    ],
  },
  {
    version: '0.11.1',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Fix React error #310 crash on FeatureDetailPage (DVP-ISS-014)',
    changes: [
      'FeatureDetailPage: moved useMemo hooks above early returns to fix conditional hook call violation',
      'Root cause: useMemo for relatedTaskIds/relatedIssueIds called after early return on isPending, causing React to see different hook counts between renders',
    ],
  },
  {
    version: '0.11.0',
    date: '2026-02-19',
    type: 'minor',
    summary: 'Centralized Feed page replaces separate Tasks/Issues/Features lists (DVP-FTR-025)',
    changes: [
      'New unified Feed page combining tasks, issues, and features into one stream',
      'Hierarchical filtering: project prefix > record type > type-specific filters',
      'Real-time 3-second polling on Feed page via TanStack Query refetchInterval',
      'Colored left-border type indicators (blue=task, amber=issue, emerald=feature)',
      'Bottom navigation reduced from 6 items to 4 (Home, Projects, Feed, Docs)',
      'Infinite scroll with 100-item visible cap',
      'Old /tasks, /issues, /features list routes redirect to /feed',
    ],
  },
  {
    version: '0.10.2',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Fix close/note mutations always triggering session-expired loop (DVP-ISS-015)',
    changes: [
      'Lambda@Edge v7: enceladus_refresh_token cookie Path changed from /api/v1/auth to /',
      'Lambda@Edge v7: Added callback diagnostic logging for refresh_token presence',
      'Mutation Lambda: Added auth failure logging (cookie missing or JWT invalid)',
    ],
  },
  {
    version: '0.10.1',
    date: '2026-02-19',
    type: 'patch',
    summary: 'Fix re-login stuck on session-expired screen after automatic logout (DVP-ISS-013)',
    changes: [
      'Service worker: exclude /enceladus/callback from NavigationRoute denylist',
      'authState: setLoggedOut() now clears localStorage session key',
      'main.tsx: bootstrapSessionTimestamp unconditionally writes valid cookie values',
      'LoggedOutScreen: fix btoa() → base64url encoding for state parameter',
    ],
  },
  {
    version: '0.10.0',
    date: '2026-02-18',
    type: 'minor',
    summary: 'Custom auth UX with session management, mutation retry, and credential refresh',
    changes: [
      'Custom LoggedOutScreen with OAuth sign-in (replaces default Cognito UI)',
      'Client-side 60-minute session timer with activity-based refresh',
      'SessionExpiredOverlay auto-refreshes credentials before falling back to login',
      '3-state auth machine: authenticated / expired / logged-out',
      'Mutation retry with credential refresh (3 cycles, 10s timeout each)',
      'MutationRetryExhaustedError with detailed debug output on failure',
      'MutationCache.onError handler for global mutation error handling',
      'Token refresh Lambda (POST /api/v1/auth/refresh)',
      'Lambda@Edge sets refresh_token and session_at cookies on login',
      'Session timestamp bootstrap from cookie on app load',
      'Removed redirectToReauth — all auth flows handled by overlay/screen',
    ],
  },
  {
    version: '0.9.0',
    date: '2026-02-19',
    type: 'minor',
    summary: 'Version display and release notes framework',
    changes: [
      'Added version display in header (left of REFRESH link)',
      'Established X.Y.Z versioning convention for Enceladus PWA',
      'Added structured release notes in version.ts',
      'Feature-flagged REFRESH link (DVP-FTR-015) included from v0.8',
    ],
  },
  {
    version: '0.8.0',
    date: '2026-02-18',
    type: 'minor',
    summary: 'Manual refresh link for cache busting',
    changes: [
      'Added REFRESH link at top-right of every page (DVP-FTR-015)',
      'Unregisters service workers, clears Cache Storage, forces full reload',
      'Feature-flagged via ENABLE_REFRESH_LINK constant',
    ],
  },
  {
    version: '0.7.0',
    date: '2026-02-18',
    type: 'minor',
    summary: 'Session expiry UX improvements',
    changes: [
      'Fixed Safari session expiry redirect (location.reload instead of assign)',
      'Added SessionExpiredOverlay with spinner and fallback button',
      'Reduced overlay timer from 8s to 4s',
    ],
  },
  {
    version: '0.6.0',
    date: '2026-02-18',
    type: 'minor',
    summary: 'PWA write capability — close and note actions',
    changes: [
      'Close/complete actions on task, issue, and feature detail pages',
      'Free-text note submission via mutation API',
      'Optimistic UI updates with React Query invalidation',
      'Cognito JWT cookie auth for /api/v1/tracker/* mutations',
    ],
  },
  {
    version: '0.5.0',
    date: '2026-02-17',
    type: 'minor',
    summary: 'Production deployment and authentication',
    changes: [
      'Deployed to https://jreese.net/enceladus via S3 + CloudFront',
      'Cognito + Lambda@Edge authentication on all protected paths',
      'SPA router fallback for /enceladus/* non-asset paths',
    ],
  },
  {
    version: '0.4.0',
    date: '2026-02-17',
    type: 'minor',
    summary: 'Detail pages with search, sort, and infinite scroll',
    changes: [
      'Task, issue, and feature detail pages',
      'Cross-project search with text filtering',
      'Sort by last updated, created, or priority',
      'Infinite scroll with react-window virtualization',
    ],
  },
  {
    version: '0.3.0',
    date: '2026-02-17',
    type: 'minor',
    summary: 'List views and navigation',
    changes: [
      'Project list, task list, issue list, feature list pages',
      'Bottom navigation with active state indicators',
      'Status/priority badge components with color coding',
    ],
  },
  {
    version: '0.2.0',
    date: '2026-02-17',
    type: 'minor',
    summary: 'Dashboard and feed integration',
    changes: [
      'Dashboard page with project summary cards',
      'Integration with /mobile/v1 JSON feeds from DynamoDB',
      'React Query for data fetching and caching',
    ],
  },
  {
    version: '0.1.0',
    date: '2026-02-17',
    type: 'minor',
    summary: 'Initial Enceladus PWA scaffold',
    changes: [
      'React 19 + Vite + Tailwind CSS project structure',
      'PWA manifest and service worker via vite-plugin-pwa',
      'AppShell layout with Header and BottomNav',
      'React Router with /enceladus/ base path',
    ],
  },
]
