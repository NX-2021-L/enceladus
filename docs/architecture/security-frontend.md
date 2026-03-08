# Enceladus Architecture: Security & Frontend

> Sections 6-8 extracted from ARCHITECTURE.md (ENC-TSK-819).
> For navigation, see [docs/ARCHITECTURE.md](../ARCHITECTURE.md).

---

# SECTION 6 — AUTHENTICATION & SECURITY

## [SECTION 6.1] Cognito Configuration

| Property | Value |
|----------|-------|
| **User Pool ID** | `us-east-1_b2D0V3E1k` |
| **User Pool Name** | `enceladus-status-users` |
| **Client ID** | `6q607dk3liirhtecgps7hifmlk` |
| **Domain** | `enceladus-status-356364570033.auth.us-east-1.amazoncognito.com` |
| **Region** | us-east-1 |
| **Scopes** | openid, email, profile |
| **Redirect URI** | `https://jreese.net/enceladus/callback` |
| **Token Signing** | RS256 |
| **Token Expiration** | 1 hour |

## [SECTION 6.2] JWT Validation

All API Lambdas validate JWT from cookies using the shared layer auth module:
1. Extract `enceladus_id_token` from `headers.cookie` AND `event.cookies` (API Gateway v2)
2. Fetch JWKS from `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_b2D0V3E1k/.well-known/jwks.json`
3. Cache JWKS for 1 hour (module-level singleton)
4. Verify RS256 signature, expiration, audience, issuer
5. Return decoded token payload on success, 401 on failure

**Critical Note:** Both `headers.cookie` AND `event.cookies` must be checked. API Gateway v2 provides cookies in both locations depending on request format.

## [SECTION 6.3] Service-to-Service Auth

| Header | Value Source | Used By |
|--------|-------------|---------|
| `X-Coordination-Internal-Key` | Environment variable `COORDINATION_INTERNAL_API_KEY` | MCP server -> Lambda APIs |

This bypasses Cognito JWT validation for internal service calls.

## [SECTION 6.4] Auth Cookie Architecture

| Cookie | HttpOnly | Secure | SameSite | Max-Age | Purpose |
|--------|----------|--------|----------|---------|---------|
| `enceladus_id_token` | Yes | Yes | None | 3600 | JWT for API authentication |
| `enceladus_refresh_token` | Yes | Yes | Lax | 86400 | Cognito refresh token |
| `enceladus_session_at` | No | Yes | None | 3600 | Session timestamp (JS-readable) |

## [SECTION 6.5] IAM Security Model

Three-role model (ENC-TSK-564):

| Role | Purpose | Allowed | Denied |
|------|---------|---------|--------|
| `enceladus-agent-cli` | Local agent sessions | STS, CloudWatch reads, Lambda inspect, S3 reads, doc/deploy table reads, SQS SendMessage | All DynamoDB writes, tracker/projects reads, S3 writes, Lambda mutations, IAM, STS AssumeRole |
| CI backend deploy | GitHub Actions backend | Lambda update, S3 write, CloudFormation | (scoped to backend resources) |
| CI frontend deploy | GitHub Actions UI | S3 write, CloudFront invalidation | (scoped to frontend resources) |

**Critical:** Agent sessions MUST use MCP tools for all mutations. Direct DynamoDB/S3 writes are IAM-denied.

## [SECTION 6.6] Secrets Manager

| Secret | Purpose | Used By |
|--------|---------|---------|
| `devops/github-app/private-key` | GitHub App RS256 private key | github_integration Lambda |
| `devops/github-app/webhook-secret` | GitHub webhook HMAC secret | github_integration Lambda |
| Anthropic API key | Claude API access | coordination_api Lambda |
| OpenAI API key | Codex API access | coordination_api Lambda |

---

# SECTION 7 — FRONTEND (PWA)

## [SECTION 7.1] Framework and Build Configuration

| Property | Value |
|----------|-------|
| **Framework** | React 19.2.0 |
| **Language** | TypeScript 5.9.3 (strict mode) |
| **Build Tool** | Vite 7.3.1 |
| **Styling** | Tailwind CSS 4.1.18 (via @tailwindcss/vite) |
| **State** | TanStack React Query 5.90.21 + React Context |
| **Routing** | React Router DOM 7.13.0 |
| **Testing** | Vitest 4.0.18 + React Testing Library |
| **PWA Plugin** | vite-plugin-pwa 1.2.0 |
| **Markdown** | react-markdown 10.1.0 + react-syntax-highlighter 16.1.0 |
| **Virtualization** | react-window 2.2.7 |
| **Base Path** | `/enceladus/` |
| **Source** | `frontend/ui/src/` |
| **Build Output** | `frontend/ui/dist/` |

**Manual Chunks (Vite):** react-core, react-router, query, markdown, virtualized, routes, shell

## [SECTION 7.2] Pages and Routes

| Path | Component | Description |
|------|-----------|-------------|
| `/` | DashboardPage | Stat cards + top projects |
| `/projects` | ProjectsListPage | All projects |
| `/projects/create` | CreateProjectPage | New project form |
| `/projects/:projectId` | ProjectDetailPage | Tabs: Tasks/Issues/Features |
| `/projects/:projectId/reference` | ProjectReferencePage | Markdown reference doc |
| `/feed` | FeedPage | Unified feed with live polling (3s) |
| `/tasks/:taskId` | TaskDetailPage | Task detail + mutations |
| `/issues/:issueId` | IssueDetailPage | Issue detail |
| `/features/:featureId` | FeatureDetailPage | Feature detail |
| `/documents` | DocumentsListPage | All documents |
| `/documents/:documentId(/:slug)` | DocumentDetailPage | Document content |
| `/coordination` | CoordinationPage | Coordination requests |
| `/coordination/:requestId` | CoordinationDetailPage | Request detail |

## [SECTION 7.3] API Client Layer

**Base URLs (configurable via VITE_* env vars):**
- Feed: `/mobile/v1` (S3 CDN)
- Mutation: `/api/v1/tracker`
- General: `/api/v1`
- GitHub: `/api/v1/github`

**Retry Pattern (mutations):** 3-cycle with 10s abort timeout. On 401, calls `refreshCredentials()` before retry. Client errors (4xx) throw immediately. Server errors (5xx) retry.

**Feed Functions:** fetchProjects, fetchTasks, fetchIssues, fetchFeatures, fetchDocumentsFeed, fetchLiveFeed (single observer), fetchProjectReference
**Mutation Functions:** closeRecord, reopenRecord, submitNote, setField
**Auth Functions:** refreshCredentials (POST /api/v1/auth/refresh)
**Document Functions:** fetchDocumentsByProject, fetchDocument, searchDocuments
**GitHub Functions:** createGitHubIssue (2-cycle retry, 15s timeout)
**Coordination Functions:** fetchCoordinationList, fetchCoordinationRequest

## [SECTION 7.4] State Management

**React Context (Auth):**
- `AuthStateContext` / `AuthStateProvider` in `lib/authState.tsx`
- State: `authStatus` (authenticated/expired/logged-out), `sessionExpiresAt`
- Session duration: 60 minutes
- Storage: `enceladus:session_last_active` in localStorage

**TanStack React Query:**
- staleTime: 2 min
- gcTime: 30 min
- retry: 2 times (except SessionExpiredError)
- refetchOnWindowFocus: true
- refetchOnReconnect: true

## [SECTION 7.5] Custom Hooks

| Hook | Purpose | Key Behavior |
|------|---------|-------------|
| `useSessionLifecycle()` | Revalidates session on resume | Probes after 10+ min idle; refreshes credentials on 401 |
| `useSessionTimer()` | Polls for session expiry | Checks localStorage every 15s; debounced 30s activity tracking |
| `useProjects()` | Project data | Returns projects array + generatedAt timestamp |
| `useTasks(filters?)` | Task data | Client-side filtering/sorting on feed data |
| `useIssues(filters?)` | Issue data | Same pattern with severity filtering |
| `useFeatures(filters?)` | Feature data | Same pattern |
| `useFeed(filters?, options?)` | Unified feed | Merges tasks+issues+features; single live observer; 3s polling |
| `useDocuments(filters?)` | Document data | S3 feed polling (15s interval); de-dupe by ID |
| `useCoordinationList(filters?)` | Coordination list | 3s polling; stable array refs |
| `useCoordinationDetail(requestId)` | Coordination detail | 3s polling; enabled when ID exists |
| `useProjectReference(projectId)` | Reference markdown | 5-min staleTime; 1 retry |
| `useRecordMutation()` | Tracker mutations | Optimistic close/reopen; rollback on error; 15s invalidation debounce |
| `useInfiniteList(items, pageSize)` | Pagination | IntersectionObserver; 200px root margin; 20 items/page |
| `useFilterState<T>(initial)` | Filter state | toggleArrayFilter, setFilter, clearFilters |

## [SECTION 7.6] Components Reference

**Layout (3):** AppShell, Header, BottomNav

**Cards/Rows (7):** TaskRow, IssueRow, FeatureRow, FeedRow, DocumentRow, CoordinationRow, ProjectCard

**Badges (7):** StatusChip, PriorityBadge, SeverityBadge, GitHubLinkBadge, FreshnessBadge, ActiveSessionBadge, CoordinationFlagBadge, CoordinationStateBadge

**Data Display (5):** HistoryFeed, RelatedItems, ParentRecord, ChildRecords, RecentItemsDisplay

**Interactive (5):** FilterBar, SortPicker, SearchInput, GitHubOverlay, NoteOverlay

**Content (3):** MarkdownRenderer, CodeBlock, LinkedText

**Utility (5):** AnimatedList, ScrollSentinel, LoadingState, ErrorState, EmptyState

**Auth (2):** SessionExpiredOverlay, LoggedOutScreen

## [SECTION 7.7] PWA Configuration

- **Service Worker:** Manual registration in main.tsx; scope `/enceladus/`; `updateViaCache: 'none'`
- **Workbox:** Static asset caching (`*.{js,css,html,ico,png,svg,woff2}`)
- **Offline:** Static assets only; feeds require network auth
- **Manifest:** "Project Status" / "ProjStatus"; standalone display; dark theme (#0f172a)
- **Icons:** 192x192, 512x512, 512x512 maskable

## [SECTION 7.8] Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_FEED_BASE_URL` | `/mobile/v1` | S3 feed CDN path |
| `VITE_MUTATION_BASE_URL` | `/api/v1/tracker` | Tracker mutation API |
| `VITE_API_BASE_URL` | `/api/v1` | General API base |
| `VITE_GITHUB_API_BASE_URL` | `/api/v1/github` | GitHub integration API |

## [SECTION 7.9] Styling

- **Framework:** Tailwind CSS 4.1.18 (utility-first, no custom CSS files)
- **Theme:** Dark mode (slate-900 bg, slate-100 text)
- **Colors:** blue (primary), emerald (completed), rose (closed), amber (in-progress), purple (planned)
- **Priorities:** red (P0), orange (P1), yellow (P2), slate (P3)
- **Responsive:** Mobile-first, no breakpoints (mobile-optimized PWA)

---

# SECTION 8 — MCP SERVER

## [SECTION 8.1] Server Architecture

| Property | Value |
|----------|-------|
| **File** | `tools/enceladus-mcp-server/server.py` (~4400 lines) |
| **Transport** | stdio (MCP protocol) |
| **Language** | Async Python |
| **AWS Access** | Lazy boto3 import; supports provider sessions without AWS CLI |
| **SSL** | Custom CA bundle handling for macOS (falls back to certifi) |

## [SECTION 8.2] MCP Tools Reference

**Project Management (2):** projects_list, projects_get
**Tracker CRUD (7):** tracker_get, tracker_list, tracker_pending_updates, tracker_set, tracker_log, tracker_create, tracker_set_acceptance_evidence
**Documents (6):** documents_get, documents_list, documents_put, documents_patch, documents_search, check_document_policy
**Governance (2):** governance_hash, governance_update
**Deployments (8):** deploy_submit, deploy_state_get, deploy_state_set, deploy_pending_requests, deploy_history, deploy_history_list, deploy_status, deploy_status_get, deploy_trigger
**Coordination (4):** coordination_capabilities, coordination_request_get, dispatch_plan_generate, dispatch_plan_dry_run
**Search (1):** reference_search
**GitHub (3):** github_create_issue, github_projects_list, github_projects_sync
**System (1):** connection_health

## [SECTION 8.3] MCP Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `ENCELADUS_TRACKER_TABLE` | `devops-project-tracker` | Tracker DynamoDB table |
| `ENCELADUS_PROJECTS_TABLE` | `projects` | Projects DynamoDB table |
| `ENCELADUS_DOCUMENTS_TABLE` | `documents` | Documents DynamoDB table |

## [SECTION 8.4] Governance Resolution

- **Live files:** `s3://jreese-net/governance/live/`
- **History:** `s3://jreese-net/governance/history/`
- **URI scheme:** `governance://agents.md` -> `governance/live/agents.md`
- **Hash:** SHA-256 of all loaded governance files (optimistic concurrency for writes)

---
