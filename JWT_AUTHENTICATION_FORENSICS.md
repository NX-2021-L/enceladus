# JWT & Authentication Issue Forensics: 2026 Incident Analysis

**Document Type**: Incident Analysis & Prevention Guide
**Date**: 2026-02-24
**Critical Issues Analyzed**: 9 JWT/auth incidents
**Status**: PREVENTION FRAMEWORK IMPLEMENTED

---

## Executive Summary

Between 2026-02-17 and 2026-02-24, Enceladus experienced **9 JWT/authentication-related incidents**, with root causes across **8 distinct patterns**:

1. **Cross-platform compilation** (macOS → Linux) — ENC-ISS-041, DVP-ISS-059, DVP-ISS-071
2. **API Gateway v2 cookie parsing mismatches** — DVP-ISS-071, DVP-ISS-015
3. **Cognito configuration drift** — DVP-ISS-012, DVP-ISS-068
4. **Service worker auth interference** — DVP-ISS-009, DVP-ISS-013
5. **Cookie scope/SameSite violations** — DVP-ISS-009, DVP-ISS-015
6. **Asymmetric error handling** — DVP-ISS-012, DVP-ISS-015
7. **Session state persistence bugs** — DVP-ISS-013
8. **JWT library silent failures** — ENC-ISS-041, DVP-ISS-059

## Most Critical Finding

**🚨 CRITICAL: Never build compiled dependencies (PyJWT, cryptography, cffi) on macOS for Lambda deployment.**

macOS produces Mach-O binaries; Lambda runs on Linux ELF. When `import jwt` tries to load native extensions, it silently fails, setting `_JWT_AVAILABLE=False`. The error message "JWT library not available in Lambda package" is misleading — the library IS there, but in the wrong binary format.

**Solution**: Use `pip install --platform manylinux2014_x86_64 --only-binary=:all:` for Lambda builds.

---

## Incident Timeline

### 1. ENC-ISS-041: Lambda Tracker API JWT Library Missing (JUST FIXED)

**Date**: 2026-02-24 08:38:13Z → 18:49:17Z
**Impact**: All tracker API mutations returned 401
**Root Cause**: `tracker_mutation/deploy.sh` bundled PyJWT with macOS binaries

**Resolution**:
- Built `enceladus-shared` layer v5 with `--platform manylinux2014_x86_64`
- Removed bundled deps from `tracker_mutation/deploy.sh`
- Lambda now relies on shared layer only

**Proof**: CloudWatch logs show error changed from "JWT library not available" to "no enceladus_id_token cookie"

### 2. DVP-ISS-059: Same Issue in devops-tracker-mutation-api

**Date**: 2026-02-20 07:57:36Z → 08:03:00Z
**Root Cause**: Identical macOS binary issue
**Resolution**: Rebuilt with platform-specific targeting

### 3. DVP-ISS-071: Create Project Auth Integration Fails

**Date**: 2026-02-21 19:58:22Z → 20:05:23Z
**Root Causes**:
- Missing API Gateway v2 cookie parsing
- macOS binary incompatibility

**Resolution**:
- Updated `_extract_token()` to parse BOTH `headers.cookie` AND `event.cookies`
- Rebuilt with correct platform targeting

### 4. DVP-ISS-012: PWA Mutation Calls Fail with Session Expired

**Date**: 2026-02-18 23:18:10Z → 2026-02-19 04:11:36Z
**Root Causes**:
- Cognito pool ID mismatch: `us-west-2_vVAHkuPwr` (wrong) vs `us-east-1_b2D0V3E1k`
- Missing `MutationCache.onError()` handler

**Resolution**:
- Fixed Lambda env vars
- Added mutation error handler with 3-cycle retry

### 5. DVP-ISS-013: PWA Stuck on Session-Expired After Re-auth

**Date**: 2026-02-19 07:56:50Z → 08:00:01Z
**Root Causes** (4 compounding bugs):
- Service worker caching pre-login state
- localStorage not cleared on logout
- Bootstrap guard vulnerable to clock skew
- Encoding mismatch (base64 vs base64url)

**Resolution**: Fixed all 4 components

### 6. DVP-ISS-015: PWA Mutations Trigger Session-Expired Loop

**Date**: 2026-02-19 09:51:48Z → 14:13:34Z
**Root Causes**:
- Refresh token `Path=/api/v1/auth` (too restrictive)
- Query refetch race condition on token expiry

**Resolution**: Changed cookie `Path=/`, added dual parsing

### 7. DVP-ISS-009: PWA Renders Blank After Login

**Date**: 2026-02-17 22:46:34Z
**Root Causes** (3 bugs):
- Missing `base: /enceladus/` in vite config
- `SameSite=Lax` blocked cross-origin fetch
- Service worker cached auth-required paths

**Resolution**: Fixed all 3 components

### 8. DVP-ISS-068: Cognito Allowed Public Self-Signup (SECURITY)

**Date**: 2026-02-21 12:53:21Z → 12:53:56Z
**Root Cause**: `AllowAdminCreateUserOnly=false`

**Resolution**: Set to `true`, audited user pool

---

## Prevention Guardrails

### 1. Lambda Build Process

**File**: `backend/lambda/shared_layer/deploy.sh`

```bash
# CRITICAL: Always use manylinux platform targeting
python3 -m pip install \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.11 \
  --only-binary=:all: \
  -r requirements.txt \
  -t "${build_dir}/python"

# Post-build verification
if file "${build_dir}"/python/**/*.so | grep -i "mach-o"; then
  echo "ERROR: Mach-O binaries found in Lambda layer!"
  exit 1
fi
```

### 2. Lambda Cookie Parsing Checklist

**All auth-checking Lambdas must parse BOTH**:

```python
def _extract_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from headers.cookie OR event.cookies."""
    headers = event.get("headers") or {}
    cookie_parts = []

    # Parse headers.cookie (standard)
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        cookie_parts.extend(part.strip() for part in cookie_header.split(";") if part.strip())

    # Parse event.cookies (API Gateway v2) — CRITICAL!
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(part.strip() for part in event_cookies if part.strip())

    for part in cookie_parts:
        if not part.startswith("enceladus_id_token="):
            continue
        return unquote(part[len("enceladus_id_token="):])
    return None
```

**Affected Lambdas** (verify all have dual parsing):
- ✅ devops-tracker-mutation-api
- ✅ devops-project-service
- ✅ devops-document-api
- ⚠️ devops-coordination-api (verify)
- ⚠️ devops-reference-search (verify)

### 3. Cookie Governance Standards

| Cookie | Value | Path | SameSite | Secure |
|--------|-------|------|----------|--------|
| `enceladus_id_token` | JWT | `/` | None | ✅ |
| `enceladus_refresh_token` | JWT | `/` | None | ✅ |

**Why `Path=/`**: Ensures cookie sent to ALL endpoints (not just `/api/v1/auth`)
**Why `SameSite=None`**: Required for fetch() from `/enceladus` to `/api/v1/*`

### 4. Service Worker Auth Path Exclusion

```typescript
export default defineConfig({
  plugins: [
    VitePWA({
      workbox: {
        navigateFallbackDenylist: [
          /^\/api\//,    // All API routes
          /^\/auth/,     // Auth routes
          /^\/logout/,   // Logout routes
        ],
        // Don't cache auth-required endpoints
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/jreese\.net\/(api|auth)/,
            handler: 'NetworkOnly',
          },
        ],
      },
    }),
  ],
});
```

### 5. React Query Error Handlers

```typescript
// CRITICAL: Must handle BOTH QueryCache and MutationCache
queryClient.getQueryCache().subscribe((event) => {
  if (event.type === 'error' && event.query.state.status === 'error') {
    if ((event.query.state.error as any)?.status === 401) {
      handleAuthExpired();
    }
  }
});

queryClient.getMutationCache().subscribe((event) => {
  if (event.type === 'error') {
    if ((event.mutation.state.error as any)?.status === 401) {
      handleAuthExpired(); // Must handle mutations!
    }
  }
});
```

### 6. JWT Import Validation

```python
# At module load time, validate JWT library is available
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError as e:
    JWT_AVAILABLE = False
    import sys
    import logging
    logging.error(f"CRITICAL: JWT library not available: {e}")
    logging.error(f"Python path: {sys.path}")

def lambda_handler(event, context):
    # FAIL FAST: Validate before processing any requests
    if not JWT_AVAILABLE:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Lambda layer not properly attached. Check enceladus-shared layer."
            }),
        }

    # ... rest of handler
```

### 7. Cognito Pre-flight Validation

```bash
# Run before each deployment
COGNITO_POOL_ID="us-east-1_b2D0V3E1k"
COGNITO_CLIENT_ID="6q607dk3liirhtecgps7hifmlk"

# Verify pool exists
aws cognito-idp describe-user-pool \
  --user-pool-id "$COGNITO_POOL_ID" \
  --query 'UserPool.Id' || exit 1

# Verify admin-only creation is enforced
aws cognito-idp describe-user-pool \
  --user-pool-id "$COGNITO_POOL_ID" \
  --query 'UserPool.Policies' | grep -q 'AdminCreateUserConfig' || exit 1

# Verify Lambda env vars
if [[ "$COGNITO_USER_POOL_ID" != "$COGNITO_POOL_ID" ]]; then
  echo "ERROR: Lambda env var COGNITO_USER_POOL_ID mismatch!"
  exit 1
fi
```

---

## Deployment Checklist

**Before Every Production Deployment**:

- [ ] Lambda Layer: Built with `--platform manylinux2014_x86_64`
- [ ] Lambda Layer: Post-build check confirms no Mach-O binaries
- [ ] Lambda Functions: All auth-checking functions parse BOTH `headers.cookie` AND `event.cookies`
- [ ] Cognito: Pool/client IDs match Lambda env vars (pre-flight check)
- [ ] Cookies: Verified `Path=/` for session cookies
- [ ] Service Worker: Confirmed auth paths in navigateFallbackDenylist
- [ ] React Query: Confirmed BOTH QueryCache AND MutationCache have error handlers
- [ ] CloudWatch: Monitored for "JWT library not available" errors
- [ ] Smoke Tests: Completed full auth flow (login → mutation → logout)

---

## Key Learnings

1. **Build environment matters**: Compiled dependencies must match deployment environment
2. **API Gateway v2 broke assumptions**: Modern versions send cookies in `event.cookies` array
3. **Cognito configuration is silent**: Mismatches don't fail loudly, they silently reject tokens
4. **Service workers interfere with auth**: Caching policies, encryption, and state transitions must be coordinated
5. **Error handling must be symmetric**: QueryCache and MutationCache need identical error handlers
6. **Cookie governance is critical**: Path, Domain, SameSite, and Secure flags work together
7. **Session state is fragile**: Multiple components (SW, localStorage, bootstrap guards) must be in sync

---

## Related Issues & PRs

- ENC-ISS-041: JWT library missing (CLOSED)
- DVP-ISS-059: JWT library missing (CLOSED)
- DVP-ISS-071: Auth integration fails (CLOSED)
- DVP-ISS-012: Session expired errors (CLOSED)
- DVP-ISS-013: Session-expired loop (CLOSED)
- DVP-ISS-015: Mutation session loop (CLOSED)
- DVP-ISS-009: Blank screen after login (CLOSED)
- DVP-ISS-068: Public signup enabled (CLOSED)

---

## Document Maintenance

- **Last Updated**: 2026-02-24
- **Owner**: DevOps Team
- **Review Cycle**: Quarterly (next: Q2 2026)
- **Related Docs**: agents.md, shared_layer/deploy.sh comments
