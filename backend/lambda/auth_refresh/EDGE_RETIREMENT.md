# Lambda@Edge `auth_edge` verifier: retirement decision (DVP-TSK-861)

Decision: KEEP `backend/lambda/auth_edge` for the legacy (v3 / jreese.net) paths now.
`auth_refresh` is the auth edge for ui-v2 (code exchange, cookies, kit refresh contract,
PermissionManifest). Removal is a follow-up, not part of this change.

Why not remove now: the legacy PWA paths still verify the session cookie at the CloudFront
edge, and removing it changes viewer-request behavior for every legacy route (infra change,
out of this task's protected-repo scope).

Follow-up (to be filed by the orchestrator): retire the `auth_edge` viewer-request verifier
once the legacy paths are served only by ui-v2, then drop the CloudFront association.
Exit criteria: no legacy-path traffic for 14 days; kit AUTH-C refresh/manifest tests green on auth_refresh.
