**Project**: intelligence
**Related**: DOC-4B28ED908326, DVP-PLN-007, DVP-FTR-098, INT-FTR-074, DOC-5139680AB636, DOC-5719E0FBDADB, DOC-D08339291746, DOC-F7958D6B7E65, DOC-A5BCD6216666, DOC-7789FF132F90, DOC-FB1738F8E0A2, DOC-256B5F36C6FD, DOC-1931CDD35AAA, DOC-488491DADD6C, INT-TSK-542, INT-TSK-546
**Created**: 2026-10-10
**Author**: enceladus-architect-documentation, from io's platform vision (2026-10-10), io's explicit guidance on notifications, media, and scheduling, and the DVP-PLN-007 Wave A/B/C/D outputs

---

## 0. Executive summary

coach.thepup.io grows from a one-way cum log into a closed two-person platform: one backend, an io surface for logging and future features, and a coach surface that becomes a single installable app with notifications, a 30-day login, and the ability to post. coach gains three new powers -- logging io's cum events when they happen together, posting non-cum updates with media, and booking io's time through a scheduler. Agent sessions gain one narrow power: posting articles about what io is learning, which io approves before coach sees them.

This BRD does not design the platform's plumbing from scratch. The DVP-PLN-007 program (integrated BRD DOC-4B28ED908326, pending io's acceptance) already names coach the reference stack for the shared kit's auth and feed packages, schedules coach's route split in wave E0, and defines the principal model, token custody, feed contract, gate hub, and markdown engine the platform needs. The platform adopts those contracts as its foundation (section 5.0) and adds only what is coach-specific: the post model, the author/subject distinction, the duplicate rule, the agent article tool, notifications, the scheduler, and the media seams. [INF: that the kit lands on the convergence program's schedule; the fallback is stated in section 9]

io's three explicit guidances are locked: notifications and calendar events carry no content by default but are built so io can later define per-feature cryptic templates and coach can opt into them (section 5.6, 5.8); video and resumable uploads stay on the back burner with seams designed in now (section 5.7).

## 1. Objectives

```yaml
O-1: coach uses one installed app for the timeline, scheduler, and articles, with one login and one notification channel
O-2: coach re-authenticates at most every 30 days once installed, with no reduction in the security posture established by INT-PLN-022 and the kit's token-custody rule
O-3: coach can log a cum event that happened with him, and it renders celebrated (io mark) and counts correctly, with no duplicates when both principals log it
O-4: both principals can post non-cum updates with photos, audio, text, and file attachments; the cum-event figures ignore them
O-5: coach receives content-free notifications and badges for new activity, with a forward path to opt-in cryptic detail
O-6: io can publish availability and coach can book it, producing a discreet Google Calendar event for both
O-7: agent sessions can post articles about io's learning through a write-only io-graph tool; io approves each before coach sees it; agents can never read the cockpit
O-8: the platform is built on the shared kit's contracts so improvements propagate from the convergence program rather than being re-implemented here
```

## 2. Tenets

- **A governed handler is the only place an action exists** [DOC: DOC-4B28ED908326 s3.1]. coach's UI, io's UI, the io-graph article tool, and any future MCP surface all call the same handlers with the same authorization, dry run, and audit.
- **The cum log stays the cum log.** New post types never change `days_since_last`, `count_30d`, or the strip. Those count cum events only.
- **One tap stays one tap.** No new post type, field, or surface adds a step to io's logging path.
- **Content-free by default, cryptic by choice.** Anything that leaves the app -- a push notification, a badge, a calendar invite -- carries nothing readable until io defines a template and coach opts in.
- **Agents write, never read.** The cockpit's data is never readable by an agent principal. The article tool is a one-way door.
- **Nothing io has not approved reaches coach from an agent.**
- **Serve small, keep originals private** [DOC: INT-TSK-542]. Every media type follows the same rendition discipline photos already do.
- **Adopt the kit, do not fork it.** Where the convergence program defines a contract, coach consumes it; coach is the reference consumer for auth and feed [DOC: DOC-4B28ED908326 s6].

## 3. Scope

**In scope:** the post model and author/subject distinction; coach-logged with-coach cum events with the duplicate rule; updates with photos, audio, text, and attachments; the single installable coach app; 30-day login on the kit's custody model; notifications and badges, content-free with the opt-in seam; the scheduler and Google Calendar integration; the agent article tool with approval; article rendering through the kit's markdown package; media seams for future video and resumable upload.

**Out of scope, with seams designed:** video upload, playback, and transcoding; resumable multipart upload; cryptic notification and calendar templates (seam only); passkeys and step-up auth (convergence stage 2, DOC-4B28ED908326 F-06); coach search; any agent read access to the cockpit, ever.

**Explicitly not a goal:** generality. This is a platform for two people and io's agents. Multi-tenant concerns do not apply.

## 4. Current state (as built)

```yaml
coach_today:
  surfaces: [write page for io, reader timeline for coach]
  auth: shared pool us-west-2_y6bHKpNZN; groups coach-io, coach-reader, iograph-owner; per-route group table with a generated boundary regression (INT-TSK-414/415)
  feed: 14-day initial window, 7-day batches, derived figures on every response (INT-PLN-028); realtime via DynamoDB Streams -> publisher -> AppSync Events, signals only (INT-PLN-023)
  content: cum events with emoji, note, photos; threads with comments and photos; one reaction per principal per target (INT-PLN-025, 026)
  media: presigned PUT to pending/, commit to media/, M7 renditions (display ~1080px, thumb, GIF poster), immutable /media/* caching, no original ever fetched by the feed (INT-ISS-108)
  in_flight: INT-TSK-542 large-photo pipeline; INT-TSK-546 safe area + io preview toggle; INT-FTR-074 with_coach (BRD DOC-5139680AB636)
  convergence_role: reference consumer for @io-kit/auth and @io-kit/feed; route split scheduled E0; fronts no MCP surface today [DOC: DOC-4B28ED908326 s3.1, s6]
```

## 5. Design

### 5.0 Foundation inherited from the convergence program

These are adopted, not re-decided. Each is a locked decision in DOC-4B28ED908326 s3.2 unless tagged otherwise.

```yaml
inherited:
  principal: "Principal {type: human|agent|service, sub, issuer, groups, agentId?, onBehalfOf?, authTime, amr?} [DOC: DOC-4B28ED908326 s5.1]"
  authorization: "L-06 server-only authorize(principal, action, mode); policy table action -> {dry_run: [groups], execute: [groups]}; coach's route_group_map.json becomes the policy table"
  token_custody: "L-07 memory + HttpOnly cookie minted by a per-stack auth edge at /auth/*; nothing in localStorage; refresh failure -> 401 AUTH_REFRESH_FAILED"
  realtime: "L-09 AppSync Events carries signals only; data from governed page/since handlers"
  feed: "L-10 signed opaque cursors; FeedSource {page, since, subscribe}; PageResponse with schema feed.vN [DOC: DOC-4B28ED908326 s5.5]"
  markdown: "L-11 unified/react-markdown + docstore semantics; rehype-sanitize; rawHtml never allowed"
  gates: "GateCard {kind, family, proposedCalls, risk, expiresAt, onExpire, etag}; DecideRequest with two-layer If-Match; hash-chained decision log [DOC: DOC-4B28ED908326 s5.8]"
  shell: "registry-derived nav; one registry, three renderers by breakpoint; PWA via vite-plugin-pwa [DOC: DOC-4B28ED908326 s5.2]"
  capability_manifest: "L-03 caps.json per MCP surface, generated from the handler registry; when coach gains a surface it joins the parity check [DOC: DOC-4B28ED908326 s7]"
```

What this buys the platform: the agent article author is `Principal {type: 'agent', agentId, onBehalfOf: io}` with its own policy rows; io's approval of an article is a gate card whose cleared call is `publish`; the 30-day login is the auth edge's HttpOnly refresh cookie with a 30-day Cognito refresh lifetime; the multi-section coach app is the shell's registry-derived nav over coach's split routes. None of these is new machinery.

### 5.1 The post model

The core noun changes from cum event to post.

```yaml
post:
  id: ULID, server-minted, immutable
  type: cum_event | update | article | booking
  author: Principal sub (io, coach, or an agent principal acting onBehalfOf io)
  subject: the person the post is about; io for every cum_event, otherwise same as author
  created_at: server instant
  event_at: for cum_event only; the time it happened (one-tap = now, backfill = supplied)
  body: note (<=100 for cum_event, per-type cap otherwise) or article markdown
  with_coach: boolean, cum_event only (INT-FTR-074)
  confirmed_by: optional sub, cum_event only (section 5.2)
  attachments: [] of {id, kind: image|audio|file|video(reserved), key, renditions{}, w, h, duration, bytes, content_type}
  visibility: published | draft | withdrawn
  thread, reactions: unchanged from INT-PLN-025
storage: "same partition and ULID sort key as today; type is an attribute, not a key change, so existing items are cum_event posts with no migration [INF]"
derived_figures: "days_since_last, count_30d, recent_events read only type == cum_event (R-1); every existing query gains that predicate"
```

The timeline renders all types; "current state" (the view coach has today) is the filter `type == cum_event`. Filters are a view over post types, never separate feeds.

### 5.2 Coach logs a with-coach cum event

Authorization widens by one row: `coach-reader` may create a cum_event only with `with_coach = true` and `subject = io`. Any other cum_event create from coach-reader is 403. This is a D-1 amendment and is recorded on INT-PLN-022 when approved.

**The duplicate rule.** When it happens together, both may reach for their phones.

```yaml
duplicate_rule:
  window: "a with_coach cum_event whose event_at is within 30 minutes of an existing with_coach cum_event by the other principal"
  on_create_inside_window: "the server does not create a second post; it returns the existing post with a 'confirm' affordance"
  confirm: "PATCH /posts/{id}/confirm sets confirmed_by to the caller; the post renders as logged by one and confirmed by the other"
  counts: "one event, counted once"
  override: "io only, by logging via backfill with an explicit event_at outside the window; coach cannot override"
  rationale: "a missed duplicate corrupts the count; a false merge can be split by io; so the rule errs toward merging [INF: 30-minute window is a judgment, io may change it]"
```

**The celebration.** A coach-logged or coach-confirmed with-coach event carries the io mark (INT-FTR-074 D-11) and a distinct treatment on the rail, defined with Claude Design as a design task, not specified here.

### 5.3 Updates with media

`type = update`, either principal. Body text plus attachments. Attachment kinds ship in this order, each on the pipeline photos already use (presign to pending/, commit to media/, M7 renditions, serve renditions only):

```yaml
attachment_kinds:
  image: as today
  audio: "upload original (cap 25MB per INT-TSK-542 strategy); M7 produces an AAC/Opus rendition and a duration; served rendition only; played inline with the native audio element"
  file: "PDF and documents; never rendered inline; served with Content-Disposition: attachment and a sniff-safe content type; no preview rendition beyond an icon and the file name; cap 25MB"
  video: "RESERVED. kind value and attachment shape exist; the write path rejects it with a readable message until the seams in 5.7 are built"
text: "markdown through @io-kit/md with rehype-sanitize (L-11); rawHtml never allowed"
limits: "4 attachments per post (R-13 carried forward); per-kind caps as above"
```

### 5.4 The coach app: one installable surface

```yaml
coach_app:
  install: "one PWA; sections (timeline, scheduler, articles) are routes inside it; never separate installables -- iOS isolates storage per home-screen app, so separate installs would mean separate logins and push subscriptions [DOC: DOC-D08339291746 s4]"
  shell: "@io-kit/shell registry-derived nav over coach's split routes (E0 Q-10); bottom bar on phone"
  safe_area: INT-TSK-546
  login: "@io-kit/auth cognitoAdapter + coach auth edge; Cognito refresh token lifetime 30 days with rotation on the Essentials tier; refresh held in the auth edge's HttpOnly cookie, never in the page [DOC: DOC-D484594E8479 s4; DOC-4B28ED908326 L-07]"
  reauth: "at the 30-day boundary coach signs in again via managed login; passkeys (one-tap Face ID) are convergence stage 2 (F-06) and are the planned path to make that painless"
  io_surface: "the write page remains io's app; it gains the preview toggle (INT-TSK-546) and, later, the scheduler's availability editor and the article approval inbox"
```

### 5.5 Notifications and badges

io's guidance: content-free now; future-proof per-feature cryptic templates and a coach toggle.

```yaml
notifications:
  transport: "Declarative Web Push for the installed iOS app (iOS 18.4+), direct VAPID from Lambda; Android Chrome standard push [DOC: DOC-D08339291746 s3]"
  subscriptions: "one per installed app, stored keyed by principal; 404/410 from the push service deletes it"
  badge: "app_badge in the declarative payload; count of unseen activity; cleared on open"
  trigger: "the same stream signals the realtime publisher already emits (INT-FTR-064); a new post, comment, or reaction by the other principal"
  payload_v1: "title and body are fixed, content-free strings per feature, e.g. 'the cockpit' / 'something new'; no names, no note text, no image, no post type"
  seam_for_cryptic_detail:
    template_registry: "server-side map feature -> {level: 0|1, template}; level 0 is the content-free string, level 1 is io's cryptic line (e.g. 'the pup has posted an event' / 'an update' / 'an article')"
    coach_preference: "notification_detail: 0|1 stored on coach's principal record, editable from the coach app; default 0"
    io_authoring: "io edits templates from the write page; a template never interpolates post content, only the feature name and fixed phrases"
    rule: "the payload renderer picks min(coach_preference, template_level); content never enters a payload at any level"
  lock_screen: "the payload is what the lock screen shows; this is why content is excluded structurally, not by convention"
```

### 5.6 The scheduler

```yaml
scheduler:
  availability: "io publishes slots (start, end, timezone-safe instants) from the write page; stored as posts of type booking with state open"
  booking: "coach books an open slot; the handler uses a conditional write (state == open) so two taps cannot double-book; state -> booked"
  calendar: "on booking, a Lambda creates one Google Calendar event from ai@thepup.io inviting coach's email and io@thepup.io, with the event id stored on the post for update/cancel"
  google_auth: "service account with domain-wide delegation to ai@thepup.io, or OAuth for that account -- decided in the contract task; credentials in Secrets Manager; the Calendar scope only"
  discretion: "io's guidance, same approach as notifications: level 0 default -- title and description are fixed content-free strings; a template registry and coach toggle allow a level-1 cryptic title later; a calendar event is visible to anyone who sees coach's calendar and to Google, so content is excluded structurally"
  cancel_reschedule: "either principal may cancel; the event is deleted; the slot returns to open or is withdrawn by io"
  timezone: "slots are instants; the UI renders in each viewer's local time, the same convention as the feed's day boundaries"
```

### 5.7 Media seams for the future

io's guidance: back burner, but design for it.

```yaml
seams:
  attachment_kind: "video is a reserved enum value now, so the data model needs no migration later"
  uploader_interface: "the client upload engine exposes put(file) behind one interface; a multipart implementation can replace the single PUT without changing callers (resumable upload per INT-TSK-542 telemetry decision)"
  rendition_pipeline: "M7 dispatches by kind; a video branch (MediaConvert -> HLS + poster) plugs in as a new branch, not a new pipeline"
  serve_rule: "originals are never served for any kind; the feed requests renditions only (INT-TSK-540 invariant generalized)"
  caps: "per-kind caps live in one server-side table so raising video's cap is a config change"
  watermark: "INT-FTR-068's per-viewer pattern applies to image renditions; video and audio are explicitly excluded until designed"
```

### 5.8 Articles: the agent author

```yaml
articles:
  principal: "Principal {type: 'agent', agentId: <session>, onBehalfOf: io} issued to agent sessions through io-graph; it is a distinct principal, never io's own"
  tool: "io-graph exposes one new action, cockpit.article.draft, with a per-action schema in caps.json (L-03); it is write-only: it creates a post of type article with visibility draft and returns the id; there is no cockpit read action for agents, and the policy table has no read row for agent principals"
  content: "markdown; rendered by @io-kit/md with rehype-sanitize (L-11); the article view is the kit's renderer, converged with think.thepup.io's timeline and Enceladus docs, not a third renderer"
  approval: "a draft creates a gate card (kind: acceptance, family: decision, risk: low, proposedCalls: [publish], expiresAt: 7d, onExpire: deny) in io's inbox; io reads the rendered draft and clears it; the cleared call publishes; coach sees only published articles [DOC: DOC-4B28ED908326 s5.8 contract]"
  edits: "io may edit a draft before approval; an agent may replace its own draft; neither may edit after publish -- withdraw and republish"
  attribution: "published articles show 'written for io by an agent' with the agent id, and io's approval timestamp"
  topics: "io asks an agent session to summarize what he has been learning and building into the think.thepup.io corpus; the agent reads io-graph as it does today and writes to the cockpit only through this tool"
```

### 5.9 Authorization table (delta)

```yaml
policy_delta:
  posts.cum_event.create: {execute: [coach-io, "coach-reader (with_coach=true, subject=io only)"]}
  posts.cum_event.confirm: {execute: [coach-io, coach-reader]}
  posts.update.create: {execute: [coach-io, coach-reader]}
  posts.article.draft: {execute: [agent principals onBehalfOf io]}
  posts.article.publish: {execute: [coach-io], via: gate clear only}
  scheduler.slot.create: {execute: [coach-io]}
  scheduler.slot.book: {execute: [coach-reader]}
  scheduler.booking.cancel: {execute: [coach-io, coach-reader]}
  notifications.preference: {execute: [self]}
  cockpit.read: {execute: [coach-io, coach-reader]; never agent}
boundary_regression: "every row above becomes rows in the route-table data file so INT-TSK-415's generated regression covers it, including the agent-cannot-read case as a hard assertion"
```

## 6. Requirements

```yaml
R-1: derived figures (days_since_last, count_30d, recent_events) count posts of type cum_event only
R-2: a coach-reader cum_event create is accepted only with with_coach=true and subject=io; otherwise 403
R-3: the duplicate rule merges a with_coach event logged by both principals within the window into one counted event
R-4: no new post type, field, or surface adds a step to io's one-tap path; R-1 timing test unchanged
R-5: coach's app is one installable PWA with one login and one push subscription
R-6: the refresh credential lives only in the auth edge's HttpOnly cookie; nothing in localStorage; 30-day lifetime with rotation
R-7: push payloads and badges contain no post content at any detail level; detail level is min(coach preference, template level)
R-8: calendar events contain no post content at level 0; the same template and toggle seam as notifications
R-9: agent principals have no read path to the cockpit; the policy table has no agent read row and the boundary regression asserts 403
R-10: an article is visible to coach only after io clears its gate card; expired cards deny
R-11: originals of every attachment kind are never served; renditions only
R-12: video is a reserved kind rejected on write until its seams are built
R-13: booking uses a conditional write; a slot cannot be booked twice
R-14: articles render through @io-kit/md with rawHtml disallowed
R-15: every new handler is registered in coach's governed handler registry so caps.json can be generated when coach joins the parity check
```

## 7. Constraints and dependencies

```yaml
convergence_program:
  dependency: "@io-kit/auth and @io-kit/feed 0.x, with coach as reference consumer, scheduled E1; coach route split E0 [DOC: DOC-4B28ED908326 s8]"
  gate: "DOC-4B28ED908326 is pending io's acceptance (DVP-TSK-828 AC5); this BRD assumes acceptance"
  fallback: "if the kit slips, phase 0 implements the same contracts locally in coach (principal shape, policy table, auth edge cookie) so that adopting the kit later is a swap, not a rewrite [INF]"
in_flight:
  - INT-TSK-542 large-photo pipeline: audio and file attachments reuse its cap table and S3-enforced sizes
  - INT-TSK-546: safe area and preview toggle land before the shell migration
  - INT-FTR-074 with_coach: foundation for coach-logged events; ships first
cognito: "shared pool stays; Essentials tier already live; refresh lifetime set to 30 days on the coach app client; rotation enabled"
google: "ai@thepup.io must exist as a Workspace account; Calendar API enabled; credentials in Secrets Manager"
push: "iOS 18.4+ for Declarative Web Push; older iOS falls back to a service-worker push handler or no push"
```

## 8. Recommended feature records

All in project intelligence unless noted. Proposals; the coordination lead mints ids.

```yaml
proposed_features:
  - key: P-A
    title: "Platform foundation: post model, author/subject, cum-event-only figures, handler registry"
    intent: "everything else depends on this; zero visible change"
    ac_sketch: ["type attribute on every post; existing items read as cum_event with no migration", "R-1 predicate on every derived figure", "handler registry with action ids matching the policy table", "boundary regression regenerated"]
  - key: P-B
    title: "coach app shell and 30-day login: route split, @io-kit/shell nav, @io-kit/auth edge, Cognito 30-day refresh"
    depends_on: [P-A, INT-TSK-546, "convergence E0 route split / E1 auth (or the local fallback)"]
  - key: P-C
    title: "coach as author: with-coach cum events with the duplicate rule, updates with photos, audio, and attachments"
    depends_on: [P-A, INT-FTR-074, INT-TSK-542]
    ac_sketch: ["R-2, R-3, R-11, R-12", "celebration treatment from a Claude Design pass"]
  - key: P-D
    title: "Notifications and badges: Declarative Web Push, content-free payloads, template and preference seam"
    depends_on: [P-B]
    ac_sketch: ["R-7", "opt-in template registry present but only level 0 shipped"]
  - key: P-E
    title: "Scheduler: availability, conditional booking, discreet Google Calendar events"
    depends_on: [P-B]
    ac_sketch: ["R-8, R-13"]
  - key: P-F
    title: "Articles: io-graph write-only draft tool, agent principal, gate-card approval, @io-kit/md rendering"
    depends_on: [P-A, P-B, "convergence gates hub (E4) or a coach-local gate list as fallback"]
    ac_sketch: ["R-9, R-10, R-14"]
    placement_note: "the io-graph tool is an intelligence backend change; the gate card may be an ENC record if the hub is shared [INF]"
  - key: P-G
    title: "Media seams: video reserved kind, uploader interface, M7 kind dispatch, per-kind cap table"
    depends_on: [P-C]
    note: "seams only; no video"
```

## 9. Plan outline (phases in dependency order)

```yaml
phase_0_foundation:
  objective: [P-A]
  tasks:
    - contract: post model, policy delta, duplicate rule parameters, handler registry layout; references the kit contracts verbatim
    - backend: type attribute + R-1 predicate on figures; registry; boundary regression regen
    - verify: existing coach behavior byte-identical for coach-reader; figures unchanged on a 30-day fixture
phase_1_surface_and_login:
  objective: [P-B]
  depends_on: [phase_0, INT-TSK-546]
  tasks:
    - route split (E0 Q-10) and shell nav with three sections
    - auth edge + cognitoAdapter; refresh lifetime 30d with rotation on the coach client; localStorage empty of tokens
    - verify: coach installs once, stays signed in across 7 days of use, re-auths at the boundary
phase_2_coach_as_author:
  objective: [P-C, P-G]
  depends_on: [phase_0, INT-FTR-074, INT-TSK-542]
  tasks:
    - coach-reader cum_event create (with_coach only) + confirm + duplicate rule
    - update post type; audio and file kinds on the rendition pipeline; video reserved
    - celebration treatment (design task) and rail rendering
    - verify: both log the same event -> one counted; coach posts an update with an audio clip; figures unchanged
phase_3_reach:
  objective: [P-D, P-E]
  depends_on: [phase_1]
  parallel: true
  tasks:
    - push subscriptions, VAPID, declarative payloads, badge; template registry at level 0; coach preference stored
    - slots, conditional booking, Google Calendar event create/cancel from ai@thepup.io; level-0 titles
    - verify: lock-screen payload shows no content; a double tap cannot double-book; invite lands on both calendars
phase_4_articles:
  objective: [P-F]
  depends_on: [phase_1, "gates hub or local fallback"]
  tasks:
    - io-graph cockpit.article.draft action with caps.json schema; agent principal rows; agent-read 403 assertion
    - gate card on draft; approval inbox on io's write page; publish on clear
    - article renderer via @io-kit/md
    - verify: an agent drafts from io-graph; io approves; coach sees it; an agent read attempt is 403 in the regression
phase_5_deferred:
  items: [video + resumable upload, cryptic templates level 1, passkeys]
  gate: "INT-TSK-542 telemetry for uploads; io's call for templates; convergence stage 2 for passkeys"
```

Critical path: phase 0 -> phase 1 -> phase 4. Phases 2 and 3 run alongside once their prerequisites land.

## 10. Risks

- **Kit timing.** Coach is the kit's reference consumer, so the kit's E1 schedule is coach's phase 1. If it slips, phase 1 implements the contracts locally and swaps later; the contracts are already written in DOC-4B28ED908326, so the swap is mechanical.
- **A merged event that was two.** The duplicate rule can merge two genuinely separate with-coach events inside the window. io can split by backfilling with an explicit time; the window is a parameter.
- **Push privacy.** Mitigated structurally: content never enters a payload at any level. The only residual is the app's name on the lock screen.
- **Calendar leakage.** A level-0 title still shows a meeting exists. Accepted by io's guidance; level 1 is opt-in.
- **Agent misuse of the article tool.** The tool is write-only and draft-only; the worst case is an unwanted draft in io's inbox, which expires in 7 days. The regression asserts no read path exists.
- **Coach's phone and iOS versions.** Declarative Web Push needs iOS 18.4+; below that, a service-worker push handler or nothing. Verified on his device before phase 3 closes.

## 11. Inference register

```yaml
inferred:
  - the convergence kit lands on its E0/E1 schedule; fallback in section 7
  - the type attribute can be added with no key change and no migration (coach's partition and sort key are unchanged)
  - 30 minutes is the right duplicate window; io may change it
  - a gate card is the right approval mechanism for articles; if the gates hub is not shared with intelligence, a coach-local draft list serves the same purpose
  - domain-wide delegation vs OAuth for ai@thepup.io is decided in the scheduler contract task
  - coach's phone runs iOS 18.4 or later
evidenced:
  - every inherited contract in section 5.0 (DOC-4B28ED908326 s3.2, s5)
  - coach's reference-consumer role and E0 route split (DOC-4B28ED908326 s6, s8, Q-10)
  - iOS storage isolation per installed app, Declarative Web Push, Cognito 30-day refresh with rotation (DOC-D484594E8479, DOC-D08339291746)
  - the current media pipeline and its invariants (INT-TSK-538/539/540, INT-TSK-542)
  - io's guidance on notifications, media, and scheduling (2026-10-10)
```



---

## 12. Amendment 1 (2026-10-10) -- DOC-4B28ED908326 accepted at v16 with rulings L-15 and L-16

io accepted the integrated BRD on 2026-10-10 with two amendments. This section records their effect; where it conflicts with sections 5, 7, or 9 above, this section governs.

```yaml
acceptance:
  status: "DOC-4B28ED908326 v16, maturity compliant; io's rulings A1 (L-15) and A2 (L-16) applied; everything else accepted as written [DOC: DOC-4B28ED908326 s0, s10]"
  effect_on_section_7: "the 'gate: pending io's acceptance' line is satisfied; the local-contract fallback remains available only as insurance against kit slippage, not against non-acceptance"

L-16_stack_order:
  ruling: "coach.thepup.io first, as the modernization prelude to this BRD; then think, enceladus, vagamod [DOC: DOC-4B28ED908326 L-16]"
  coach_row_now:
    - {seq: 0, area: parity, wave: E0, prerequisite: "@io-kit/parity report-only job green at 0/0; route split"}
    - {seq: 1, area: auth, wave: E1}
    - {seq: 2, area: feed, wave: E1}
    - {seq: 3, area: shell, wave: E1}
    - {seq: 4, area: md, wave: E1, note: "pulled from E3 into E1 by L-16"}
    - {seq: 5, area: "search, schema_form, gates, recipes", wave: conditional, prerequisite: "coach fronts an MCP surface"}
  effect_on_phase_1: "phase 1 (P-B) IS coach's E0/E1 prelude; it is no longer a dependency on another stack's schedule. Its scope grows by one item: the @io-kit/parity report-only job, green at 0/0, so that the first surface this BRD adds is caught on day one [DOC: DOC-4B28ED908326 s6 O-6, s7 rank 0]"
  effect_on_phase_4: "@io-kit/md arrives in coach's E1, not E3; P-F's renderer dependency is satisfied by phase 1. Phase 4's remaining external dependency is the gates hub (E4) or the coach-local fallback"
  effect_on_R-15: "R-15 is now mandatory from phase 1: when P-F adds cockpit.article.draft (an io-graph action) and when coach gains any MCP surface, the parity job that L-16 puts in place catches it. Any surface this BRD adds joins the parity check on the day it ships"
  effect_on_critical_path: "unchanged (phase 0 -> 1 -> 4), but phase 1's content is now fixed by the integrated BRD rather than proposed here"

L-15_keycloak:
  ruling: "ai.vagamod.io keeps Keycloak; @io-kit/auth targets Keycloak parity including realm-per-tenant multi-tenancy; Principal gains optional tenant [DOC: DOC-4B28ED908326 L-15, s5.1]"
  effect_on_coach: "none functionally -- the cognitoAdapter leaves Principal.tenant unset. The platform's policy table and PermissionManifest should be written tenant-aware only in shape (a nullable tenant key), so a future kit release that keys policy per tenant does not force a coach change [INF]"

section_5_0_correction:
  inherited_capability_manifest: "unchanged in substance; add: coach's parity job exists from E0 (L-16), so 'when coach gains a surface it joins the parity check' becomes 'coach is already in the parity check at 0/0 and any added surface is counted immediately'"
```

No objective, requirement, feature proposal, or risk in sections 1-10 is withdrawn by this amendment. The two documents now reference each other: DOC-4B28ED908326 names this BRD as the reason coach goes first, and this BRD inherits its contracts.



---

## 13. Amendment 2 (2026-10-10) -- per-post notification squash

io's addition: each principal controls notification generation at the post level, and receipt at the feature level.

```yaml
squash:
  definition: "every action that can generate a notification (one-tap and backfill cum_event, update, comment, reaction, booking, article publish, with-coach confirm) accepts an optional squash_notification boolean, default false"
  effect: "when true, the push sender (5.5) emits nothing for that action to the other principal, regardless of the recipient's feature-level preference; the badge count is not incremented for it"
  scope: "device notifications and badge only. The in-app new-activity banner and realtime signal are unaffected -- squash is about what leaves the app, not what is visible inside it"
  storage: "persisted on the post or comment as notify_squashed: true (absent means false) for audit; never rendered to the recipient"
  composer: "a small resting-state toggle on every composer, unchecked by default, reset after each post; on io's one-tap path it is optional and adds no step (same discipline as the with_coach checkbox)"
  two_axes:
    generation: "the poster, per post, via squash"
    receipt: "the recipient, per feature, via notification_detail and the enable/disable control (5.5)"
    rule: "a notification is sent only if the poster did not squash it AND the recipient has the feature enabled; the rendered detail is still min(recipient preference, template level)"
```

Records amended: INT-FTR-078 (acceptance criteria), INT-TSK-547 (contract), INT-TSK-563 (composers), INT-TSK-565 (sender). R-7 unchanged; new **R-16**: a squashed action never produces a push or badge increment, proven by a test for each action type.


---

## 14. Amendment 3 (2026-10-10) -- scheduler groomed: availability windows, partial bookings, booking records, invitation toggle
<!-- enc:block:01M4K82BSNZP3D6V5W1C0TAN1B -->

io groomed the scheduler during INT-PLN-029 delivery (coordinator ENC-SES-0IZ, enceladus-architect). Where this conflicts with section 5.6, this section governs. Catalog DOC-E34DCB005324, ruling R18.

```yaml
availability:
  who: io only
  routes: ["PWA write page scheduler section", "io-graph cockpit.availability.create | list | withdraw (io's own MCP session; principal io via the iograph_mcp direct-invoke path from INT-TSK-567, human principal, availability actions only)"]
  input: "date + begin time + end time in io's local time; the client converts to UTC instants (PWA: device tz; io-graph tool: tz parameter, default America/Los_Angeles); the server stores instants only"
  record: "type availability {start, end, state open|withdrawn, version}"
  calendar: "a TRANSPARENT event (shows as free) on ai@thepup.io, level-0 content-free title, no attendees"
booking:
  who: coach (coach-reader)
  scope: "all or part of one availability window: [start, end) inside the window, 15-minute grid, minimum 30 minutes, no overlap with an active booking in that window"
  record: "type booking -- the SOURCE OF TRUTH -- {availability_sk, start, end, booked_by, state booked|cancelled, invitees (snapshot at booking), calendar_event_id, calendar_sync pending|ok|failed}"
  concurrency: "TransactWriteItems: Put booking + Update availability SET version = version + 1 with condition version = :read; overlap checked against the bookings read at that version; a lost race returns 409 SLOT_TAKEN (R-13 holds)"
  calendar: "an OPAQUE (busy) event on ai@thepup.io; attendees: jfosterreese@gmail.com always, plus coach's Cognito email claim when coach's booking_invitations preference is on (default on); sendUpdates=all; level-0 content-free title"
  cancel: "either principal; booking -> cancelled; event deleted with sendUpdates=all; the time returns to the window"
projection:
  rule: "the calendar is a PROJECTION of availability/booking records, never part of the write"
  mechanism: "coach_calendar_projector Lambda on the coach stream creates/deletes events idempotently (deterministic Google event ids derived from the record sk) and writes back calendar_event_id + calendar_sync"
  failure: "a Google failure never fails a booking; pending items retry via stream retry and a coach-io POST /scheduler/resync; until the INT-TSK-552 credential exists, records are created and calendar_sync stays pending"
coach_views:
  available: "GET /availability: free intervals (windows minus active bookings), future only, ascending by start, infinite scroll via feed.v1 signed cursors"
  mine: "GET /bookings: coach sees his own active bookings ascending; io sees all"
settings: "coach's settings page gains 'Event invitations for bookings' (default ON), stored as booking_invitations on the per-principal preferences item (GET/PUT /notifications/preferences). It governs only whether coach is an attendee; io's invite and the ai@thepup.io events are unaffected"
config: "io's invite address is env IO_INVITE_EMAIL = jfosterreese@gmail.com (not hard-coded); io@thepup.io is no longer invited"
supersedes: "section 5.6 availability/booking/calendar lines, and the v1 implementation in INT-TSK-566 (whole-slot booking, claim -> Calendar -> revert)"
juice: "partial booking costs one version-guarded transaction and an interval subtraction over a handful of windows, and removes io hand-chunking slots; the projector takes Google off the booking's critical path and makes INT-TSK-552 non-blocking for the data model"
records:
  - "INT-TSK-566 superseded by INT-TSK-578 (scheduler v2 backend + calendar projector); 566 leaves the plan per io's orphan rule"
  - "new: io-graph cockpit.availability tools task"
  - "INT-TSK-570 (scheduler UI), INT-FTR-079, gates INT-TSK-568 and INT-TSK-573 acceptance criteria regroomed"
```

### 15. Amendment 4 (2026-10-10) -- coach-proposed booking times (INT-FTR-082)

io's direction:
- Besides booking io's pre-set availability slots, coach can **propose** a time.
- io then **accepts the whole time**, **accepts part of it** (adjusted inside the proposed range), or **declines**.
- **Slot bookings stay instant:** they are confirmed and calendar invites go to both immediately.
- **Proposals send nothing to the calendar until io approves.**

Contract:
- **Storage:** proposals live at `pk SCHED#proposal`, `sk <start>#<ULID>`. States are pending, accepted, declined, withdrawn and expired (expired is computed for a pending proposal whose start has passed). The proposal stores coach's invitee snapshot. Proposals are never projected to the calendar.
- **Accepting:** creates an ordinary booking (`pk SCHED#booking`, origin proposal, booked_by the proposer). The booking and the proposal update are written in **one** DynamoDB transaction, so nothing is double-booked (409 SLOT_TAKEN). The booking then projects like any slot booking.
- **Routes:** all are human-only, and agents get 403.
  - `POST /proposals`: coach.
  - `GET /proposals`: io sees all, coach sees his own.
  - `POST /proposals/{id}/accept` with an optional `{start, end}`: io.
  - `POST /proposals/{id}/decline`: io.
  - `POST /proposals/{id}/withdraw`: coach, own proposals.
- **Limits:** 15-minute grid, 30 minutes to 12 hours, a note of up to 280 characters, and at most 5 pending per coach.
- **Push:** content-free, as today. Propose notifies io; accept and decline notify coach.