# Status color

Color on a card answers one question at a time. Lifecycle status has nine roles; each role has one color treatment, one glyph and one meaning, for every record kind. Priority, severity, checkout, type and taxonomy each have their own channel and never touch the status pill.

The data is `status-map.json`: record kind and status string in, role out, and for each role the tokens for text, border, fill and glyph. `components/StatusOverview` shows all of it.

## The roles

| Role | Tells the operator | Glyph | Emphasis | Border |
|---|---|---|---|---|
| `todo` | Not started. Ready or queued; nobody is working on it. | ring | outline | solid |
| `active` | Moving. An agent or the pipeline is working on it; nothing is needed from the operator. | play | tint | solid |
| `caution` | Off the forward path: sent back, deferred or gone stale. No action is required yet, but it will not finish on its own momentum. | return | tint | solid |
| `waiting` | Waiting on a human decision or gate. The operator is the next actor. | pause | strong | solid |
| `done` | Ended well. The goal was reached and nothing more is needed. | check | tint | solid |
| `live` | In service. A steady good state with no end expected (a live feature, an active project). | disc | outline | solid |
| `failed` | Ended badly or is broken now: failed, denied, dead-lettered, objectives not met. | cross | strong | solid |
| `retired` | Ended without a verdict: superseded, cancelled, deprecated, archived, expired. | dash | outline | dashed |
| `unknown` | A status this map does not contain. Shown verbatim so it is readable, and marked so it is noticed. | diamond | outline | dotted |

Use the role, never a hue. `status-<role>-text`, `-border`, `-fill` and `-dot` are the only tokens a status pill reads.

- Grey is the default. `todo` and `retired` are neutral outlines, so a feed of ordinary records is quiet.
- Blue is motion: `active`.
- Amber is attention. Tinted for `caution`, where nothing is required yet; filled for `waiting`, where a person is the next actor.
- Green is good: tinted with a check for `done`, outlined with a disc for `live`.
- Red is `failed` and nothing else. It is never priority, never a record type and never a closed record. A plan that is `incomplete` is still in progress, so it is `active`, not `failed`.
- Teal is not a status. It stays the brand, links, record IDs and focus.

## Lookup

1. Lowercase and trim the status. Look it up under the record kind.
2. If the kind is not listed, use the `any` table, which holds the strings that mean the same thing in every kind.
3. Otherwise the role is `unknown`: dotted outline, diamond, label verbatim.

Priority, severity, record type and checkout are never inputs. Three strings mean different things in different kinds and so need the kind: `approved`, `deployed`, `pending`.

## Every status

| Kind | Role: statuses |
|---|---|
| task | todo: `open`; active: `in-progress`, `coding-complete`, `committed`, `merged-main`, `deploy-init`, `deploy-success`, `deployed`; waiting: `pr`; caution: `coding-updates`; done: `closed`; retired: `superseded` |
| issue | todo: `open`; active: `in-progress`; done: `closed`; retired: `superseded` |
| feature | todo: `planned`; active: `in-progress`; done: `completed`; live: `production`; retired: `deprecated` |
| plan | todo: `drafted`; active: `started`, `incomplete`; done: `complete` |
| lesson | todo: `draft`; waiting: `proposed`; done: `accepted`; live: `active`; retired: `superseded`, `archived` |
| escalation | waiting: `requested`; active: `approved`, `applying`; failed: `denied`, `denied_with_guidance`, `failed`; done: `applied` |
| coordination request | todo: `intake_received`, `queued`; active: `dispatching`, `running`; done: `succeeded`; failed: `failed`, `dead_letter`; retired: `cancelled` |
| agent session | todo: `allocated`; active: `claimed`; retired: `retired` |
| project | live: `active`; retired: `archived` |
| deployment decision (no pill today) | waiting: `pending_approval`; active: `approved`, `deploying`; caution: `diverted`; failed: `reverted`, `failed`; done: `deployed` |
| component (no pill today) | live: `active`; retired: `deprecated`, `archived` |
| component lifecycle (no pill today) | waiting: `proposed`; active: `approved`, `designed`, `development`; live: `production`; failed: `code-red`; retired: `deprecated`, `archived` |
| handoff (no pill today) | todo: `pending`; active: `claimed`; done: `completed`; caution: `stale` |
| lesson candidate (no pill today) | waiting: `pending`; done: `approved`; caution: `stale` |
| relationship (no pill today) | live: `active`; retired: `archived` |
| recipe run (no pill today) | todo: `queued`; active: `running`; waiting: `awaiting_gate`; done: `completed`; failed: `failed`; retired: `cancelled`, `expired` |
| recipe step (no pill today) | todo: `pending`; done: `ok`; failed: `error`; retired: `skipped`; waiting: `awaiting` |
| recipe (no pill today) | todo: `draft`; active: `validated`; live: `published`; retired: `deprecated`, `retired` |
| gate | waiting: `pending`; caution: `snoozed`; done: `decided`; retired: `expired`, `superseded` |
| gate verdict (no pill today) | done: `approve`, `ack`, `promote`; failed: `deny`; caution: `snooze`, `edit` |
| search signal (no pill today) | live: `available`; done: `ranked`; retired: `no_match`, `disabled_by_user`; failed: `unavailable`, `timed_out` |

Readings that rest on an assumption, to confirm: `pr` as waiting (it is active if merges are automatic); lesson `proposed` and lesson candidate `pending` as waiting (they are active if no person decides); `diverted` as caution and `reverted` as failed, read from their names; `stale` as caution.

`blocked` is mapped in the shipped code and is not a governed status for any record kind. It is kept as a legacy alias for `waiting`.

## The other dimensions

| Fact | Channel | Component |
|---|---|---|
| Priority, severity, gate risk | One four-step urgency scale. Mono label, four-bar glyph, neutral ramp. Level 0 is the only filled badge. | `Pill`, urgency badge |
| Checkout, active session | Lock or signal glyph. Neutral for checkout; the accent for a live session. Checked in is shown only on the detail page. | `Pill`, operational chip |
| Record type | Kind label and icon in `text-dim`. No color. | `RecordCard` |
| Category, escalation kind | Tinted lavender tag, one look for every value. | `Pill`, tag |
| Component, project, search tier, transition type | Mono tag, neutral outline. Search tier adds a glyph. | `Pill`, tag |
| Context score, document maturity, changelog confidence | Segmented meter and a mono number, neutral ramp. | `Pill`, level meter |
| Diff | Tinted line with a + or - sign. | `DocumentSection` |
| Alerts | `info`, `success`, `warning`, `danger` roles with an icon and a heading word. | Alert, Flashbar |
| Feed row rail | Record type by default (teal; seafoam for plans; lavender for lessons). The lifecycle role replaces it for `caution`, `waiting` and `failed`. | `RecordCard` |
| Document type | Tag with a page glyph, one brand treatment per type. | `Pill`, tag |
| Document subtype pattern | Mono tag, one look for every value. | `Pill`, tag |

## Accessibility

- Every pill carries a label, a glyph and a color. The nine glyphs have different silhouettes, and the two roles that need a person are also the only filled ones.
- Pill text is 4.5:1 or better on its own fill over canvas, surface and raised surface. The lowest is `retired` at 4.91:1 on raised.
- Under simulated protanopia, deuteranopia and tritanopia (Machado 2009 matrices, CIE76 distance), the two filled roles stay apart: amber against red is 36, 20 and 43. The closest pair of text hues is `done` against `failed` under deuteranopia, at 13 with a lightness difference of 12; those two always differ by fill and glyph as well. These are simulations of dichromacy, not tests with people.
- In forced-colors mode every pill keeps a solid border and its glyph.
- An opt-in mode that moves green to blue and red to orange would give red-green color-blind users full hue separation. The role tokens are the only thing it would override. It is not built.
