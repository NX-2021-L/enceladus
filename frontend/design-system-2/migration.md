# Token tiers and migration

Tokens are in three tiers. Components read roles; roles alias primitives; nothing but a role's alias names a primitive. A token's usage note starts with its tier.

- **Primitives**: raw values. The eleven `enc-*` colors, the new hue steps (`enc-amber`, `enc-green`, `enc-blue`, `enc-red`, each with a `-light` text step; `enc-mist`, `enc-haze`, `enc-frost`), `enc-field`, `enc-placeholder`, and the `tint-*` alpha literals.
- **Roles**: brand-neutral jobs. `canvas`, `surface`, `surface-raised`, `surface-sunken`; `text`, `text-dim`, `text-dim-raised`, `text-display`, `text-on-accent`; `accent`, `accent-hover`, `accent-secondary`; `link`, `link-hover`; `border`, `border-strong`, `divider`; `focus`; `scrim`; `success`, `warning`, `danger`, `info` and their `-text` steps; `status-<role>-*`; `urgency-<n>-*`; `level-*`; `tag-*`; `op-*`; `diff-*`. This is the tier io-kit and other products bind to.
- Second pass: `rail-default`, `rail-task`, `rail-issue`, `rail-feature`, `rail-document`, `rail-plan`, `rail-lesson`, `status-caution-rail`; `doctype-<type>-text`, `-border`, `-fill` for the ten document types; `text-placeholder`; six more tints.
- **Component**: `control-h`, `control-h-sm`, `control-h-lg`, `tap-min`, `pill-pad-x`, `pill-pad-y`, `pill-glyph`, `rail-width`, `row-pad-x`, `row-pad-y`, `focus-offset`, `radius-pill`, `radius-round`, `shadow-bar`.

The system is dark only. Every color token holds its value under the `dark` theme, so a second theme can be added later by giving roles a second value; no role name would change.

Nothing is deleted in this pass. A deprecated token keeps its value and says what replaces it.

## Old token to new

| Old | New | Note |
|---|---|---|
| `--bg` | `canvas` | |
| `--bg-surface` | `surface` | |
| `--bg-surface-alt` | `surface-raised` | |
| `--fg` | `text` | |
| `--fg-muted` | `text-dim`; `text-dim-raised` on raised surface | `text-dim` keeps the dust value, 4.25:1 on raised |
| `--fg-display` | `text-display` | |
| `--knowledge` | `accent-secondary` | |
| `--code-bg` | `enc-slate` as a fill | never referenced by the app |
| `--accent`, `--accent-hover`, `--danger` | unchanged | already role names |
| `--border-subtle` | `1px solid` `border` | the color is now a token on its own |
| `--border-hover` | `1px solid` `border-strong` | |
| `--border-divider` | `1px solid` `divider` | |
| `--status-open` | `status-todo-*` | by role, through `status-map.json` |
| `--status-in-progress` | `status-active-*` | |
| `--status-blocked` | `status-waiting-*` | `blocked` is not a governed status |
| `--status-closed` | `status-done-*` | |
| `--status-draft` | `status-todo-*` | |
| `--status-lesson` | none | lessons show their lifecycle role |
| `--status-p0` | `urgency-0-*` | priority no longer colors status |
| `--v2-status-success` | `success` | green, was teal: visible change |
| `--v2-status-error` | `danger`, `danger-text` | |
| `--v2-status-warning` | `warning`, `warning-text` | same amber |
| `--v2-status-info` | `info`, `info-text` | blue, was teal-light: visible change |
| `--v2-status-pending` | `status-todo-text` | |
| `--v2-status-stopped` | `status-retired-text` | |
| `--v2-field-bg` | `surface-sunken` | |
| `--v2-field-border`, `-hover` | `tint-teal-25`, `tint-teal-45` | |
| `--v2-field-border-focus` | `focus` | |
| `--v2-field-placeholder` | `text-placeholder` | 2.75:1, source value kept |
| `--v2-divider` | `divider` | 0.12 becomes 0.1 |
| `--v2-panel-border` | `border` | |
| `--v2-overlay-bg` | `scrim` | |
| `--v2-control-height`, `-sm` | `control-h`, `control-h-sm` | |

## Names the code reached for and found undefined

| Undefined name | Now |
|---|---|
| `--bg-elevated` | `surface-raised` |
| `--bg-inset` | `surface-sunken` |
| `--bg-void` | `canvas` |
| `--border` | `border` |
| `--focus` | `focus` |
| `--status-success-fg`, `--status-warning-fg`, `--status-danger-fg` | `success-text`, `warning-text`, `danger-text`; for context scores, `level-high-text`, `level-mid-text`, `level-low-text` |
| `--accent-secondary` | `accent-secondary` |

## Shipped literals to scale steps

"Visible" marks a snap that changes what is on screen.

| Kind | Step | Shipped values that snap to it | Visible |
|---|---|---|---|
| Font size | `--text-2xs` 11px (new) | 10, 10.5, 11 | 10 and 10.5 grow |
| | `--text-xs` 12px | 11.5, 12, 12.5 | half a pixel |
| | `--text-row` 13.5px (new) | 13, 13.5 | 13 grows |
| | `--text-sm` 14px, `--text-base` 16px | 14, 16 | no |
| | relative `0.95em` | record ID | no |
| Tracking | `--tracking-label` 0.07em | 0.06em, 0.07em, 0.09em | slight on five 0.09em labels |
| | `--tracking-id` 0.01em (new) | 0.01em | no |
| Line height | `--lh-none` 1 (new) | 1, 1.05 | no |
| | `--lh-tight` 1.15 | 1.2 | slight |
| | `--lh-normal` 1.55 | 1.5, 1.6 | slight |
| | `--lh-relaxed` 1.7 | 1.65 | slight |
| Radius | `radius-pill` 999px, `radius-round` 50% (new) | 999px, 50% | no |
| Shadow | `shadow-bar` (new) | `0 -4px 16px rgba(0,0,0,.28)` | no |
| | none | `0 0 6px currentColor` dot glow | removed with the new pill |
| z-index | `z-raised` 5 | 3, 4, 5 | no, if order is kept |
| | `z-sticky` 20, `z-overlay` 30, `z-modal` 100, `z-top` 9999 | 20, 30, 100, 9999 | no |
| Breakpoint | `bp-sm` 688px | 600, 640, 688 | layouts that changed at 600 or 640 change at 688 |
| | `bp-md` 768px | 768, 769 | no |
| | `bp-lg` 960px | 900, 960, 1024 | layouts that changed at 900 or 1024 change at 960 |
| Size | `tap-min` 44px, `control-h` 32px, `rail-width` 3px | 44, 32, 3 | no |
| | `pill-glyph` 8px | 6px dot | dot becomes an 8px glyph |
| | `measure` 68ch, `measure-narrow` 52ch, `measure-tight` 38ch, `article-max` 880px, `split-column` 460px | same | no |
| Color | `tint-teal-08`, `tint-teal-35` | teal at .08, .35 | no |
| | `tint-amber-10`, `-16`, `-40` | amber at .1, .16, .4 | no |
| | `tint-lavender-08`, `tint-void-60` | lavender .08, void .6 | no |
| | `tint-blue-08` | `rgba(90,155,212,.08)` | slight hue shift |
| | `diff-add-fill`, `diff-remove-fill` | `rgba(46,160,67,.15)`, `rgba(248,81,73,.15)` | hue shifts to the system green and red |
| | `level-high-text`, `-mid-`, `-low-` | `#6ee7b7`, `#fcd34d`, `#fca5a5` | score bands lose hue; the meter carries the band |
| | not mapped | plan graph: `#0ea5a4`, `#0369a1`, `#334155`, `#64748b`, `#94a3b8`, `#e2e8f0`, `#020617` | see the report |

The type sizes, weights, line heights, tracking and motion values are CSS variables in `components/bundle.css`, not in `tokens.json`, because the token format has no family for them under those names. The 38 `var(--token, #hex)` fallbacks can drop their hex once the tokens resolve.

## Deprecated and unused

Tokens the app never references, kept because the system's own element styles and components still use some of them: `--bg`, `--code-bg`, the six `--print-*`, `--font-display`, `--text-xl`, `--text-4xl`, `--text-5xl`, `--text-6xl`, `--fw-semibold`, `--fw-extra`, `--tracking-wordmark`, `--tracking-tight`, `--space-10`, `--space-12`, `--radius-xl`, `--shadow-sm`, `--dur-slow`. None is removed.

Two workarounds a token now covers: `min-width: var(--space-0)` (use `0`), and `calc(var(--space-16) * 56)` as a page width (see the report; no token is proposed because the intended width is unclear).
