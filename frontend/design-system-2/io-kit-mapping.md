# io-kit mapping

Each key in the kit's common set has one Enceladus role to read. A generated bridge would emit, for each package prefix, `--io-<package>-<key>: var(--<role>)`.

| Kit key | Enceladus role or token |
|---|---|
| `surface` | `canvas` |
| `surface-raised` | `surface` |
| `surface-sunken` | `surface-sunken` |
| `text` | `text` |
| `text-dim` | `text-dim` |
| `accent` | `accent` |
| `accent-text` | `text-on-accent` |
| `accent-secondary` | `accent-secondary` |
| `focus` | `focus` |
| `border` | `border` |
| `border-strong` | `border-strong` |
| `danger` | `danger` |
| `success` | `success` |
| `link` | `link` |
| `link-hover` | `link-hover` |
| `scrim` | `scrim` |
| `radius-sm`, `radius-md`, `radius-lg` | `radius-sm`, `radius-md`, `radius-lg` |
| `radius-pill` | `radius-pill` |
| `font-ui` | `--font-body` |
| `font-display` | `--font-heading` |
| `font-mono` | `--font-mono` |
| `font-size`, `font-size-sm` | `--text-sm` (14px), `--text-xs` (12px) |
| `line-height` | `--lh-normal` |
| `control-h`, `control-h-sm`, `control-h-lg` | `control-h`, `control-h-sm`, `control-h-lg` |
| `tap-min` | `tap-min` |
| `focus-ring` | `v2-focus-ring` |
| `focus-offset` | `focus-offset` |
| `space-1` to `space-6` | `space-1` to `space-6` |
| `elevation-1`, `-2`, `-3` | `shadow-sm`, `shadow-md`, `shadow-lg` |
| `duration`, `duration-fast`, `duration-slow` | `--dur-base`, `--dur-fast`, `--dur-slow` |
| `easing` | `--ease-orbit` |
| `--io-bp-palette-min` | `bp-sm` (43rem) |
| `--io-bp-medium-min` | `bp-md` (48rem) |

Three rows are judgment calls to confirm against the kit:

- `surface` reads `canvas` and `surface-raised` reads `surface`, on the reading that a kit package draws on the page and raises its own cards. If kit packages are placed inside an Enceladus card, shift both up one step.
- `font-display` reads the heading face, not Syne, because the app never uses Syne.
- `font-size` reads 14px. The catalog does not say which size kit packages expect as their base.

## Kit keys with no Enceladus role

- `safe-top`, `safe-right`, `safe-bottom`, `safe-left`: pass `env(safe-area-inset-*)` through. Not a design token.
- `--io-bp-expanded-min` (kit default 80rem): the app has no breakpoint above 1024px. Leave the kit default.

## Enceladus roles the kit has no key for

- **Status.** The nine `status-<role>-*` sets, and the urgency, level, tag and operational sets. The kit has no shared tone vocabulary; gates, recipes and search expose `data-state`, `data-status`, `data-field="risk"` and `data-verdict` with no CSS. Those attributes can bind to the role classes through `status-map.json`, which already holds the kit's gate, recipe and search-signal values. A shared kit key set for this would be `status-<role>-text`, `-border`, `-fill`, `-dot`.
- `warning`, `info` and the four `-text` steps. The kit's common set has `danger` and `success` only; search reads `--io-color-warning-*` separately.
- `surface-raised` as a third elevation, `text-display`, `text-dim-raised`, `divider`.
- `z-*` and `bp-lg`.

## Packages that read Enceladus short names directly

shell, notify, settings, content and ui read `--bg`, `--fg`, `--accent`, `--border`, `--focus` and the space and radius names. `--border` and `--focus` now exist as roles, which ends the grey fallback. The other short names are deprecated here and still defined, so those packages keep working until they move to their own `--io-<package>-*` contract.

The search-ui theme emitter maps `border` to `--enc-slate`. It should read `border`.
