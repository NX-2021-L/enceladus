# Revision report, 2026-11-13

## Second pass, on io's direction

- **Rail.** Kept on every feed row. It shows record type (teal for task, issue, feature and document; seafoam for plan; lavender for lesson) and is replaced by amber or red when the role is caution, waiting or failed. It is removed on hover, as shipped. Waiting is included with caution because both are the amber attention state; drop `waiting` from `by_role_override` in `status-map.json` if only caution was meant.
- **Plan `incomplete`** is `active`, not `failed`.
- **Documents** have a type tag with one brand treatment per type and a subtype-pattern tag that is the same for every value. The ten types are the `document.*` entities in the dictionary: confirm the list.
- **SideNavigation** keeps its always-on `surface` background and has a full specification.
- **Search, filter and sort.** Twelve Cloudscape-derived components are re-skinned onto the role tokens, in their sources under `v2/components/` and in `components/bundle.js`. Only the CSS strings changed; props, behavior, structure and layout did not. `SearchFilterSort` shows them together.
- The older `_ds_bundle.js` copy was not touched, so the legacy cards under `v2/components/*/` that load it still show the earlier skin.

Built from the shipped-state catalog (`DOC-C8B611A5CB39`) and the status-color research (`DOC-D679C86958C0`). No code was read or changed.

## What changed and why

- **Tokens** went from 49 colors to 228, in three tiers: 15 new primitives, 27 alpha tints as literals, and a role tier that names every job the catalog found the code reaching for. Radius, shadow, spacing, size, z-index and breakpoint tokens were added for values that shipped without one. Details and the snap table are in `migration.md`.
- **Status color** is a role layer with a data file. Nine roles replace seventeen string matches; all 112 governed status values across 21 vocabularies have a role; an unmapped value has a designed look. See `status.md` and `status-map.json`.
- **Components.** Guides and previews were added for the record card, status pill, pill family, record ID, detail header, document section, worklog entry, home tile and skeleton card. The last five previews are schematics, because the catalog gives their existence and a few values but not their layout.
- **Brand book.** The statements the catalog showed to be out of date were corrected in place.

Each of the eleven defects in the catalog's section 5.5 is closed by structure. Priority and record type are not inputs to the role lookup (1, 2). Unknown has its own role (3). Not started, ended well and retired are three roles (4, 5). Amber is attention only and checkout is neutral (6). Lavender is taxonomy only (7). Search tiers differ by glyph (8). The rail's override reads the pill's role, and its default reads record type only (9). Every role has its own glyph (10). Color comes from a token keyed to a role, and the mapping is data (11).

## Brand rules the research overrode

| Rule in the brand book | Now | Why |
|---|---|---|
| Success is teal, never green | Done and live are green | A hue with thirteen meanings cannot signal one. Teal stays the brand, links, IDs and focus. Green for good is the convention readers bring. |
| Crimson for P0 and alerts | Red only for the failed role and errors | Red reserved for things that went wrong. Urgency is a neutral scale. |
| Lavender marks knowledge and every lesson | Lavender is the taxonomy tag color only | One color, one meaning. Lesson lifecycle was invisible. |
| Amber for checked out | Checkout is neutral with a lock | Warm colors only for abnormal states. Holding a lock is routine. |
| Glow on blocked, P0 and lesson dots | No glow | Emphasis is carried by fill, on two roles. |
| Small radii, never rounded-full | Lifecycle pills are capsules | Shape is a channel: only lifecycle is a capsule. This one is a design choice, not a research finding. |

## Recommendations on the decisions that are io's

1. **Source of truth.** `@io-kit/tokens` in DTCG, since every other product already builds from it. Generate the repo's CSS and this artifact's `tokens.json` from it. Until that exists, this artifact is the proposal and the repo folder is what ships.
2. **Teal, never green.** Retire the rule. Green and red already ship in diffs and scores; this brings them inside the system.
3. **Priority.** Its own badge only. No claim on the pill, rail or title.
4. **Lessons.** Show lifecycle like every other record. Type is the kind label and the `LSN` in the ID.
5. **Left rail.** Decided by io: kept on every feed row, by record type, with caution, waiting and failed overriding.
6. **Filled or outlined.** Both, by role: outline for the quiet roles, tint for active, caution and done, solid fill for waiting and failed.
7. **Statuses with no pill today.** Designed now. It is data, and it gives the kit's unstyled gate and recipe states somewhere to land.
8. **Light theme.** Not now. The role tier does not prevent one.
9. **Unused components and Syne.** Demote the 36 never-exposed components to an appendix group and stop presenting them as the product's library; remove nothing. Keep Syne for the showcase and the cover; drop it from the app's font download.

Further decisions raised by the catalog: the shadow on the detail card, the unicode glyphs used as icons, the left rails on section labels, and the amber Check In button. Each has a recommended rule where it appears in the brand book or the component guide.

## Not reconciled

- **Page width.** The app uses `calc(var(--space-16) * 56)`, which is 224rem if `--space-16` is 4rem. The brand book says 72rem. No token is proposed.
- **How often each status occurs.** The catalog has counts by type only. Whether the feed stays mostly neutral depends on the share of closed records, which are tinted green here. If that share is high, move `done` to an outline.
- **`denied` as failed.** The prompt lists it as a terminal failure. A denial is also io's own decision, so red may overstate it; `retired` is the alternative.
- **Severity** is not in the governance dictionary. It is mapped onto the urgency scale from app code.
- **Kit surface keys.** Whether the kit's `surface` is the page or a card is not stated; see `io-kit-mapping.md`.
- **Plan graph.** Seven Tailwind literals in a Cytoscape stylesheet that cannot read CSS variables. They need resolved values at build time; no mapping is proposed because the catalog does not say what each color marks.
- **Kit-rendered surfaces.** How recipe runs, gate forms, schema forms and signal chips are styled in the app was not traced, so the attribute bindings in the mapping are untested.

## Not done

- No code or repository file was changed. The repo copy of the design system and `@io-kit/tokens` are as they were.
- No color-blind override theme. The default relies on glyph, fill and lightness.
- The simulated color-vision figures are computed, not tested with people.
- `tokens.css` was not written; the page regenerates it from `tokens.json`.
- The 65 Cloudscape-derived component cards and the cover are unchanged. The two older showcase cards that show the April pill and feed card now say so.
- Nothing was deleted, and no token was removed.
