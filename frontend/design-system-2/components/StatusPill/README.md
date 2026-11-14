The lifecycle status of a record, drawn as a capsule with a glyph, a label and a role color.

Markup: `<span class="enc-pill" data-role="waiting">pr</span>`. The styles are in `components/bundle.css`; every color is a `status-<role>-*` token.

## What the consumer provides

- `data-role`: one of `todo`, `active`, `caution`, `waiting`, `done`, `live`, `failed`, `retired`, `unknown`. Look it up in `status-map.json` from the record kind and the status string. Nothing else is an input: not priority, not severity, not record type, not checkout.
- The label: the status string with hyphens and underscores shown as spaces. CSS uppercases it.

## Rules

- A pill with no `data-role`, or a status the map does not contain, renders as `unknown`: dotted outline, diamond, label verbatim. That is the designed behaviour for a status added to the governed model before the map is updated.
- The capsule shape (`radius-pill`) is reserved for lifecycle. Priority, checkout, tags and scores use the rectangular components in `Pill`.
- Typeface is Space Grotesk, medium, 12px, uppercase, tracking 0.07em, as shipped. A status is a word that names a state, so it takes the label face; coded values take the mono face.
- Only `waiting` and `failed` are filled. Do not add a filled treatment to another role, and do not add glow.
- Text is 4.5:1 or better on its own fill over canvas, surface and raised surface (lowest: `retired` 4.91:1 on raised). The contrast for each role is in its token's usage note.
- Replaces the shipped `StatusChip`. Changes from shipped: capsule instead of a 4px radius, an 8px glyph instead of a 6px glowing dot, and tinted or filled grounds for five of the nine roles.
