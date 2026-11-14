The rectangular pill family for every fact that is not lifecycle: urgency badge, operational chip, tag and level meter.

One component with variants replaces the shipped `Badge`, `Chip` and `SearchTierBadge`, which differ only in typeface and one pixel of padding and draw priority and checkout differently in the feed and on the detail page.

## Variants and what the consumer provides

- **Urgency badge**, `<span class="enc-badge" data-level="0">P0</span>`. For priority (P0 to P3), severity (critical to low) and gate risk, which share one four-step scale. `data-level` is 0 for the most urgent. JetBrains Mono: the value is a code. Neutral ramp with a four-bar glyph; level 0 is the only filled badge.
- **Operational chip**, `<span class="enc-op" data-op="held">Checked out</span>`. `data-op` is `held`, `free` or `session`. Space Grotesk: the value is a state word. Lock or signal glyph. In the feed show `held` only; the absence of the chip means checked in.
- **Document type tag**, `<span class="enc-tag" data-doctype="brd">brd</span>`. `data-doctype` is the document's type: `doc`, `idea`, `brd`, `handoff`, `wave`, `governance_sync`, `lesson-candidate`, `coe`, `skill` or `context-node`. Five brand colors, each outlined for one type and tinted for another, so all ten differ. An unlisted type takes the `doc` treatment. The subtype pattern is a code tag beside it.
- **Tag**, `<span class="enc-tag">security</span>`. For category and escalation kind. Space Grotesk, tinted lavender, no glyph. Add `data-kind="code"` for identifiers (component, project, search tier, transition type): JetBrains Mono, case as given, neutral outline. Search tier adds `data-glyph="local"` or `"hybrid"`.
- **Level meter**, `<span class="enc-level" data-level="high">…</span>` with three `<i>` segments, `data-on` on the filled ones. For context scores, document maturity and changelog confidence. Mono number, neutral ramp.

## Rules

- No variant here uses a status hue or the capsule shape. That is what keeps priority, checkout and taxonomy from being read as lifecycle.
- Urgency never changes any other element: not the status pill, not the row rail, not the title.
- One look per tag kind for every value. The word carries the value; do not assign a color per category.
- Padding is `pill-pad-y` by `pill-pad-x` (2px by 8px). The shipped mono badge used 1px vertical padding; it snaps to 2px.
