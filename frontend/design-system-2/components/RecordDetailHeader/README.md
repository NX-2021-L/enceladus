The header of the record detail page: identity, title, chip row, vitals grid and the sticky action bar.

The preview is a schematic. From the catalog: the detail card has 2rem padding, `shadow-md`, a `measure` (68ch) maximum width, no rail and no interactive states; the chip row carries priority, severity, category, component, active session and checkout; the action bar is sticky with `shadow-bar` and can sit on `surface-raised`.

## Rules

- Chip order: status pill, urgency badges, operational chips, then tags. On this page show both checkout values.
- The action bar repeats the status pill; it is the same pill on `surface-raised`, which is why every role is checked on that ground.
- The shipped Check In button is amber. Recommended: a normal primary button. Amber now means caution or waiting, and checking in is neither.

**Decision for io:** the brand book says cards stay grounded with no shadow, and this card ships with `shadow-md`. Recommended rule: one shadow tier for the single detail card and for floating bars, none on cards in lists.

## Gaps

Vitals grid columns and type, tab styling, neighbors, evidence checklist and action modals are not in the catalog.
