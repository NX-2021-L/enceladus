A section of a sectioned document: heading, body, the changed marker, the in-focus highlight and diff lines.

The preview is a schematic. From the catalog: the section marker is Space Grotesk 10px on an amber 0.16 fill with a full radius; the highlight is `rgba(90,155,212,.08)`; diff lines use GitHub green and red at 0.15.

- Marker: `tint-amber-16` ground, `warning-text` label, `radius-pill`. The 10px label snaps to 11px (`text-2xs`).
- Highlight: `tint-blue-08`, replacing the off-palette blue.
- Diff: `diff-add-fill` and `diff-remove-fill` with a `+` or `-` sign in `diff-add-text` and `diff-remove-text`, so added and removed do not depend on color.

**Decision for io:** section labels ship with left rails. Recommended: keep a rail only where it marks state (a changed section), not as decoration on every label.

Gap: outline tree, editor and conflict view are not in the catalog.
