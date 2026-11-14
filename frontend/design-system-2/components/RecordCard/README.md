The record card in its four shipped variants: feed, compact, standard and selectable.

## Feed variant (the feed row)

Markup: `.enc-row` with `.enc-row__top`, `.enc-row__title` and `.enc-row__chips`; styles in `components/bundle.css`. Values are the shipped ones unless marked.

- Surface `surface`, border 1px `border`, radius `radius-lg`, padding `row-pad-y` by `row-pad-x` (13px by 16px), 8px between rows, minimum height `tap-min`.
- Row 1: record ID (`RecordId`), copy control, project label and right-aligned relative time, both mono 11px in `text-dim`.
- Row 2: title, Inter 13.5px medium, line height 1.35, `text`, one line with ellipsis.
- Row 3: chip strip with 8px gaps, wrapping: status pill, urgency badge, then the checked-out chip when the record is held.
- Hover: border to `border-strong`. Focus: 2px `focus` outline, 2px offset. Selected: `border-strong` plus `glow-teal`.

**The rail.** Every feed row has a `rail-width` rail on its left edge. Its color is the record type unless the lifecycle role asks for attention.

- Set `data-type` to the record type. `task`, `issue`, `feature` and `document` take the brand teal (`rail-task` and so on). `plan` takes seafoam (`rail-plan`). `lesson` takes nebula lavender (`rail-lesson`). Any other type takes `rail-default`.
- When the pill's role is `caution`, `waiting` or `failed`, set `data-rail` to that role. The rail takes that role's rail token instead: amber for caution and waiting, red for failed.
- On hover the border brightens to `border-strong` and the rail is removed, as shipped.
- The rail reads the same role as the pill, and priority is never an input, so a closed P0 row has a teal rail and the two cannot disagree.

Changed from shipped: the rail no longer goes red for P0 or dims for closed records, and plans and lessons have their own rail colors.

**Documents.** A document row adds two tags after the status pill: the document type (`<span class="enc-tag" data-doctype="brd">`), which has one brand color treatment per type and a page glyph, and the subtype pattern (`<span class="enc-tag" data-kind="code">`), which looks the same for every value.

## Compact and standard

Kind label (Space Grotesk 12px bold uppercase), record ID, title as an `h4` in `text-display`, a two-line description in `text-dim` and a status footer. Padding 1rem on compact. No rail. Changed from shipped: the kind label is `text-dim`, not teal, so teal stays with links and IDs.

## Selectable

A compact or standard card with the selected state: `border-strong` plus `glow-teal`.

## Gaps

The catalog does not give the standard variant's padding, the selectable variant's control, or how the kit's `SignalReadout` evidence chips are styled under the feed row.
