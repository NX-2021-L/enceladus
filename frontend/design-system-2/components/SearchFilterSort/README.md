The search, filter and sort components together: text filter, property filter, sort select, segmented view switch, sortable table and pagination.

A reference page. Every component on it is the existing Cloudscape-derived implementation from the bundle, with the same props, behavior and layout; only the stylesheets changed.

## What changed in the re-skin

- Colors read role tokens (`surface`, `surface-sunken`, `text`, `text-dim`, `accent`, `accent-hover`, `border`, `divider`, `focus`) and the `tint-teal-*` literals, not `enc-*` primitives and inline rgba values.
- Type sizes read the scale: 10 to 11px becomes `--text-2xs`, 11.5 to 12.5px `--text-xs`, 13 to 13.5px `--text-row`, 14px `--text-sm`.
- Filter tokens in `PropertyFilter` are identifier tags: neutral mono on `surface-raised` with a `tag-code-border`. Teal is left for what is interactive or selected.
- Remove and invalid states use `danger-text` and `danger`.
- Secondary text on a raised ground uses `text-dim-raised`.
- Table cells show the new pills: `enc-pill` for status, `enc-badge` for priority, `enc-id` for record IDs.

## What did not change

Component names, props, events, keyboard behavior, DOM structure and class names. Selected and current states stay teal: selected segment, current page, focused field, checked row.

Re-skinned: `TextFilter`, `PropertyFilter`, `Select`, `Multiselect`, `Autosuggest`, `Pagination`, `CollectionPreferences`, `Table`, `TokenGroup`, `SegmentedControl`, `Input`, and `SideNavigation`.

The arrangement on this page is one plausible composition. It is not a layout specification; the app's own layouts stay as they are.
