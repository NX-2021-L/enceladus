# Showcase Site — UI Kit

Pixel-faithful recreation of the **public showcase at jreese.net/enceladus-showcase**. It's the platform's portfolio artefact for hiring managers — one long dark-canvas article with a hero, architecture cards, innovation items, a stats grid, a pull-quote, and a lightbox carousel for screenshots.

## Source of truth

- `NX-2021-L/enceladus-showcase` · `enceladus-showcase.html` (static, single-file, ~37 KB). All brand tokens + component styles are in the inline `<style>` block of that file — nothing else is needed.
- Screenshots are imported to `assets/` (see project root `assets/showcase-*.jpg`).

## What's in here

- `index.html` — the showcase, factored but rendered identically to production.
- `Hero.jsx` — full-viewport hero with atmospheric moon photo at 0.15 opacity.
- `Navbar.jsx` — sticky top nav with scroll-state change.
- `Article.jsx` — body prose components (headings with teal rule, paragraphs, blockquote, `.record-id` spans).
- `ArchGrid.jsx`, `InnovationList.jsx`, `StatsGrid.jsx` — the three big composable sections.
- `FloatStrip.jsx` — bottom-left floating CTAs with the `◆` diamond easter egg.
- `Carousel.jsx` — near-opaque lightbox, keyboard + touch navigation.
- `Footer.jsx` — teal top rule, mono dust copyright.
- `data.js` — hero badges, architecture cards, innovations, stats, carousel images (points at our local `assets/showcase-*.jpg`).

## Notes

- Production loads `jreese.net/css/styles.css` (Bootstrap-based site-wide stylesheet) for outer nav + typography resets. The recreation embeds just Bootstrap 5 CSS from CDN so the `navbar` and `container px-5` still render correctly without changing the markup.
- The Syne/Space Grotesk/Inter/JetBrains Mono Google Fonts bundle is imported via `colors_and_type.css` at the project root.
- Carousel images are pulled from `assets/` rather than `jreese.net/img/...` so the kit works offline.
