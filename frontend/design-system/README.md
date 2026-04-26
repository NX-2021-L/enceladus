# Enceladus Design System

**Version:** v1.0 · April 2026
**Maintainer:** J. Reese
**Scope:** Brand identity + visual system governing the Enceladus platform across the PWA 2.0 governance cockpit, the public showcase at `jreese.net/enceladus-showcase`, and hiring / collaborator documents.

> Operational philosophy made manifest — a $35/month serverless platform that thinks about itself.

---

## What is Enceladus?

Enceladus is a production **knowledge-governance platform** built and operated solo by J. Reese. It coordinates multiple AI agents across 20 active projects, has accumulated 2,789+ governed records, and runs on AWS serverless at ~$35/month. The core primitives — Features, Tasks, Issues, and **Lessons** — are ontologically-defined objects with governed lifecycles, required evidence gates, and deterministic completion contracts.

The brand is named for Saturn's sixth-largest moon: small, strange, and alive beneath the surface. That literal quality (disproportionate energy from a tiny body) is the north star for every visual choice.

**Archetype:** Sage + Magician. Evidence-gated wisdom + transformative capability. Not Ruler, not Hero, not Creator.

---

## Products covered by this system

| Surface | Audience | Where it lives |
|---|---|---|
| **PWA 2.0 governance cockpit** | Sole operator (J. Reese), on mobile | `frontend/ui/` in `NX-2021-L/enceladus` — React 19 + Vite + Tailwind. Dark, mobile-first. |
| **Showcase site** | Hiring managers, collaborators | `jreese.net/enceladus-showcase.html` in `NX-2021-L/enceladus-showcase` — static HTML. Portfolio artefact. |
| **One-pagers / hiring docs** | Hiring managers | Print. Inverted (light) palette; identity preserved through typography + telemetry. |

See `ui_kits/` for pixel-faithful recreations of the first two.

---

## Sources consulted

- **GitHub repo** `NX-2021-L/enceladus` (main) — full monorepo. We read `frontend/ui/src/` to recreate the PWA: `components/{cards,layout,shared}/`, `pages/DashboardPage.tsx`, `index.css`, `main.tsx`.
- **GitHub repo** `NX-2021-L/enceladus-showcase` (main) — static showcase site at `enceladus-showcase.html` plus three dashboard screenshots in `assets/images/`.
- **Brand doc (attached)** — `ENCELADUS Brand Identity & Visual System v1.0` by J. Reese, April 2026. The 10-section document that this system implements.
- **Cassini 2008 moon photograph** (NASA/ESA) — source image for the teal/seafoam/void palette.
- **JWST Orion Nebula (M42)** — source imagery for lavender/crimson/indigo.

Both repos were read through the GitHub tools rather than cloned locally; if you have commit access, clone them for full fidelity.

---

## Index — what's in this folder

```
README.md                   ← you are here
SKILL.md                    ← Claude Code / Agent Skills manifest
colors_and_type.css         ← all CSS variables + semantic element styles
assets/                     ← logos, favicons, moon photo, showcase screenshots
preview/                    ← design-system review cards (one HTML each)
ui_kits/
  showcase/                 ← jreese.net/enceladus-showcase recreation
    README.md, index.html, *.jsx
  pwa/                      ← PWA 2.0 governance cockpit recreation
    README.md, index.html, *.jsx
```

---

## 01 · Content fundamentals

The writing voice is distinctive, load-bearing, and extremely specific. Honour it.

**Register:** Confident but not corporate. Technical without a PhD gate. Philosophical without being precious. "Operational philosophy made manifest" — not "revolutionary AI-powered platform."

**Casing:**
- `ENCELADUS` wordmark: **ALL CAPS**, letter-spacing 0.15em, Space Grotesk Bold (or Syne for hero only).
- Page / section headings: Title Case or Sentence case, never ALL CAPS.
- Uppercase labels allowed for chip/badge labels only — JetBrains Mono, tight letterspacing.

**Pronoun:** First-person singular. "I am the sole architect, developer, and operator." The platform's authorship is part of the brand. Never "we."

**Numbers:**
- Use exact, verifiable counts: **2,789+ records · 20 projects · ~$35/month · 17 lessons · 5 code-mode tools · 89% schema reduction.** The "~" on $35 is intentional — a signal of truthfulness.
- Scores carry **decimals**: `pillar_composite 0.82`, not "high". `resonance 0.734`. This is the brand's evaluation language.
- Compact scale words (million/thousand) are fine when writing for hiring managers.

**Record IDs — the brand's secret weapon:**
- **Always inline-cite** IDs in running prose: "The lesson primitive (`ENC-FTR-052`) gives the platform a first-class record type..."
- Render them in **JetBrains Mono**, Cosmic Teal, at 95% of surrounding body size.
- Project prefixes seen in the wild: `ENC-` (Enceladus core), `DVP-` (devops). Type codes: `TSK`, `ISS`, `FTR`, `LSN`, `DOC`, `PLN`.
- Format is always `{PROJECT}-{TYPE}-{NN...}`. Never abbreviate. Never lowercase.

**Emoji:** No. Not in UI, not in copy, not in docs. The platform uses structured data (record IDs, pillar scores, mono tokens) as its texture instead. The showcase uses a diamond bullet `◆` once, in the floating action strip, rendered via HTML entity — this is the limit.

**Icons:** Lucide-style single-stroke line icons at 1.5–2px weight only (the PWA ships inline `<svg>` paths matching this weight). Never filled, never duotone.

**Examples — pulled directly from the sources:**

> "Enceladus is not a product for sale — it is an operational philosophy made manifest."

> "The core innovation is treating project management primitives — Features, Tasks, Issues, and now **Lessons** — not as database records, but as **ontologically defined objects** with governed lifecycles, required evidence gates, and deterministic completion contracts."

> "The Lesson Primitive (`ENC-FTR-052`) transforms operational history into institutional knowledge."

Note the rhythm: short assertive sentence, then a complex technical sentence with inline bold terms and an inline-cited record ID. Copy this cadence.

**Don't write:**
- "Leverage AI to unlock..." — banned jargon.
- "Our team..." — there's no team.
- "Revolutionary" / "groundbreaking" / "game-changing" — marketing slop.
- "🚀 Ship faster!" — no.

---

## 02 · Visual foundations

**Colors.** See `colors_and_type.css` for the full token set. The system has exactly **6 core colors** to memorize: Void Black `#0A0A0F` (canvas), Cosmic Teal `#3D9BA8` (primary), Seafoam `#C8DDD9` (display text), Nebula Lavender `#8A8CB5` (knowledge), Stellar Crimson `#C85060` (alerts), Terminator Slate `#2E4D5C` (code/muted). Everything else is a derivative.

**Typography.** Four families, each with a single job: **Syne ExtraBold 800** for hero display *only*; **Space Grotesk 400/500/700** for headings and chip labels; **Inter 400/500/600** for all body copy; **JetBrains Mono 400/500** for record IDs, scores, hex values. Font files are pulled from Google Fonts — no self-hosted binaries in this repo. If you need offline builds, add `fonts/` later.

**Backgrounds.** The default is **near-black (`#0A0A0F` → `#111827`)** — the void. The Enceladus moon photo appears **only** as an atmospheric layer (`opacity: 0.15–0.20`) behind hero text; it never competes with content. No gradient meshes, no stock photos, no humans, no illustrations. Print inverts to white `#FFFFFF` or very light seafoam tint `#F5FAFA`.

**Imagery vibe.** Cool, cosmic, high-contrast. One hero photo (the moon) recurs as motif. Screenshots of the platform itself are admissible — never decorative stock.

**Spacing.** 4px baseline scale (`--space-1` … `--space-16`). PWA cards use `px-4 py-3` internally with `space-y-2` between siblings. Showcase sections breathe more: `padding: 4rem 1.5rem` on article wrappers.

**Corner radii.** Small radii, not pill-shaped. `3px` on code pills, `4px` on status chips, `6–8px` on cards, `12px` on large panels. Never rounded-full except for circular carousel arrows.

**Cards.**
```
background: var(--bg-surface);       /* #111827 */
border:     1px solid rgba(61,155,168,0.20);
border-radius: 8px;
padding: 1.25rem 1.5rem;
transition: border-color 200ms cubic-bezier(0.4,0,0.2,1);
```
On hover, the border brightens to `rgba(61,155,168,0.50)`. No shadow change, no lift — the card stays grounded. (Floating action buttons DO lift, see below.)

**Hover states.** Border-color brightens (teal 0.20 → 0.50), text shifts from slate to teal-light. No scale, no shadow bloom. Floating elements (CTAs) DO translateY(-2px) and deepen shadow.

**Press/active states.** Darker background (`active:bg-slate-700`), no scale-down. Links in text switch to teal-light on hover.

**Shadows.** Three tiers:
- `--shadow-sm` — almost invisible, for subtle elevation
- `--shadow-md` — floating CTAs, menus: `0 4px 18px rgba(0,0,0,0.5)`
- `--shadow-lg` — carousel overlay: `0 8px 48px rgba(0,0,0,0.7)`

Plus three **glow** shadows for telemetry decoration: `--glow-teal`, `--glow-lavender`, `--glow-crimson`. Use sparingly, on things like high-confidence lesson cards or P0 alerts.

**Borders.** All borders are teal-with-alpha: `rgba(61,155,168,0.1)` for dividers, `0.2` for subtle card edges, `0.5` on hover. The _only_ solid-color borders are on alert states (`--enc-crimson`) and chip outlines.

**Transparency + blur.** Sparingly. The PWA header uses `bg-slate-900/95 backdrop-blur` as a sticky nav. The showcase carousel overlay is `rgba(10,10,15,0.95)` — near-opaque. Everything else is solid.

**Animation.** **Orbital motion, not spring physics.** Use `cubic-bezier(0.4, 0, 0.2, 1)` — Material's "standard" easing. No bouncing, no elastic. Durations: 150ms (tiny state flips), 200ms (card entry, hover), 300ms (graph nodes, modals). The TTL countdown and "In Progress" badge pulse via `animate-pulse` only — don't invent new keyframes.

**Layout rules.**
- Max content width **880px** on article pages (showcase).
- Max page width **72rem** on app pages.
- Nav **sticky top** with backdrop-blur; bottom nav **fixed bottom** on mobile.
- One **teal accent line** per page minimum — a rule, a blockquote border, or a card edge.
- The `::before` atmospheric moon image sits at `inset: 0; opacity: 0.15` — it's never a full-bleed primary.

**Telemetry is decoration.** Record IDs (`ENC-LSN-004`), constitutional scores (`0.82`), TTL countdowns (`42s`), SHA-256 hashes — these are the visual texture. Put them in JetBrains Mono, teal or dust, at small sizes. Do not hide them. Do not apologize for them.

---

## 03 · Iconography

**Approach.** The PWA ships **inline SVG `<path>`s** stroked at 1.5–2px — no external icon font, no sprite sheet, no icon components library. Each icon is pasted directly into its consuming component as a hand-crafted path `d="..."`. The set is tiny and purposeful (~10 icons in production: home, projects, feed, docs, clock/changelog, hamburger, chevron, copy, close, arrow).

**Source set — substitution flagged.** The stroke weight, corner treatment, and overall silhouettes match **[Lucide](https://lucide.dev)** almost exactly. For this design system, we link Lucide via CDN in the UI-kit previews to avoid recreating each path by hand. **Substitution flagged to the user: these are Lucide icons, not the exact PWA-shipped paths. They visually match, but if you need byte-identical parity with production, copy the `d=""` attributes out of `Header.tsx` / `BottomNav.tsx` / `TaskRow.tsx`.**

**Rules.**
- **Stroke-only**, never filled. `fill="none"`, `stroke="currentColor"`, `stroke-width="1.5"` or `2`.
- `stroke-linecap="round"` and `stroke-linejoin="round"` everywhere — no sharp corners.
- Color inherits from text (`currentColor`), so icons pick up the parent's teal / dust / starlight.
- Sizes: `w-4 h-4` (16px) inline with text, `w-5 h-5` (20px) in chips, `w-6 h-6` (24px) in nav/header.
- **No emoji.** **No unicode symbol icons** — except **`◆`** (U+25C6, BLACK DIAMOND) used exactly once in the showcase's floating CTA strip as a brand easter egg.

**Logos / marks.**
- No finalized logomark exists yet. The brand doc describes two concepts (subsurface cross-section; governance hex-node) but both are forward-looking. See `preview/20-logo-direction.html` for sketched direction.
- The current `favicon.svg` in the PWA is a temporary placeholder (`"P"` on a slate tile) — see `assets/original-favicon.svg`. It does **not** reflect final brand and should be replaced.
- The **wordmark** `ENCELADUS` in Space Grotesk Bold, ALL CAPS, tracking 0.15em, teal-on-void, is the production-ready identity today. Use it.

---

## 04 · Design principles (the Five Laws)

Apply in order; earlier laws override later ones.

1. **Dark canvas, luminous signal.** The void is the background; content emerges like starlight. Print inverts; hierarchy doesn't.
2. **Fracture as detail.** Governance hashes, constitutional scores, TTL countdowns — these are the texture, not supporting noise. Render them boldly in mono teal.
3. **Subsurface depth.** Lead with the gesture — high-level status, vibe-board score. Reveal complexity on demand. Skeleton loaders, progressive disclosure.
4. **Orbital motion, not spring physics.** `cubic-bezier(0.4, 0, 0.2, 1)`. No elastic. No bouncing.
5. **Telemetry is decoration.** Record IDs in a hiring doc are not leakage; they are evidence of rigor.

---

## 05 · How to use this system

- **Designing a new Enceladus surface?** Start with `colors_and_type.css`. Use CSS variables, not magic hex codes.
- **Writing copy?** Reread `01 · Content fundamentals` out loud. If it sounds like a startup landing page, rewrite.
- **Building a component?** Look at the `ui_kits/pwa/` source. Don't reinvent — the PWA has production patterns for feed cards, status chips, pillar charts.
- **Exporting to Claude Code / Agent Skills?** `SKILL.md` is the manifest; this folder drops directly into an Agent Skill.

---

## Caveats + what's missing

- **No font files in `fonts/`.** All type is loaded from Google Fonts CDN. If you need offline/print pipelines, download Syne, Space Grotesk, Inter, and JetBrains Mono WOFF2s and drop them in `fonts/` with `@font-face` rules in `colors_and_type.css`.
- **No finalized logomark.** The brand doc describes two concepts but neither has been rendered. The current `favicon.svg` is placeholder.
- **Iconography is Lucide, not PWA-exact.** Visually identical stroke weight and geometry, but not byte-identical to shipped paths.
- **Showcase UI-kit uses CDN Bootstrap.** The live `jreese.net` site loads `jreese.net/css/styles.css` which we don't have access to. The recreation uses the tokens from the inline `<style>` block only — good for 95% fidelity, missing the outer nav styling.

---
