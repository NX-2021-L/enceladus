#!/usr/bin/env node
/**
 * Bundle-size budget gate (ENC-TSK-M18 / UX-A4, AC-2).
 *
 * Reads `dist/index.html` after `vite build` and computes the gzip size of
 * every JS asset referenced by an initial (non-module-preload, non-dynamic)
 * `<script>` tag — i.e. exactly what the browser downloads to paint the
 * default mobile route ("/"). Route chunks (Feed/Projects/.../record
 * primitives) are NOT in this set because router.tsx lazy-loads them via
 * `lazyRouteComponent()` / `React.lazy()` — they only ship after
 * `dist/index.html`'s own script tags resolve.
 *
 * Budget: 200 KB gzip (AC-2: "Initial mobile route JS ≤200KB gz, route
 * code-split"). Fails the build (exit 1) if the initial JS payload exceeds
 * budget, so a future PR that un-splits a route or grows the shell gets
 * caught in CI rather than discovered by profiling a live device.
 */

import { readFileSync, existsSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const distDir = path.join(pkgRoot, 'dist')
const indexHtmlPath = path.join(distDir, 'index.html')

const BUDGET_BYTES = 200 * 1024 // 200 KB gz (AC-2)

if (!existsSync(indexHtmlPath)) {
  console.error(
    `[assert-bundle-budget] ${indexHtmlPath} not found. Run "npm run build" first.`,
  )
  process.exit(1)
}

const html = readFileSync(indexHtmlPath, 'utf8')

// Match `<script ... src="/assets/foo.js">` tags only (module-preload <link>
// tags and the manifest/CSS links are not part of the initial JS payload).
const scriptSrcRe = /<script[^>]*\ssrc="([^"]+\.js)"[^>]*>/g
const initialScripts = [...html.matchAll(scriptSrcRe)].map((m) => m[1])

if (initialScripts.length === 0) {
  console.error('[assert-bundle-budget] No <script src="..."> tags found in dist/index.html.')
  process.exit(1)
}

let totalRawBytes = 0
let totalGzBytes = 0
const rows = []

for (const src of initialScripts) {
  const assetPath = path.join(distDir, src.replace(/^\//, ''))
  if (!existsSync(assetPath)) {
    console.error(`[assert-bundle-budget] Referenced asset missing on disk: ${assetPath}`)
    process.exit(1)
  }
  const raw = readFileSync(assetPath)
  const gz = gzipSync(raw, { level: 9 })
  totalRawBytes += raw.byteLength
  totalGzBytes += gz.byteLength
  rows.push({ src, rawKB: raw.byteLength / 1024, gzKB: gz.byteLength / 1024 })
}

const fmt = (kb) => `${kb.toFixed(2)} KB`

console.log('[assert-bundle-budget] Initial route JS (referenced by dist/index.html):')
for (const row of rows) {
  console.log(`  ${row.src}  raw=${fmt(row.rawKB)}  gz=${fmt(row.gzKB)}`)
}
console.log(
  `[assert-bundle-budget] TOTAL  raw=${fmt(totalRawBytes / 1024)}  gz=${fmt(totalGzBytes / 1024)}  budget=${fmt(BUDGET_BYTES / 1024)}`,
)

if (totalGzBytes > BUDGET_BYTES) {
  console.error(
    `[assert-bundle-budget] FAIL — initial route JS is ${fmt(totalGzBytes / 1024)} gz, over the ${fmt(BUDGET_BYTES / 1024)} gz budget (AC-2). Route-split the new weight with lazyRouteComponent()/React.lazy() or trim the dependency.`,
  )
  process.exit(1)
}

console.log('[assert-bundle-budget] PASS — within AC-2 budget.')
