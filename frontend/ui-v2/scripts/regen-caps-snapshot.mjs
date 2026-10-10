#!/usr/bin/env node
// DVP-TSK-860: regenerate src/shell/capsSnapshot.json from the committed MCP
// caps manifest (the actions.schemas discovery output, DVP-TSK-843). Reads a
// local file only: CI never calls prod. Usage:
//   node scripts/regen-caps-snapshot.mjs [path/to/caps.json]
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const src = process.argv[2] ?? path.resolve(root, '../../tools/enceladus-mcp-server/parity/caps.json')
const caps = JSON.parse(readFileSync(src, 'utf8'))
const snapshot = {
  schemaVersion: caps.schemaVersion,
  surface: caps.surface,
  actions: caps.actions.map((a) => ({
    name: a.name,
    title: a.title,
    annotations: { readOnlyHint: Boolean(a.annotations?.readOnlyHint) },
    ...(a.via ? { via: a.via } : {}),
  })),
}
writeFileSync(path.join(root, 'src/shell/capsSnapshot.json'), JSON.stringify(snapshot) + '\n')
console.log(`wrote ${snapshot.actions.length} actions from ${src}`)
