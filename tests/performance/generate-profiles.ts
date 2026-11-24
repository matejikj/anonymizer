/**
 * Node-side profile generator CLI.
 * Writes text + match sidecar JSON (small metadata) under tests/performance/fixtures/.
 *
 * Usage:
 *   npx tsx tests/performance/generate-profiles.ts common
 *   npx tsx tests/performance/generate-profiles.ts maximum
 *   npx tsx tests/performance/generate-profiles.ts all
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  generateProfile,
  PROFILE_SPECS,
  type ProfileKind,
} from './profileGenerator.ts'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const OUT = path.join(__dirname, 'fixtures')

function writeProfile(kind: ProfileKind) {
  console.log(`Generating ${kind}…`)
  const t0 = performance.now()
  const profile = generateProfile(PROFILE_SPECS[kind])
  const ms = performance.now() - t0
  fs.mkdirSync(OUT, { recursive: true })
  const base = path.join(OUT, kind)
  fs.writeFileSync(`${base}.log`, profile.text)
  const meta = {
    kind: profile.kind,
    lineCount: profile.lineCount,
    utf8ByteLength: profile.utf8ByteLength,
    matchCount: profile.matches.length,
    entityCount: profile.entities.length,
    generateMs: ms,
    entities: profile.entities,
    matches: profile.matches,
  }
  fs.writeFileSync(`${base}.meta.json`, JSON.stringify(meta))
  console.log(
    `  lines=${profile.lineCount} utf8MB=${(profile.utf8ByteLength / (1024 * 1024)).toFixed(2)} matches=${profile.matches.length} entities=${profile.entities.length} in ${ms.toFixed(0)}ms`,
  )
  console.log(`  wrote ${base}.log and ${base}.meta.json`)
}

const arg = process.argv[2] ?? 'common'
const kinds: ProfileKind[] =
  arg === 'all'
    ? ['common', 'maximum', 'match-stress', 'long-line-stress']
    : [arg as ProfileKind]

for (const kind of kinds) {
  if (!(kind in PROFILE_SPECS)) {
    console.error(`Unknown profile: ${kind}`)
    process.exit(1)
  }
  writeProfile(kind)
}
