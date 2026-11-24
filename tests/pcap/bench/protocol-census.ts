/**
 * T13 — Protocol census CLI (local, offline).
 *
 * Usage:
 *   npm run pcap:census -- <file|dir> [...]
 *   npm run pcap:census -- --synthetic
 *
 * Writes JSON + Markdown under tests/pcap/bench/results/ (gitignored).
 */

import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runProtocolCensus } from './protocolCensusRunner.ts'

const outDir = join(dirname(fileURLToPath(import.meta.url)), 'results')

async function main(): Promise<void> {
  const argv = process.argv.slice(2)
  const synthetic = argv.includes('--synthetic')
  const paths = argv.filter((a) => a !== '--synthetic')

  const { report, jsonPath, mdPath } = await runProtocolCensus({
    paths,
    includeSynthetic: synthetic || paths.length === 0,
    outDir,
  })

  console.log(`wrote ${basename(jsonPath)} and ${basename(mdPath)} (${report.rows.length} rows)`)
  if (report.rows[0]) {
    console.log(`top priority: ${report.rows[0]!.key} score=${report.rows[0]!.priorityScore}`)
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err)
  process.exit(1)
})
