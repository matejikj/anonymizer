/**
 * Validate protocol support matrix conformance.
 * Matrix source of truth: src/pcap/docs/protocolSupportMatrix.ts
 * (validates conformance only — no generated markdown dump in the public tree).
 * Usage: npx tsx scripts/generate-protocol-matrix.ts
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildProtocolSupportMatrix } from '../src/pcap/docs/protocolSupportMatrix.ts'
import { collectMatrixConformanceViolations } from '../src/pcap/docs/protocolMatrixVariantConformance.ts'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function main(): void {
  const violations = collectMatrixConformanceViolations(root, (p) => fs.readFileSync(p, 'utf8'))
  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`T32 conformance: ${v.handlerId}: ${v.message}`)
    }
    process.exit(1)
  }

  const rows = buildProtocolSupportMatrix()
  console.log(`protocol support matrix OK (${rows.length} rows)`)
}

main()
