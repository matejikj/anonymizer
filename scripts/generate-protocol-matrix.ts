/**
 * Regenerates the in-memory protocol support matrix markdown helper.
 * Construction-time ANONYMIZER.md / docs overview injection was removed for the public tree;
 * this script now validates that the matrix renderer still works and prints a short summary.
 */
import {
  buildProtocolSupportMatrix,
  renderProtocolSupportMatrixMarkdown,
} from '../src/pcap/docs/protocolSupportMatrix.ts'

const rows = buildProtocolSupportMatrix()
const markdown = renderProtocolSupportMatrixMarkdown(rows)
if (!markdown.includes('|') || rows.length === 0) {
  console.error('protocol support matrix render failed')
  process.exit(1)
}
console.log(`protocol support matrix ok: ${rows.length} rows (docs injection disabled)`)
