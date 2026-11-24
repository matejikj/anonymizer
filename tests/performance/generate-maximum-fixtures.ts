/**
 * CLI — generate maximum-size fixtures into a temp directory (never dist/ or git).
 *
 * Usage:
 *   npm run fixtures:maximum
 *   npm run fixtures:maximum -- /tmp/my-fixtures
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  generateMaximumClassicPcap,
  generateMaximumPcapng,
  generateMaximumText,
  MAXIMUM_FIXTURE_TARGETS,
} from './maximumFixtureGenerators.ts'

const outArg = process.argv[2]
const outDir =
  outArg ??
  fs.mkdtempSync(path.join(os.tmpdir(), 'rnd-anonymizer-maximum-'))

fs.mkdirSync(outDir, { recursive: true })

console.log(`Generating maximum fixtures → ${outDir}`)
console.log(
  `Targets: text=${MAXIMUM_FIXTURE_TARGETS.textMiB} MiB, pcap=${MAXIMUM_FIXTURE_TARGETS.pcapMiB} MiB`,
)

const lf = generateMaximumText({ lineEnding: 'lf' })
fs.writeFileSync(path.join(outDir, 'maximum-90mib-lf.log'), lf.text)
console.log(`  maximum-90mib-lf.log: ${lf.byteLength} bytes, ${lf.lineCount} lines`)

const crlf = generateMaximumText({ lineEnding: 'crlf' })
fs.writeFileSync(path.join(outDir, 'maximum-90mib-crlf.log'), crlf.text)
console.log(`  maximum-90mib-crlf.log: ${crlf.byteLength} bytes, ${crlf.lineCount} lines`)

const pcap = generateMaximumClassicPcap()
fs.writeFileSync(path.join(outDir, 'maximum-100mib.pcap'), pcap.buffer)
console.log(`  maximum-100mib.pcap: ${pcap.byteLength} bytes, ${pcap.packetCount} packets`)

const pcapng = generateMaximumPcapng()
fs.writeFileSync(path.join(outDir, 'maximum-100mib.pcapng'), pcapng.buffer)
console.log(`  maximum-100mib.pcapng: ${pcapng.byteLength} bytes, ${pcapng.packetCount} packets`)

const manifest = {
  generatedAt: new Date().toISOString(),
  targets: MAXIMUM_FIXTURE_TARGETS,
  files: [
    { name: 'maximum-90mib-lf.log', bytes: lf.byteLength, canaries: lf.canaryHits.length },
    { name: 'maximum-90mib-crlf.log', bytes: crlf.byteLength, canaries: crlf.canaryHits.length },
    { name: 'maximum-100mib.pcap', bytes: pcap.byteLength, canaries: pcap.canaryTokens.length },
    { name: 'maximum-100mib.pcapng', bytes: pcapng.byteLength, canaries: pcapng.canaryTokens.length },
  ],
}
fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2))
console.log('Done.')
