/**
 * Generate max-size release fixtures into tests/performance/fixtures/max-size/
 * Usage: npm run fixtures:max-size
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  generateMaximumClassicPcap,
  generateMaximumPcapng,
  generateMaximumText,
  MAXIMUM_FIXTURE_TARGETS,
} from './maximumFixtureGenerators.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const outDir = process.env.MAX_SIZE_FIXTURE_DIR
  ? path.resolve(process.env.MAX_SIZE_FIXTURE_DIR)
  : path.join(here, 'fixtures/max-size')

fs.mkdirSync(outDir, { recursive: true })

console.log(`Max-size fixtures → ${outDir}`)
console.log(`Targets: text=${MAXIMUM_FIXTURE_TARGETS.textMiB} MiB, pcap=${MAXIMUM_FIXTURE_TARGETS.pcapMiB} MiB`)

const lf = generateMaximumText({ lineEnding: 'lf' })
fs.writeFileSync(path.join(outDir, 'maximum-90mib-lf.log'), lf.text)
console.log(`  maximum-90mib-lf.log: ${lf.byteLength} bytes`)

const crlf = generateMaximumText({ lineEnding: 'crlf' })
fs.writeFileSync(path.join(outDir, 'maximum-90mib-crlf.log'), crlf.text)
console.log(`  maximum-90mib-crlf.log: ${crlf.byteLength} bytes`)

const pcap = generateMaximumClassicPcap()
fs.writeFileSync(path.join(outDir, 'maximum-100mib.pcap'), pcap.buffer)
console.log(`  maximum-100mib.pcap: ${pcap.byteLength} bytes`)

const pcapng = generateMaximumPcapng()
fs.writeFileSync(path.join(outDir, 'maximum-100mib.pcapng'), pcapng.buffer)
console.log(`  maximum-100mib.pcapng: ${pcapng.byteLength} bytes`)

fs.writeFileSync(
  path.join(outDir, 'manifest.json'),
  JSON.stringify({ generatedAt: new Date().toISOString(), targets: MAXIMUM_FIXTURE_TARGETS }, null, 2),
)
console.log('Done.')
