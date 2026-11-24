/**
 * Optional tshark oracle for step 10 — soft locally, hard when TSHARK_REQUIRED=1.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const execFileAsync = promisify(execFile)

export interface TsharkExpertSummary {
  readonly available: boolean
  readonly malformed: number
  readonly checksum: number
  readonly error: number
  readonly warn: number
  readonly output: string
}

export function tsharkRequired(): boolean {
  return process.env.TSHARK_REQUIRED === '1' || process.env.TSHARK_REQUIRED === 'true'
}

async function hasTshark(): Promise<boolean> {
  try {
    await execFileAsync('tshark', ['-v'])
    return true
  } catch {
    return false
  }
}

function countMatches(text: string, re: RegExp): number {
  return (text.match(re) ?? []).length
}

export async function summarizeTsharkExpert(buffer: ArrayBuffer, fileName: string): Promise<TsharkExpertSummary> {
  if (!(await hasTshark())) {
    return {
      available: false,
      malformed: 0,
      checksum: 0,
      error: 0,
      warn: 0,
      output: 'tshark not installed',
    }
  }
  const dir = await mkdtemp(join(tmpdir(), 'pcap-tshark-oracle-'))
  const path = join(dir, fileName)
  try {
    await writeFile(path, Buffer.from(buffer))
    const { stdout, stderr } = await execFileAsync(
      'tshark',
      ['-r', path, '-q', '-z', 'expert'],
      { maxBuffer: 8 * 1024 * 1024 },
    )
    const out = `${stdout}\n${stderr}`
    return {
      available: true,
      malformed: countMatches(out, /Malformed/gi),
      checksum: countMatches(out, /Checksum/gi),
      error: countMatches(out, /\bError\b/gi),
      warn: countMatches(out, /\bWarn(?:ing)?\b/gi),
      output: out.slice(0, 6000),
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return {
      available: true,
      malformed: 999,
      checksum: 999,
      error: 999,
      warn: 999,
      output: message.slice(0, 4000),
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

export async function assertNoNewTsharkStructuralErrors(
  original: ArrayBuffer,
  anonymized: ArrayBuffer,
  fileBase = 'diag',
): Promise<{ skipped: boolean; original: TsharkExpertSummary; anonymized: TsharkExpertSummary }> {
  const before = await summarizeTsharkExpert(original, `${fileBase}.orig.pcap`)
  const after = await summarizeTsharkExpert(anonymized, `${fileBase}.anon.pcap`)
  if (!before.available || !after.available) {
    if (tsharkRequired()) {
      throw new Error('TSHARK_REQUIRED=1 but tshark is not available')
    }
    return { skipped: true, original: before, anonymized: after }
  }
  if (after.malformed > before.malformed) {
    throw new Error(
      `tshark malformed increased ${before.malformed}→${after.malformed}\n${after.output}`,
    )
  }
  if (after.checksum > before.checksum) {
    throw new Error(
      `tshark checksum expert items increased ${before.checksum}→${after.checksum}\n${after.output}`,
    )
  }
  if (after.error > before.error) {
    throw new Error(
      `tshark error expert items increased ${before.error}→${after.error}\n${after.output}`,
    )
  }
  return { skipped: false, original: before, anonymized: after }
}
