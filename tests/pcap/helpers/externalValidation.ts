/**
 * External capture validation for CI / Node tests — TShark/capinfos when installed.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const execFileAsync = promisify(execFile)

export interface ExternalValidationResult {
  readonly available: boolean
  readonly tool: 'tshark' | 'capinfos' | null
  readonly valid: boolean | null
  readonly output: string
}

async function toolAvailable(name: string): Promise<boolean> {
  try {
    await execFileAsync(name, ['-v'])
    return true
  } catch {
    return false
  }
}

export async function validateCaptureWithTshark(
  buffer: ArrayBuffer,
  fileName = 'capture.anonymized.pcap',
): Promise<ExternalValidationResult> {
  const hasTshark = await toolAvailable('tshark')
  if (!hasTshark) {
    const hasCapinfos = await toolAvailable('capinfos')
    if (!hasCapinfos) {
      return { available: false, tool: null, valid: null, output: 'tshark/capinfos not installed' }
    }
    return validateWithCapinfos(buffer, fileName)
  }

  const dir = await mkdtemp(join(tmpdir(), 'pcap-ext-val-'))
  const path = join(dir, fileName)
  try {
    await writeFile(path, Buffer.from(buffer))
    const { stdout, stderr } = await execFileAsync('tshark', ['-r', path, '-q', '-z', 'io,stat,0'], {
      maxBuffer: 4 * 1024 * 1024,
    })
    const out = `${stdout}\n${stderr}`.trim()
    const valid = !/error|invalid|couldn't|could not/i.test(out)
    return { available: true, tool: 'tshark', valid, output: out.slice(0, 4000) }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { available: true, tool: 'tshark', valid: false, output: message.slice(0, 4000) }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

async function validateWithCapinfos(buffer: ArrayBuffer, fileName: string): Promise<ExternalValidationResult> {
  const dir = await mkdtemp(join(tmpdir(), 'pcap-ext-val-'))
  const path = join(dir, fileName)
  try {
    await writeFile(path, Buffer.from(buffer))
    const { stdout, stderr } = await execFileAsync('capinfos', [path], { maxBuffer: 1024 * 1024 })
    const out = `${stdout}\n${stderr}`.trim()
    return {
      available: true,
      tool: 'capinfos',
      valid: out.length > 0 && !/error/i.test(out),
      output: out.slice(0, 4000),
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { available: true, tool: 'capinfos', valid: false, output: message.slice(0, 4000) }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}
