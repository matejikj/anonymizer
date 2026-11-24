/**
 * Minimized regression fixtures for PCAP fuzz corpus (Krok 9).
 * Synthetic only — no real capture content.
 */

import { writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = join(dirname(fileURLToPath(import.meta.url)), 'fuzz-corpus')
mkdirSync(dir, { recursive: true })

function write(name: string, bytes: number[]): void {
  writeFileSync(join(dir, name), Buffer.from(bytes))
}

// Empty / tiny
write('empty.bin', [])
write('tiny-3.bin', [0x00, 0x01, 0x02])

// Bad classic magic
write('bad-magic.pcap', [
  0xde, 0xad, 0xbe, 0xef, 0x02, 0x00, 0x04, 0x00,
  0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
])

// Classic header + huge claimed incl_len
{
  const buf = Buffer.alloc(40)
  buf.writeUInt32LE(0xa1b2c3d4, 0)
  buf.writeUInt16LE(2, 4)
  buf.writeUInt16LE(4, 6)
  buf.writeUInt32LE(65535, 16)
  buf.writeUInt32LE(1, 20)
  buf.writeUInt32LE(0x7fffffff, 32) // incl_len
  buf.writeUInt32LE(0x7fffffff, 36)
  writeFileSync(join(dir, 'classic-huge-incl.bin'), buf)
}

// PCAPNG SHB + block claiming max aligned length
{
  const buf = Buffer.alloc(40)
  buf.writeUInt32LE(0x0a0d0d0a, 0)
  buf.writeUInt32LE(28, 4)
  buf.writeUInt32LE(0x1a2b3c4d, 8)
  buf.writeUInt16LE(1, 12)
  buf.writeUInt16LE(0, 14)
  buf.writeBigInt64LE(-1n, 16)
  buf.writeUInt32LE(28, 24)
  buf.writeUInt32LE(1, 28)
  buf.writeUInt32LE(0xfffffffc, 32)
  writeFileSync(join(dir, 'pcapng-huge-block.bin'), buf)
}

// Odd-length option padding trap (SHB only, truncated)
write('pcapng-trunc-shb.bin', [
  0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00,
  0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
])

console.log(`Wrote fuzz corpus to ${dir}`)
