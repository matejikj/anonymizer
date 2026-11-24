/**
 * Deterministic maximum-size fixture generators for Stage 0 release gates.
 * Never writes into dist/ or commits large binaries — callers use temp dirs or runtime buffers.
 */

import {
  BYTES_PER_MIB,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
  TEXT_INPUT_LIMITS,
} from '../../src/domain/capabilityContract.ts'
import { createPrng } from './profileGenerator.ts'

export type LineEndingKind = 'lf' | 'crlf' | 'cr'

/** Canary tokens covered by builtins and rnd-team-production custom rules. */
export const MAX_FIXTURE_TEXT_CANARIES = {
  /** One line per builtin category. */
  builtin: [
    'peer=10.99.88.77',
    'host=canary-host.stage0.example.invalid',
    'email=canary.stage0@corp.example.invalid',
    'sip:9720998877@gw-stage0.example.invalid',
    'operator=Stage0 Canary Person',
    'user=disp9999',
    'tenant=MP_STAGE0',
  ],
  /** Extra tokens from production profile regexes. */
  productionProfile: [
    'mac=00:1A:2B:3C:4D:5E',
    'uuid=550e8400-e29b-41d4-a716-446655440000',
    'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.stage0.canary',
    'password=Stage0Secret!',
    'api_key=sk-baseline-canary-not-real',
    'url=https://internal-stage0.example.invalid/path',
    'path=/var/log/stage0/canary/app.log',
  ],
} as const

export const MAX_FIXTURE_PCAP_CANARIES = {
  ipv4Src: '10.88.99.77',
  ipv4Dst: '192.168.77.88',
  hostname: 'pcap-canary.stage0.example.invalid',
  dnsQuery: 'secret-dns-canary.stage0.example.invalid',
  metadataHost: 'SECRET_HOST.stage0.internal',
  tlsSecret: 'TLS_MASTER_SECRET_STAGE0_CANARY',
  interfaceUser: 'interface_stats_user_stage0',
} as const

export interface MaximumTextFixture {
  readonly kind: 'maximum-lf' | 'maximum-crlf'
  readonly text: string
  readonly byteLength: number
  readonly lineEnding: LineEndingKind
  readonly lineCount: number
  readonly canaryHits: readonly string[]
}

export interface MaximumPcapFixture {
  readonly kind: 'maximum-classic-pcap' | 'maximum-pcapng'
  readonly buffer: Uint8Array
  readonly byteLength: number
  readonly packetCount: number
  readonly canaryTokens: readonly string[]
}

function lineEndingBytes(kind: LineEndingKind): string {
  switch (kind) {
    case 'lf':
      return '\n'
    case 'crlf':
      return '\r\n'
    case 'cr':
      return '\r'
  }
}

function utf8Len(text: string): number {
  return new TextEncoder().encode(text).length
}

/**
 * Build a text fixture targeting exactly `targetBytes` UTF-8 bytes (ASCII-only content).
 * Inserts Stage 0 canaries on dedicated lines near the start.
 */
export function generateMaximumText(options: {
  targetBytes?: number
  lineEnding?: LineEndingKind
  seed?: number
} = {}): MaximumTextFixture {
  const targetBytes = options.targetBytes ?? MAX_TEXT_FILE_BYTES
  const lineEnding = options.lineEnding ?? 'lf'
  const eol = lineEndingBytes(lineEnding)
  const eolBytes = eol.length
  const rand = createPrng(options.seed ?? 0xa0e00001)

  const canaryLines = [
    '# baseline-canary-block',
    ...MAX_FIXTURE_TEXT_CANARIES.builtin.map((t) => `CANARY builtin ${t}`),
    ...MAX_FIXTURE_TEXT_CANARIES.productionProfile.map((t) => `CANARY profile ${t}`),
  ]

  let usedBytes = 0
  for (const line of canaryLines) {
    usedBytes += line.length + eolBytes
  }

  const maxFileLines = TEXT_INPUT_LIMITS.fileMaxLines
  const maxFillerLines = Math.max(1, maxFileLines - canaryLines.length - 1)
  const bytesBudgetForFillers = Math.max(0, targetBytes - usedBytes)
  const minLineBytes = Math.ceil(bytesBudgetForFillers / maxFillerLines)
  const buildFillerLine = (seq: number, targetLineBytes: number): string => {
    const head = `2026-08-22T12:00:00.000Z [INFO] stage0 seq=${String(seq).padStart(8, '0')} n=${String(Math.floor(rand() * 1_000_000)).padStart(7, '0')} `
    const padLen = Math.max(0, targetLineBytes - head.length - eolBytes)
    return head + 'x'.repeat(padLen) + eol
  }

  let lineBytes = buildFillerLine(0, minLineBytes).length
  if (lineBytes > TEXT_INPUT_LIMITS.oversizedLineBytes) {
    throw new Error(
      `maximum text fixture needs ${lineBytes} bytes/line but oversizedLineBytes=${TEXT_INPUT_LIMITS.oversizedLineBytes}`,
    )
  }

  const parts: string[] = []
  for (const line of canaryLines) {
    parts.push(line + eol)
  }

  let seq = 0
  while (usedBytes + lineBytes <= targetBytes && seq < maxFillerLines) {
    parts.push(buildFillerLine(seq, minLineBytes))
    usedBytes += lineBytes
    seq++
  }

  const remaining = targetBytes - usedBytes
  if (remaining > 0) {
    const head = `${`2026-08-22T12:00:00.000Z [INFO] stage0 pad seq=${String(seq).padStart(8, '0')} `}`
    const padLen = Math.max(0, remaining - head.length)
    parts.push(head + 'x'.repeat(padLen))
    usedBytes += remaining
  }

  let text = parts.join('')
  if (text.length !== targetBytes) {
    if (text.length > targetBytes) {
      text = text.slice(0, targetBytes)
    } else {
      text = text + 'x'.repeat(targetBytes - text.length)
    }
  }
  const byteLength = targetBytes

  const lineCount =
    canaryLines.length +
    seq +
    (remaining > 0 ? 1 : 0)

  return {
    kind: lineEnding === 'crlf' ? 'maximum-crlf' : 'maximum-lf',
    text,
    byteLength,
    lineEnding,
    lineCount,
    canaryHits: [
      ...MAX_FIXTURE_TEXT_CANARIES.builtin,
      ...MAX_FIXTURE_TEXT_CANARIES.productionProfile,
    ],
  }
}

function writeU32LE(buf: Uint8Array, offset: number, val: number): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  view.setUint32(offset, val >>> 0, true)
}

function writeU16LE(buf: Uint8Array, offset: number, val: number): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  view.setUint16(offset, val & 0xffff, true)
}

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((a, c) => a + c.byteLength, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.byteLength
  }
  return out
}

/** Build one synthetic Ethernet/IPv4/UDP packet embedding optional canary IPv4 octets. */
function buildUdpPacket(i: number, payloadSize: number, canary: boolean): Uint8Array {
  const packetSize = 14 + 20 + 8 + Math.max(payloadSize, 8)
  const packet = new Uint8Array(packetSize)
  packet[12] = 0x08
  packet[13] = 0x00
  packet[14] = 0x45
  packet[14 + 9] = 17
  const ipOff = 14
  if (canary && i % 500 === 0) {
    const parts = MAX_FIXTURE_PCAP_CANARIES.ipv4Src.split('.').map(Number)
    packet[ipOff + 12] = parts[0]!
    packet[ipOff + 13] = parts[1]!
    packet[ipOff + 14] = parts[2]!
    packet[ipOff + 15] = parts[3]!
  } else {
    packet[ipOff + 12] = 10
    packet[ipOff + 13] = (i >> 8) & 0xff
    packet[ipOff + 14] = i & 0xff
    packet[ipOff + 15] = (i * 3) & 0xff
  }
  packet[ipOff + 16] = 192
  packet[ipOff + 17] = 168
  packet[ipOff + 18] = 1
  packet[ipOff + 19] = i & 0xff
  const udpOff = ipOff + 20
  packet[udpOff + 2] = 0x13
  packet[udpOff + 3] = 0xc4 // 5060
  for (let j = udpOff + 8; j < packetSize; j++) {
    packet[j] = (i + j) & 0xff
  }
  return packet
}

function classicPcapRecord(packet: Uint8Array, tsSec: number, tsFrac: number): Uint8Array {
  const hdr = new Uint8Array(16)
  writeU32LE(hdr, 0, tsSec)
  writeU32LE(hdr, 4, tsFrac)
  writeU32LE(hdr, 8, packet.byteLength)
  writeU32LE(hdr, 12, packet.byteLength)
  return concatChunks([hdr, packet])
}

/** Grow classic PCAP until byteLength is exactly targetBytes (padding last record if needed). */
export function generateMaximumClassicPcap(options: {
  targetBytes?: number
} = {}): MaximumPcapFixture {
  const targetBytes = options.targetBytes ?? MAX_PCAP_FILE_BYTES
  const globalHeader = new Uint8Array(24)
  writeU32LE(globalHeader, 0, 0xa1b2c3d4)
  writeU16LE(globalHeader, 4, 2)
  writeU16LE(globalHeader, 6, 4)
  writeU32LE(globalHeader, 16, 262144)
  writeU32LE(globalHeader, 20, 1)

  const chunks: Uint8Array[] = [globalHeader]
  let size = globalHeader.byteLength
  let i = 0
  let tsSec = 1_700_000_000
  let tsFrac = 0
  const avgPayload = 380

  while (size + 16 + 14 + 20 + 8 + avgPayload < targetBytes) {
    const pkt = buildUdpPacket(i, avgPayload + (i % 17), i % 1000 === 0)
    const rec = classicPcapRecord(pkt, tsSec, tsFrac)
    chunks.push(rec)
    size += rec.byteLength
    i++
    tsFrac += 800
    if (tsFrac >= 1_000_000) {
      tsFrac = 0
      tsSec++
    }
  }

  const remaining = targetBytes - size - 16
  if (remaining > 14 + 20 + 8) {
    const pkt = buildUdpPacket(i, remaining - 14 - 20 - 8, true)
    chunks.push(classicPcapRecord(pkt, tsSec, tsFrac))
    size += 16 + pkt.byteLength
  }

  let buffer = concatChunks(chunks)
  if (buffer.byteLength !== targetBytes) {
    // Exact pad/truncate tail — prefer truncate for safety.
    buffer = buffer.slice(0, targetBytes)
  }

  return {
    kind: 'maximum-classic-pcap',
    buffer,
    byteLength: targetBytes,
    packetCount: i + 1,
    canaryTokens: Object.values(MAX_FIXTURE_PCAP_CANARIES),
  }
}

function pcapngBlock(type: number, body: Uint8Array): Uint8Array {
  const padded = (body.byteLength + 3) & ~3
  const total = 12 + padded
  const block = new Uint8Array(total)
  writeU32LE(block, 0, type)
  writeU32LE(block, 4, total)
  block.set(body, 8)
  writeU32LE(block, total - 4, total)
  return block
}

function textOption(code: number, text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text)
  const padded = (4 + bytes.byteLength + 3) & ~3
  const opt = new Uint8Array(padded)
  writeU16LE(opt, 0, code)
  writeU16LE(opt, 2, bytes.byteLength)
  opt.set(bytes, 4)
  return opt
}

/** PCAPNG with two sections, two interfaces, metadata canaries and EPBs. */
export function generateMaximumPcapng(options: {
  targetBytes?: number
} = {}): MaximumPcapFixture {
  const targetBytes = options.targetBytes ?? MAX_PCAP_FILE_BYTES
  const chunks: Uint8Array[] = []

  // Section 1 — LE (SHB must be 28 bytes: BOM + ver + section_length=-1)
  {
    const shbBody = new Uint8Array(16)
    writeU32LE(shbBody, 0, 0x1a2b3c4d)
    writeU16LE(shbBody, 4, 1)
    writeU16LE(shbBody, 6, 0)
    writeU32LE(shbBody, 8, 0xffffffff)
    writeU32LE(shbBody, 12, 0xffffffff)
    chunks.push(pcapngBlock(0x0a0d0d0a, shbBody))

    const ifName = textOption(2, `eth0-${MAX_FIXTURE_PCAP_CANARIES.hostname}`)
    const endOpt = new Uint8Array(4) // opt_endofopt
    const idbBody = new Uint8Array(8 + ifName.byteLength + endOpt.byteLength)
    writeU16LE(idbBody, 0, 1)
    writeU16LE(idbBody, 2, 0)
    writeU32LE(idbBody, 4, 262144)
    idbBody.set(ifName, 8)
    idbBody.set(endOpt, 8 + ifName.byteLength)
    chunks.push(pcapngBlock(0x00000001, idbBody))

    // Minimal valid NRB (type/len/trailing only) — canary sits in if_name / EPB payloads.
    chunks.push(pcapngBlock(0x00000004, new Uint8Array(0)))
  }

  let ts = 0n
  let packets = 0
  let size = chunks.reduce((a, c) => a + c.byteLength, 0)

  while (size + 64 < targetBytes - 4096) {
    const payload = buildUdpPacket(packets, 320 + (packets % 40), packets % 777 === 0)
    const padded = (payload.byteLength + 3) & ~3
    const epbBody = new Uint8Array(20 + padded)
    writeU32LE(epbBody, 0, 0)
    writeU32LE(epbBody, 4, Number((ts >> 32n) & 0xffffffffn))
    writeU32LE(epbBody, 8, Number(ts & 0xffffffffn))
    writeU32LE(epbBody, 12, payload.byteLength)
    writeU32LE(epbBody, 16, payload.byteLength)
    epbBody.set(payload, 20)
    const epb = pcapngBlock(0x00000006, epbBody)
    chunks.push(epb)
    size += epb.byteLength
    packets++
    ts += 1200n
  }

  // Section 2 — different interface (valid SHB/IDB; secrets only in reviewed option form)
  {
    const shbBody = new Uint8Array(16)
    writeU32LE(shbBody, 0, 0x1a2b3c4d)
    writeU16LE(shbBody, 4, 1)
    writeU16LE(shbBody, 6, 0)
    writeU32LE(shbBody, 8, 0xffffffff)
    writeU32LE(shbBody, 12, 0xffffffff)
    chunks.push(pcapngBlock(0x0a0d0d0a, shbBody))

    const ifName = textOption(2, `wlan1-${MAX_FIXTURE_PCAP_CANARIES.interfaceUser}`)
    const endOpt = new Uint8Array(4)
    const idbBody = new Uint8Array(8 + ifName.byteLength + endOpt.byteLength)
    writeU16LE(idbBody, 0, 1)
    writeU16LE(idbBody, 2, 0)
    writeU32LE(idbBody, 4, 65535)
    idbBody.set(ifName, 8)
    idbBody.set(endOpt, 8 + ifName.byteLength)
    chunks.push(pcapngBlock(0x00000001, idbBody))
  }

  while (size < targetBytes) {
    const payload = buildUdpPacket(packets, 280, false)
    const padded = (payload.byteLength + 3) & ~3
    const epbBody = new Uint8Array(20 + padded)
    // Interface IDs restart per section — section 2's sole IDB is index 0.
    writeU32LE(epbBody, 0, 0)
    writeU32LE(epbBody, 12, payload.byteLength)
    writeU32LE(epbBody, 16, payload.byteLength)
    epbBody.set(payload, 20)
    const epb = pcapngBlock(0x00000006, epbBody)
    if (size + epb.byteLength > targetBytes) break
    chunks.push(epb)
    size += epb.byteLength
    packets++
  }

  // Never mid-block truncate/zero-pad — that yields an unreadable PCAPNG (0 packets).
  while (chunks.length > 0) {
    const total = chunks.reduce((a, c) => a + c.byteLength, 0)
    if (total <= targetBytes) break
    const removed = chunks.pop()!
    if (removed[0] === 0x06 && removed[1] === 0x00 && removed[2] === 0x00 && removed[3] === 0x00) {
      packets = Math.max(0, packets - 1)
    }
  }
  let buffer = concatChunks(chunks)
  if (buffer.byteLength < targetBytes) {
    const remaining = targetBytes - buffer.byteLength
    // Valid Custom block (0x00000bad) filler — body length chosen so total block == remaining.
    if (remaining >= 12 && (remaining - 12) % 4 === 0) {
      buffer = concatChunks([buffer, pcapngBlock(0x00000bad, new Uint8Array(remaining - 12))])
    }
  }

  return {
    kind: 'maximum-pcapng',
    buffer,
    byteLength: buffer.byteLength,
    packetCount: packets,
    canaryTokens: Object.values(MAX_FIXTURE_PCAP_CANARIES),
  }
}

/** Micro-sized generators for fast unit tests (same shape, tiny targets). */
export function generateMicroText(targetBytes: number, lineEnding: LineEndingKind = 'lf'): MaximumTextFixture {
  return generateMaximumText({ targetBytes, lineEnding, seed: 0xa0e00002 })
}

export function generateMicroClassicPcap(targetBytes: number): MaximumPcapFixture {
  return generateMaximumClassicPcap({ targetBytes })
}

export function generateMicroPcapng(targetBytes: number): MaximumPcapFixture {
  return generateMaximumPcapng({ targetBytes })
}

export const MAXIMUM_FIXTURE_TARGETS = {
  textBytes: MAX_TEXT_FILE_BYTES,
  textMiB: MAX_TEXT_FILE_BYTES / BYTES_PER_MIB,
  pcapBytes: MAX_PCAP_FILE_BYTES,
  pcapMiB: MAX_PCAP_FILE_BYTES / BYTES_PER_MIB,
} as const
