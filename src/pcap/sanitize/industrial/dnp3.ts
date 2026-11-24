/**
 * T30 — DNP3 (TCP/UDP 20000): link addresses map; object dictionary walk; CRC-16 recompute per block.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { maskBytes, readU16le } from './common.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { sanitizeDnp3ApplicationLayer } from './dnp3AppLayer.ts'

export const DNP3_PORT = 20_000

export function isDnp3PortHint(src: number, dst: number): boolean {
  return src === DNP3_PORT || dst === DNP3_PORT
}

export function looksLikeDnp3(buffer: Uint8Array, offset: number, length: number): boolean {
  return length >= 10 && buffer[offset] === 0x05 && buffer[offset + 1] === 0x64
}

/** DNP3 CRC-16 (reflected poly 0xA6BC), init 0, final invert. */
export function dnp3Crc16(data: Uint8Array): number {
  let crc = 0
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]!
    for (let b = 0; b < 8; b++) {
      if (crc & 1) crc = (crc >>> 1) ^ 0xa6bc
      else crc >>>= 1
    }
  }
  return (~crc) & 0xffff
}

function aliasStationU16(mapping: MappingLike, addr: number): number {
  if (addr === 0xffff || addr === 0xfffe) return addr
  const hex = addr.toString(16).padStart(4, '0')
  const canon = canonicalizeIdentity('opaque-id', `dnp3-sta/${hex}`) ?? `dnp3-sta/${hex}`
  const alias = mapping.aliasFor(
    'opaque-id',
    canon,
    { kind: 'text-ascii', byteLength: 4 },
    hex,
  )
  let v = 0
  for (let i = 0; i < alias.length; i++) v = (v * 33 + alias.charCodeAt(i)!) >>> 0
  return (v % 0xfffd) + 1
}

export function sanitizeDnp3(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isDnp3PortHint(srcPort, dstPort) && !looksLikeDnp3(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 10 <= end) {
    if (buffer[pos] !== 0x05 || buffer[pos + 1] !== 0x64) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'dnp3-desync', 'dnp3')
      coverage.push({
        protocol: 'dnp3-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('dnp3-frame-desync')
      break
    }
    const lenField = buffer[pos + 2]!
    coverage.push({ protocol: 'dnp3', offset: pos, length: 4, status: 'covered' })

    const dest = readU16le(buffer, pos + 4)
    const src = readU16le(buffer, pos + 6)
    const destAlias = aliasStationU16(mapping, dest)
    const srcAlias = aliasStationU16(mapping, src)

    const destBytes = new Uint8Array([destAlias & 0xff, (destAlias >>> 8) & 0xff])
    const srcBytes = new Uint8Array([srcAlias & 0xff, (srcAlias >>> 8) & 0xff])
    try {
      collector.add(pos + 4, destBytes)
      collector.add(pos + 6, srcBytes)
    } catch {
      /* overlap */
    }
    intents?.recordEntityReplacement(
      packetIndex,
      pos + 4,
      'opaque-id',
      `dnp3-sta/${dest.toString(16).padStart(4, '0')}`,
      2,
      { kind: 'text-ascii', byteLength: 4 },
      dest.toString(16),
    )
    intents?.recordEntityReplacement(
      packetIndex,
      pos + 6,
      'opaque-id',
      `dnp3-sta/${src.toString(16).padStart(4, '0')}`,
      2,
      { kind: 'text-ascii', byteLength: 4 },
      src.toString(16),
    )
    coverage.push({ protocol: 'dnp3-addr', offset: pos + 4, length: 4, status: 'covered' })

    const hdr = new Uint8Array(8)
    hdr.set(buffer.subarray(pos, pos + 4), 0)
    hdr[4] = destBytes[0]!
    hdr[5] = destBytes[1]!
    hdr[6] = srcBytes[0]!
    hdr[7] = srcBytes[1]!
    const hdrCrc = dnp3Crc16(hdr)
    try {
      collector.add(pos + 8, new Uint8Array([hdrCrc & 0xff, (hdrCrc >>> 8) & 0xff]))
    } catch {
      /* overlap */
    }
    coverage.push({ protocol: 'dnp3', offset: pos + 8, length: 2, status: 'covered' })

    const userDataLen = Math.max(0, lenField - 5)
    const dataPosStart = pos + 10
    if (userDataLen > 0 && dataPosStart + userDataLen <= end) {
      const sanitizedUser = buffer.subarray(dataPosStart, dataPosStart + userDataLen).slice()
      let logicalLen = 0
      let scan = 0
      while (scan < userDataLen) {
        const bytesLeft = userDataLen - scan
        if (bytesLeft <= 2) break
        const blockLen = Math.min(16, bytesLeft - 2)
        logicalLen += blockLen
        scan += blockLen + 2
      }
      if (logicalLen > 0) {
        const app = sanitizeDnp3ApplicationLayer(
          sanitizedUser,
          0,
          logicalLen,
          intents,
          packetIndex,
          dataPosStart,
        )
        coverage.push(...app.coverage)
        issues.push(...app.issues)
      }

      let dataPos = dataPosStart
      let logicalOff = 0
      let consumed = 0
      while (consumed < userDataLen) {
        const bytesLeft = userDataLen - consumed
        if (bytesLeft <= 2) {
          maskBytes(collector, intents, packetIndex, dataPos, bytesLeft, 'dnp3-tail', 'dnp3')
          break
        }
        const chunk = Math.min(16, bytesLeft - 2)
        const tmp = sanitizedUser.subarray(logicalOff, logicalOff + chunk)
        try {
          collector.add(dataPos, tmp)
        } catch {
          /* overlap */
        }
        const crc = dnp3Crc16(tmp)
        try {
          collector.add(dataPos + chunk, new Uint8Array([crc & 0xff, (crc >>> 8) & 0xff]))
        } catch {
          /* overlap */
        }
        coverage.push({ protocol: 'dnp3', offset: dataPos + chunk, length: 2, status: 'covered' })
        dataPos += chunk + 2
        logicalOff += chunk
        consumed += chunk + 2
      }
    } else if (userDataLen > 0) {
      maskBytes(collector, intents, packetIndex, dataPosStart, end - dataPosStart, 'dnp3-tail', 'dnp3')
      coverage.push({
        protocol: 'dnp3-body',
        offset: dataPosStart,
        length: end - dataPosStart,
        status: 'redacted',
      })
    }

    if (!issues.includes('dnp3-process-values-masked')) {
      issues.push('dnp3-process-values-masked')
    }

    const dataWithCrc =
      userDataLen === 0 ? 0 : userDataLen + Math.ceil(userDataLen / 16) * 2
    pos += 10 + dataWithCrc
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'dnp3-session', 'dnp3')
    coverage.push({ protocol: 'dnp3', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}
