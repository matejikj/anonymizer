/**
 * STUN / TURN sanitizer (enterprise step 7).
 *
 * Maps XOR-/plain address attributes and USERNAME/REALM; masks NONCE/SOFTWARE/DATA/
 * USERHASH. MESSAGE-INTEGRITY cannot be recomputed without credentials → leave bytes,
 * signal cryptographic_integrity MODIFIED. FINGERPRINT (CRC-32 ⊕ "STUN") is not a secret
 * and is recalculated after attribute rewrites so tshark stays quiet.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { crc32 } from '../recovery/codec/crc32'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'
import { createMaskFill } from './maskFill'
import type { PatchCollector } from './PatchCollector'
import { deferredBinaryMapMeta, deferredPortMapMeta } from './deferredMapMeta.ts'
import type { DeferredPatchMeta } from './types'
import { CRYPTO_INTEGRITY_ISSUE } from '../trust/cryptoIntegrity'
import {
  STUN_ATTR,
  STUN_FINGERPRINT_XOR,
  STUN_HEADER_BYTES,
  STUN_MAGIC_COOKIE,
  isMessageIntegrityAttr,
  isPlainAddressAttr,
  isXorAddressAttr,
  looksLikeStun,
  parseStunHeader,
} from '../protocols/application/stun/classify'

export interface StunSanitizeResult {
  readonly ok: boolean
  readonly hadMessageIntegrity: boolean
  readonly hadFingerprint: boolean
}

type PlannedWrite = {
  readonly relOffset: number
  readonly length: number
  readonly compute: (mapping: MappingLike) => Uint8Array
  readonly mapMeta?: Partial<DeferredPatchMeta>
}

export function sanitizeStun(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): StunSanitizeResult {
  const header = parseStunHeader(buffer, offset, length)
  if (!header) return { ok: false, hadMessageIntegrity: false, hadFingerprint: false }

  const msgEnd = offset + header.messageBytes
  const txnId = header.transactionId
  const planned: PlannedWrite[] = []
  let hadMessageIntegrity = false
  let fingerprintValueAbs = -1
  let fingerprintAttrRelStart = -1

  let pos = offset + STUN_HEADER_BYTES
  while (pos + 4 <= msgEnd) {
    const attrType = (buffer[pos]! << 8) | buffer[pos + 1]!
    const attrLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const valueStart = pos + 4
    const valueEnd = valueStart + attrLen
    const paddedEnd = valueStart + ((attrLen + 3) & ~3)
    if (valueEnd > msgEnd || paddedEnd > msgEnd) {
      maskBody(collector, intents, packetIndex, pos, msgEnd - pos, 'stun-attr-trunc')
      break
    }

    if (isMessageIntegrityAttr(attrType)) {
      hadMessageIntegrity = true
      // Leave HMAC bytes intact — credentials are unavailable; integrity is MODIFIED.
    } else if (attrType === STUN_ATTR.FINGERPRINT && attrLen === 4) {
      fingerprintAttrRelStart = pos - offset
      fingerprintValueAbs = valueStart
    } else if (isXorAddressAttr(attrType)) {
      planXorAddress(
        buffer,
        valueStart,
        attrLen,
        txnId,
        collector,
        intents,
        packetIndex,
        planned,
        offset,
        attrType,
      )
    } else if (isPlainAddressAttr(attrType)) {
      planPlainAddress(
        buffer,
        valueStart,
        attrLen,
        collector,
        intents,
        packetIndex,
        planned,
        offset,
        attrType,
      )
    } else if (attrType === STUN_ATTR.USERNAME && attrLen > 0) {
      planTextAlias(
        buffer,
        valueStart,
        attrLen,
        'sip-user',
        collector,
        intents,
        packetIndex,
        planned,
        offset,
        'stun-username',
      )
    } else if (attrType === STUN_ATTR.REALM && attrLen > 0) {
      planTextAlias(
        buffer,
        valueStart,
        attrLen,
        'hostname',
        collector,
        intents,
        packetIndex,
        planned,
        offset,
        'stun-realm',
      )
    } else if (
      (attrType === STUN_ATTR.NONCE
        || attrType === STUN_ATTR.SOFTWARE
        || attrType === STUN_ATTR.DATA
        || attrType === STUN_ATTR.USERHASH)
      && attrLen > 0
    ) {
      const fill = createMaskFill({
        length: attrLen,
        packetIndex,
        offset: valueStart,
        domain: `stun-attr-${attrType}`,
      })
      intents?.recordMaskRange(packetIndex, valueStart, attrLen, `stun-attr-${attrType}`, 'stun')
      planned.push({
        relOffset: valueStart - offset,
        length: attrLen,
        compute: () => fill,
      })
    }

    pos = paddedEnd
  }

  if (hadMessageIntegrity) {
    issues.push(CRYPTO_INTEGRITY_ISSUE.stunMi)
  }

  // Apply planned entity writes via deferred patches.
  for (const write of planned) {
    const abs = offset + write.relOffset
    try {
      collector.addDeferred(abs, write.length, ({ mapping: live }) => write.compute(live), write.mapMeta)
    } catch {
      /* overlap with prior mask */
    }
  }

  // Recalculate FINGERPRINT after simulated attribute rewrites (RFC 8489 §14.7).
  if (fingerprintValueAbs >= 0 && fingerprintAttrRelStart >= 0) {
    const stunSlice = buffer.subarray(offset, msgEnd)
    const fpRel = fingerprintAttrRelStart
    const writes = planned.slice()
    try {
      collector.addDeferred(fingerprintValueAbs, 4, ({ mapping: live }) => {
        const work = stunSlice.slice()
        for (const w of writes) {
          const bytes = w.compute(live)
          if (bytes.length === w.length) {
            work.set(bytes, w.relOffset)
          }
        }
        const crc = crc32(work.subarray(0, fpRel))
        const fp = (crc ^ STUN_FINGERPRINT_XOR) >>> 0
        return new Uint8Array([
          (fp >>> 24) & 0xff,
          (fp >>> 16) & 0xff,
          (fp >>> 8) & 0xff,
          fp & 0xff,
        ])
      })
    } catch {
      /* overlap */
    }
  }

  return {
    ok: true,
    hadMessageIntegrity,
    hadFingerprint: fingerprintValueAbs >= 0,
  }
}

export { looksLikeStun }

function planXorAddress(
  buffer: Uint8Array,
  valueStart: number,
  attrLen: number,
  txnId: Uint8Array,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  planned: PlannedWrite[],
  msgOffset: number,
  attrType: number,
): void {
  if (attrLen < 8) return
  const family = buffer[valueStart + 1]!
  const xPort = (buffer[valueStart + 2]! << 8) | buffer[valueStart + 3]!
  const port = (xPort ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff

  if (family === 0x01 && attrLen >= 8) {
    const xAddr = buffer.subarray(valueStart + 4, valueStart + 8)
    const ipBytes = xorIpv4(xAddr)
    const ip = `${ipBytes[0]}.${ipBytes[1]}.${ipBytes[2]}.${ipBytes[3]}`
    const relPort = valueStart + 2 - msgOffset
    const relAddr = valueStart + 4 - msgOffset

    intents?.recordEntityReplacement(packetIndex, valueStart + 4, 'ipv4', ip, 4)
    intents?.recordEntityReplacement(packetIndex, valueStart + 2, 'port', `udp/${port}`, 2)

    planned.push({
      relOffset: relPort,
      length: 2,
      compute: (live) => {
        const mappedPort = Number(String(live.map('port', `udp/${port}`)).replace(/^udp\//, '')) & 0xffff
        const x = (mappedPort ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff
        return new Uint8Array([(x >>> 8) & 0xff, x & 0xff])
      },
      mapMeta: deferredPortMapMeta('stun', packetIndex, 'udp', port),
    })
    planned.push({
      relOffset: relAddr,
      length: 4,
      compute: (live) => {
        const mapped = live.map('ipv4', ip)
        const parts = mapped.split('.').map(Number)
        const plain = new Uint8Array([parts[0]!, parts[1]!, parts[2]!, parts[3]!])
        return xorIpv4(plain)
      },
      mapMeta: deferredBinaryMapMeta('stun', packetIndex, 'ipv4', ip),
    })
    void collector
    void attrType
    return
  }

  if (family === 0x02 && attrLen >= 20) {
    const xAddr = buffer.subarray(valueStart + 4, valueStart + 20)
    const ipBytes = xorIpv6(xAddr, txnId)
    const ip = ipv6Bytes16ToText(ipBytes, 0)
    const relPort = valueStart + 2 - msgOffset
    const relAddr = valueStart + 4 - msgOffset

    intents?.recordEntityReplacement(packetIndex, valueStart + 4, 'ipv6', ip, 16)
    intents?.recordEntityReplacement(packetIndex, valueStart + 2, 'port', `udp/${port}`, 2)

    planned.push({
      relOffset: relPort,
      length: 2,
      compute: (live) => {
        const mappedPort = Number(String(live.map('port', `udp/${port}`)).replace(/^udp\//, '')) & 0xffff
        const x = (mappedPort ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff
        return new Uint8Array([(x >>> 8) & 0xff, x & 0xff])
      },
      mapMeta: deferredPortMapMeta('stun', packetIndex, 'udp', port),
    })
    planned.push({
      relOffset: relAddr,
      length: 16,
      compute: (live) => {
        const mapped = live.map('ipv6', ip)
        const plain = ipv6TextToBytes16(mapped) ?? new Uint8Array(16)
        return xorIpv6(plain, txnId)
      },
      mapMeta: deferredBinaryMapMeta('stun', packetIndex, 'ipv6', ip),
    })
  }
}

function planPlainAddress(
  buffer: Uint8Array,
  valueStart: number,
  attrLen: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  planned: PlannedWrite[],
  msgOffset: number,
  attrType: number,
): void {
  if (attrLen < 8) return
  const family = buffer[valueStart + 1]!
  const port = (buffer[valueStart + 2]! << 8) | buffer[valueStart + 3]!

  if (family === 0x01 && attrLen >= 8) {
    const ip = `${buffer[valueStart + 4]}.${buffer[valueStart + 5]}.${buffer[valueStart + 6]}.${buffer[valueStart + 7]}`
    const relPort = valueStart + 2 - msgOffset
    const relAddr = valueStart + 4 - msgOffset
    intents?.recordEntityReplacement(packetIndex, valueStart + 4, 'ipv4', ip, 4)
    intents?.recordEntityReplacement(packetIndex, valueStart + 2, 'port', `udp/${port}`, 2)
    planned.push({
      relOffset: relPort,
      length: 2,
      compute: (live) => {
        const mappedPort = Number(String(live.map('port', `udp/${port}`)).replace(/^udp\//, '')) & 0xffff
        return new Uint8Array([(mappedPort >>> 8) & 0xff, mappedPort & 0xff])
      },
      mapMeta: deferredPortMapMeta('stun', packetIndex, 'udp', port),
    })
    planned.push({
      relOffset: relAddr,
      length: 4,
      compute: (live) => {
        const mapped = live.map('ipv4', ip)
        return new Uint8Array(mapped.split('.').map(Number))
      },
      mapMeta: deferredBinaryMapMeta('stun', packetIndex, 'ipv4', ip),
    })
    void collector
    void attrType
    return
  }

  if (family === 0x02 && attrLen >= 20) {
    const ip = ipv6Bytes16ToText(buffer, valueStart + 4)
    const relPort = valueStart + 2 - msgOffset
    const relAddr = valueStart + 4 - msgOffset
    intents?.recordEntityReplacement(packetIndex, valueStart + 4, 'ipv6', ip, 16)
    intents?.recordEntityReplacement(packetIndex, valueStart + 2, 'port', `udp/${port}`, 2)
    planned.push({
      relOffset: relPort,
      length: 2,
      compute: (live) => {
        const mappedPort = Number(String(live.map('port', `udp/${port}`)).replace(/^udp\//, '')) & 0xffff
        return new Uint8Array([(mappedPort >>> 8) & 0xff, mappedPort & 0xff])
      },
      mapMeta: deferredPortMapMeta('stun', packetIndex, 'udp', port),
    })
    planned.push({
      relOffset: relAddr,
      length: 16,
      compute: (live) => ipv6TextToBytes16(live.map('ipv6', ip)) ?? new Uint8Array(16),
      mapMeta: deferredBinaryMapMeta('stun', packetIndex, 'ipv6', ip),
    })
  }
}

function planTextAlias(
  buffer: Uint8Array,
  valueStart: number,
  attrLen: number,
  category: 'sip-user' | 'hostname',
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  planned: PlannedWrite[],
  msgOffset: number,
  domain: string,
): void {
  const text = String.fromCharCode(...buffer.subarray(valueStart, valueStart + attrLen))
  intents?.recordEntityReplacement(packetIndex, valueStart, category, text, attrLen)
  const rel = valueStart - msgOffset
  planned.push({
    relOffset: rel,
    length: attrLen,
    compute: (live) => {
      const alias = live.aliasFor(
        category,
        text,
        { kind: 'text-ascii', byteLength: attrLen },
        text,
      )
      const out = new Uint8Array(attrLen)
      for (let i = 0; i < attrLen; i++) {
        out[i] = i < alias.length ? alias.charCodeAt(i) & 0xff : 0x2d
      }
      return out
    },
  })
  void collector
  void domain
}

function xorIpv4(xAddr: Uint8Array): Uint8Array {
  return new Uint8Array([
    xAddr[0]! ^ ((STUN_MAGIC_COOKIE >>> 24) & 0xff),
    xAddr[1]! ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xff),
    xAddr[2]! ^ ((STUN_MAGIC_COOKIE >>> 8) & 0xff),
    xAddr[3]! ^ (STUN_MAGIC_COOKIE & 0xff),
  ])
}

function xorIpv6(xAddr: Uint8Array, txnId: Uint8Array): Uint8Array {
  const out = new Uint8Array(16)
  const key = new Uint8Array(16)
  key[0] = (STUN_MAGIC_COOKIE >>> 24) & 0xff
  key[1] = (STUN_MAGIC_COOKIE >>> 16) & 0xff
  key[2] = (STUN_MAGIC_COOKIE >>> 8) & 0xff
  key[3] = STUN_MAGIC_COOKIE & 0xff
  key.set(txnId.subarray(0, 12), 4)
  for (let i = 0; i < 16; i++) out[i] = xAddr[i]! ^ key[i]!
  return out
}

function maskBody(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'stun')
}
