/**
 * T59 — NAS EPS/5GS sanitizer: identities map, auth/location/PCO mask,
 * ciphered payloads opaque; plain/integrity-only structured walk.
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import {
  looksLikeNas,
  parseNasFrame,
  EPS_EMM_MSG,
  EPS_ESM_MSG,
  G5MM_MSG,
  G5SM_MSG,
  parseMobileIdentityValue,
  normalizeIdentityDigits,
  remapMobileIdentityDigits,
  classifySuciValue,
  type NasFrame,
} from '../protocols/nas/index.ts'

export { looksLikeNas, looksLikeNasEps, looksLikeNas5gs } from '../protocols/nas/index.ts'

/** Optional IEI (TLV-E / TLV) used in baseline plaintext messages. */
const IEI = {
  MOBILE_IDENTITY: 0x23,
  EPS_MOBILE_IDENTITY: 0x50, // Attach Accept GUTI etc. (TLV-E in some msgs — also LV)
  TAI_LIST: 0x54,
  TAI: 0x53,
  APN: 0x28,
  PCO: 0x27,
  EPCO: 0x7b,
  DNN: 0x25,
  '5GS_MOBILE_IDENTITY': 0x77,
  '5GS_TRACKING_AREA_ID': 0x54,
  NAS_MESSAGE_CONTAINER: 0x71,
  EAP_MESSAGE: 0x78,
} as const

export function sanitizeNas(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  opts?: { readonly nullCipher?: boolean },
): AppLayerResult | null {
  if (!looksLikeNas(buffer, offset, length)) return null
  const frame = parseNasFrame(buffer, offset, length, opts)
  if (!frame) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = [...frame.issues]
  const proto = familyProto(frame)

  coverage.push({
    protocol: proto,
    offset: frame.headerSpan.offset,
    length: frame.headerSpan.length,
    status: 'covered',
  })

  if (frame.security === 'ciphered' || frame.security === 'unknown') {
    maskRange(
      collector,
      intents,
      packetIndex,
      frame.messageOffset,
      frame.messageLength,
      'nas-ciphered',
    )
    coverage.push({
      protocol: 'nas-ciphered',
      offset: frame.messageOffset,
      length: frame.messageLength,
      status: 'redacted',
    })
    issues.push(
      frame.security === 'unknown' ? 'nas-security-unknown-masked' : 'nas-ciphered-opaque',
    )
    // MAC always invalidated after any change — mask MAC bytes in protected header
    maskMacIfPresent(buffer, frame, collector, intents, packetIndex, coverage)
    coverage.push({ protocol: proto, offset, length, status: 'covered' })
    return { coverage, issues }
  }

  // plain | integrity-only | ciphered-null → structured
  if (frame.security === 'integrity-only' || frame.security === 'ciphered-null') {
    maskMacIfPresent(buffer, frame, collector, intents, packetIndex, coverage)
    issues.push(
      frame.security === 'integrity-only'
        ? 'nas-integrity-mac-invalidated'
        : 'nas-null-cipher-plaintext',
    )
  }

  sanitizePlainMessage(
    buffer,
    frame,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )

  coverage.push({ protocol: proto, offset, length, status: 'covered' })
  return { coverage, issues }
}

function familyProto(frame: NasFrame): string {
  switch (frame.family) {
    case 'eps-emm':
      return 'nas-emm'
    case 'eps-esm':
      return 'nas-esm'
    case '5gmm':
      return 'nas-5gmm'
    case '5gsm':
      return 'nas-5gsm'
  }
}

function msgName(frame: NasFrame): string {
  const t = frame.messageType
  if (t === null) return 'unknown'
  if (frame.family === 'eps-emm') return EPS_EMM_MSG[t] ?? `emm-0x${t.toString(16)}`
  if (frame.family === 'eps-esm') return EPS_ESM_MSG[t] ?? `esm-0x${t.toString(16)}`
  if (frame.family === '5gmm') return G5MM_MSG[t] ?? `5gmm-0x${t.toString(16)}`
  return G5SM_MSG[t] ?? `5gsm-0x${t.toString(16)}`
}

function maskMacIfPresent(
  buffer: Uint8Array,
  frame: NasFrame,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  void buffer
  // EPS: header 1 + MAC4 + SQN1; 5GMM: EPD + sec + MAC4 + SQN1
  if (frame.headerSpan.length < 6) return
  const macOff =
    frame.family === '5gmm' || frame.family === '5gsm'
      ? frame.headerSpan.offset + 2
      : frame.headerSpan.offset + 1
  const macLen = 4
  if (macOff + macLen > frame.headerSpan.offset + frame.headerSpan.length) return
  maskRange(collector, intents, packetIndex, macOff, macLen, 'nas-mac')
  coverage.push({ protocol: 'nas-auth', offset: macOff, length: macLen, status: 'redacted' })
}

function sanitizePlainMessage(
  buffer: Uint8Array,
  frame: NasFrame,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const name = msgName(frame)
  coverage.push({
    protocol: `${familyProto(frame)}-${name}`,
    offset: frame.messageOffset,
    length: Math.min(3, frame.messageLength),
    status: 'covered',
  })

  // Fixed auth vectors for Authentication Request
  if (
    (frame.family === 'eps-emm' && frame.messageType === 0x52)
    || (frame.family === '5gmm' && frame.messageType === 0x56)
  ) {
    sanitizeAuthRequest(
      buffer,
      frame,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
    return
  }

  // Walk optional/mandatory IE tail after fixed header
  const fixedLen = fixedHeaderLen(frame)
  let pos = frame.messageOffset + fixedLen
  const end = frame.messageOffset + frame.messageLength

  // Mandatory Mobile Identity as LV right after message type for Attach/Identity/Registration
  if (hasMandatoryMobileIdentity(frame)) {
    const consumed = sanitizeLvIdentity(
      buffer,
      pos,
      end,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      false,
    )
    if (consumed > 0) pos += consumed
  }

  // ESM/5GSM: APN/DNN as LV after fixed fields (simplified: scan from PTI/msg)
  if (frame.family === 'eps-esm' || frame.family === '5gsm') {
    // After PD/bearer/PTI/msgType (3) — optional IE walk covers APN
  }

  walkOptionalIes(
    buffer,
    pos,
    end,
    frame,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )
}

function fixedHeaderLen(frame: NasFrame): number {
  if (frame.family === 'eps-emm') return 2 // PD/sec + msg type (inner for protected already points here)
  if (frame.family === 'eps-esm') return 3
  if (frame.family === '5gmm') return 3 // EPD + sec + msg
  return 3 // 5gsm
}

function hasMandatoryMobileIdentity(frame: NasFrame): boolean {
  if (frame.family === 'eps-emm') {
    return (
      frame.messageType === 0x41 // Attach request
      || frame.messageType === 0x56 // Identity response
      || frame.messageType === 0x45 // Detach request (optional sometimes)
    )
  }
  if (frame.family === '5gmm') {
    return (
      frame.messageType === 0x41 // Registration request
      || frame.messageType === 0x5d // Identity response
    )
  }
  return false
}

function sanitizeAuthRequest(
  buffer: Uint8Array,
  frame: NasFrame,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // After fixed header: NAS KSI (1) + RAND (16) + AUTN LV
  let pos = frame.messageOffset + fixedHeaderLen(frame)
  const end = frame.messageOffset + frame.messageLength
  if (pos >= end) return
  // skip ksi nibble byte
  pos += 1
  if (pos + 16 > end) {
    maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-auth-trunc')
    issues.push('nas-auth-truncated')
    return
  }
  maskRange(collector, intents, packetIndex, pos, 16, 'nas-rand')
  coverage.push({ protocol: 'nas-auth', offset: pos, length: 16, status: 'redacted' })
  pos += 16
  if (pos >= end) return
  const autnLen = buffer[pos]!
  pos += 1
  if (pos + autnLen > end) {
    maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-autn-trunc')
    issues.push('nas-autn-truncated')
    return
  }
  maskRange(collector, intents, packetIndex, pos, autnLen, 'nas-autn')
  coverage.push({ protocol: 'nas-auth', offset: pos, length: autnLen, status: 'redacted' })
  issues.push('nas-auth-vector-masked')
  pos += autnLen
  walkOptionalIes(
    buffer,
    pos,
    end,
    frame,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )
}

function sanitizeLvIdentity(
  buffer: Uint8Array,
  pos: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike | null,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  isSuciContainer: boolean,
): number {
  if (pos >= end) return 0
  const len = buffer[pos]!
  if (pos + 1 + len > end) {
    maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-id-trunc')
    issues.push('nas-identity-truncated')
    return end - pos
  }
  const valOff = pos + 1
  if (isSuciContainer || (len >= 2 && (buffer[valOff]! & 0x07) === 0x01 && len > 8)) {
    // Heuristic SUCI: long identity with scheme — classify
    const suci = classifySuciValue(buffer, valOff, len)
    if (suci?.kind === 'suci-concealed') {
      maskRange(collector, intents, packetIndex, valOff, len, 'nas-suci')
      coverage.push({ protocol: 'nas-suci', offset: valOff, length: len, status: 'redacted' })
      issues.push('nas-suci-concealed-masked')
      return 1 + len
    }
  }
  if (mapping) {
    applyMobileIdentity(
      buffer,
      valOff,
      len,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
  } else {
    maskRange(collector, intents, packetIndex, valOff, len, 'nas-id')
  }
  return 1 + len
}

function walkOptionalIes(
  buffer: Uint8Array,
  start: number,
  end: number,
  frame: NasFrame,
  collector: PatchCollector,
  mapping: MappingLike | null,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  let pos = start
  let guard = 0
  while (pos < end && guard++ < 64) {
    const iei = buffer[pos]!

    // Half-octet IEI (format TV, type 1): high nibble is IEI when bit pattern matches known
    // Unknown implicit — stop safe parse of tail
    if ((iei & 0x80) === 0 && !isKnownFullIei(iei)) {
      // Could be type-1 TV (iei in high nibble)
      const hi = iei & 0xf0
      if (hi === 0x00 || hi === 0x10 || hi === 0x80 || hi === 0x90 || hi === 0xa0 || hi === 0xb0) {
        // Type 1 presence — 1 byte, preserve structural
        coverage.push({ protocol: 'nas-iei', offset: pos, length: 1, status: 'covered' })
        pos += 1
        continue
      }
      maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-tail-unknown')
      coverage.push({
        protocol: 'nas-unknown',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('nas-unknown-implicit-iei-stop')
      break
    }

    // TLV / TLV-E: IEI + length (+ value)
    if (pos + 1 >= end) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-iei-trunc')
      break
    }

    // TLV-E (length 2 octets) for some 5GS IEs — detect by IEI set
    const tlvE = isTlvE(iei)
    let ieLen: number
    let valOff: number
    let hdr = 2
    if (tlvE) {
      if (pos + 3 > end) {
        maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-tlve-trunc')
        break
      }
      ieLen = (buffer[pos + 1]! << 8) | buffer[pos + 2]!
      valOff = pos + 3
      hdr = 3
    } else {
      ieLen = buffer[pos + 1]!
      valOff = pos + 2
    }

    if (valOff + ieLen > end) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'nas-ie-oob')
      issues.push('nas-ie-length-oob')
      break
    }

    coverage.push({
      protocol: 'nas-iei',
      offset: pos,
      length: hdr,
      status: 'covered',
    })

    handleIe(
      iei,
      buffer,
      valOff,
      ieLen,
      frame,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
    pos = valOff + ieLen
  }
}

function isKnownFullIei(iei: number): boolean {
  return (
    iei === IEI.MOBILE_IDENTITY
    || iei === IEI.EPS_MOBILE_IDENTITY
    || iei === IEI.TAI_LIST
    || iei === IEI.TAI
    || iei === IEI.APN
    || iei === IEI.PCO
    || iei === IEI.EPCO
    || iei === IEI.DNN
    || iei === IEI['5GS_MOBILE_IDENTITY']
    || iei === IEI.NAS_MESSAGE_CONTAINER
    || iei === IEI.EAP_MESSAGE
    || iei >= 0x20 // most TLV IEIs
  )
}

function isTlvE(iei: number): boolean {
  return iei === IEI['5GS_MOBILE_IDENTITY'] || iei === IEI.NAS_MESSAGE_CONTAINER
}

function handleIe(
  iei: number,
  buffer: Uint8Array,
  valOff: number,
  ieLen: number,
  frame: NasFrame,
  collector: PatchCollector,
  mapping: MappingLike | null,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  void frame
  if (
    iei === IEI.MOBILE_IDENTITY
    || iei === IEI.EPS_MOBILE_IDENTITY
    || iei === IEI['5GS_MOBILE_IDENTITY']
  ) {
    if (mapping) {
      applyMobileIdentity(
        buffer,
        valOff,
        ieLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else {
      maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-id')
    }
    return
  }
  if (iei === IEI.TAI_LIST || iei === IEI.TAI || iei === IEI['5GS_TRACKING_AREA_ID']) {
    maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-tai')
    coverage.push({ protocol: 'nas-location', offset: valOff, length: ieLen, status: 'redacted' })
    issues.push('nas-location-masked')
    return
  }
  if (iei === IEI.APN || iei === IEI.DNN) {
    if (mapping) {
      mapApnDnn(buffer, valOff, ieLen, collector, mapping, intents, packetIndex, coverage)
    } else {
      maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-dnn')
    }
    return
  }
  if (iei === IEI.PCO || iei === IEI.EPCO || iei === IEI.EAP_MESSAGE) {
    maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-pco')
    coverage.push({ protocol: 'nas-secret', offset: valOff, length: ieLen, status: 'redacted' })
    issues.push('nas-pco-eap-masked')
    return
  }
  if (iei === IEI.NAS_MESSAGE_CONTAINER) {
    if (!mapping) {
      maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-container')
      return
    }
    const nested = sanitizeNas(buffer, valOff, ieLen, collector, mapping, intents, packetIndex)
    if (nested) {
      coverage.push(...nested.coverage)
      if (nested.issues) issues.push(...nested.issues)
    } else {
      maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-container')
    }
    return
  }
  // Unknown TLV with validated length — mask value, keep IEI/len
  maskRange(collector, intents, packetIndex, valOff, ieLen, 'nas-ie-unknown')
  coverage.push({ protocol: 'nas-ie', offset: valOff, length: ieLen, status: 'redacted' })
}

function applyMobileIdentity(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const view = parseMobileIdentityValue(buffer, offset, length)
  if (!view) {
    maskRange(collector, intents, packetIndex, offset, length, 'nas-id-bad')
    return
  }
  if (view.kind === 'tmsi' || view.kind === 'guti') {
    // Structured opaque map of full value (length-preserving mask via opaque-id style bytes)
    mapOpaqueBytes(
      buffer,
      view.valueOffset,
      view.valueLength,
      view.kind === 'guti' ? 'nas-guti' : 'nas-tmsi',
      collector,
      mapping,
      intents,
      packetIndex,
    )
    coverage.push({
      protocol: view.kind === 'guti' ? 'nas-guti' : 'nas-tmsi',
      offset: view.valueOffset,
      length: view.valueLength,
      status: 'covered',
    })
    return
  }
  if (view.kind === 'unknown') {
    maskRange(collector, intents, packetIndex, offset, length, 'nas-id-unknown')
    coverage.push({ protocol: 'nas-id', offset, length, status: 'redacted' })
    return
  }
  if (!view.digits) {
    maskRange(collector, intents, packetIndex, offset, length, 'nas-id-digits')
    return
  }
  const cat = view.kind === 'imsi' ? 'imsi' : 'imei'
  const normalized = normalizeIdentityDigits(view.kind, view.digits)
  const canon = normalized ? canonicalizeIdentity(cat, normalized) : null
  if (!canon) {
    maskRange(collector, intents, packetIndex, offset, length, `nas-${cat}-bad`)
    return
  }
  const slice = buffer.subarray(offset, offset + length)
  intents?.recordEntityReplacement(packetIndex, offset, cat, canon, length)
  collector.addDeferred(
    offset,
    length,
    ({ mapping: live }) => {
      try {
        const alias = live.map(cat, canon)
        const remapped = remapMobileIdentityDigits(slice, alias)
        if (remapped) return remapped
      } catch {
        /* fall through */
      }
      return createProtocolNeutralMaskFill({
        length,
        packetIndex,
        offset,
        domain: `nas-${cat}`,
      })
    },
    { fallbackKind: 'binary-mask', protocol: 'nas', category: cat, packetIndex },
  )
  coverage.push({
    protocol: cat === 'imsi' ? 'nas-imsi' : 'nas-imei',
    offset,
    length,
    status: 'covered',
  })
  void issues
  void mapping
}

function mapApnDnn(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // APN is label-encoded DNS-like; map as hostname of joined labels best-effort
  const raw = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  const labels: string[] = []
  let i = 0
  while (i < raw.length) {
    const n = raw.charCodeAt(i)
    if (n === 0 || i + 1 + n > raw.length) break
    labels.push(raw.slice(i + 1, i + 1 + n))
    i += 1 + n
  }
  const joined = labels.join('.') || raw.replace(/\0/g, '')
  const canon = canonicalizeIdentity('hostname', joined) ?? `nas-apn:${joined}`
  intents?.recordEntityReplacement(packetIndex, offset, 'hostname', canon, length, {
    kind: 'text-ascii',
    byteLength: length,
  }, joined)
  collector.addDeferred(
    offset,
    length,
    ({ mapping: live }) => {
      try {
        const alias = live.aliasFor('hostname', canon, { kind: 'text-ascii', byteLength: length }, joined)
        // Length-preserving: mask if cannot re-encode labels
        void alias
        return createProtocolNeutralMaskFill({
          length,
          packetIndex,
          offset,
          domain: 'nas-apn',
        })
      } catch {
        return createProtocolNeutralMaskFill({
          length,
          packetIndex,
          offset,
          domain: 'nas-apn',
        })
      }
    },
    { fallbackKind: 'binary-mask', protocol: 'nas', category: 'hostname', packetIndex },
  )
  coverage.push({ protocol: 'nas-apn', offset, length, status: 'redacted' })
  void mapping
  void buffer
}

function mapOpaqueBytes(
  buffer: Uint8Array,
  offset: number,
  length: number,
  domain: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  const canon = canonicalizeIdentity('opaque-id', `${domain}:${toHex(buffer, offset, Math.min(length, 8))}`) ?? `${domain}:${raw.length}`
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, length)
  collector.addDeferred(
    offset,
    length,
    ({ mapping: live }) => {
      try {
        const alias = live.map('opaque-id', canon)
        // Produce stable length-preserving fill from alias hash
        void alias
        return createProtocolNeutralMaskFill({
          length,
          packetIndex,
          offset,
          domain,
        })
      } catch {
        return createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
      }
    },
    { fallbackKind: 'binary-mask', protocol: 'nas', category: 'opaque-id', packetIndex },
  )
  void mapping
}

function toHex(buffer: Uint8Array, offset: number, length: number): string {
  let s = ''
  for (let i = 0; i < length; i++) {
    s += buffer[offset + i]!.toString(16).padStart(2, '0')
  }
  return s
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'nas')
}
