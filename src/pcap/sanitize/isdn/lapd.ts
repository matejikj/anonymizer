/**
 * T51 — Q.921 LAPD (DSS1 D-channel): address/control preserve; I-frame → Q.931 child.
 * LINKTYPE_LINUX_LAPD (177) cooked header + raw LAPD frames.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from '../types.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import { looksLikeQ931, sanitizeQ931 } from './q931.ts'
import { protocolGraphCaptureGeneration } from '../protocolGraphState.ts'

/** tcpdump LINKTYPE_LINUX_LAPD */
export const LINKTYPE_LINUX_LAPD = 177

const LINUX_LAPD_COOKED_LEN = 16

export function looksLikeLapd(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  // Address: SAPI (6) + C/R + EA0; TEI (7) + EA1. EA bits: first EA=0, second EA=1.
  const a0 = buffer[offset]!
  const a1 = buffer[offset + 1]!
  if ((a0 & 0x01) !== 0) return false
  if ((a1 & 0x01) !== 1) return false
  return true
}

/**
 * Sanitize a LAPD frame (address+control[+info]). Optional FCS (2 octets) at end when
 * `hasFcs` is true — FCS is not rewritten unless present and claimed.
 */
export function sanitizeLapd(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  options: { readonly hasFcs?: boolean } = {},
): AppLayerResult | null {
  if (!looksLikeLapd(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = offset + length
  let frameEnd = end
  if (options.hasFcs && length >= 5) {
    frameEnd = end - 2
    coverage.push({ protocol: 'lapd-fcs', offset: frameEnd, length: 2, status: 'covered' })
  }

  // Address (2 octets) — map TEI (bits of second octet >> 1), preserve SAPI/CR/EA
  const linkScope = lapdLinkScope(buffer, offset)
  const tei = buffer[offset + 1]! >> 1
  coverage.push({ protocol: 'lapd-addr', offset, length: 2, status: 'covered' })
  if (tei !== 127 /* broadcast */) {
    mapTei(buffer, offset + 1, tei, collector, mapping, intents, packetIndex, coverage)
  }

  // Control: 1 octet (U/S) or 2 octets (I with seq)
  if (offset + 2 >= frameEnd) {
    coverage.unshift({ protocol: 'lapd', offset, length, status: 'malformed' })
    return { coverage, issues: ['lapd-short'] }
  }
  const ctrl0 = buffer[offset + 2]!
  const isIframe = (ctrl0 & 0x01) === 0
  const ctrlLen = isIframe ? 2 : 1
  if (offset + 2 + ctrlLen > frameEnd) {
    coverage.unshift({ protocol: 'lapd', offset, length, status: 'malformed' })
    return { coverage, issues: ['lapd-ctrl-trunc'] }
  }
  coverage.push({
    protocol: 'lapd-ctrl',
    offset: offset + 2,
    length: ctrlLen,
    status: 'covered',
  })

  const infoOff = offset + 2 + ctrlLen
  const infoLen = frameEnd - infoOff
  if (infoLen <= 0) {
    coverage.unshift({ protocol: 'lapd', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  if (isIframe && looksLikeQ931(buffer, infoOff, infoLen)) {
    const q = sanitizeQ931(
      buffer,
      infoOff,
      infoLen,
      collector,
      mapping,
      intents,
      packetIndex,
      'q931',
      {
        linkScope,
        // Generation-wide graph so the same CR on different TEIs can flag multi-link.
        captureScopeKey: `${protocolGraphCaptureGeneration()}/q931`,
      },
    )
    if (q) {
      coverage.push(...q.coverage)
      if (q.issues) for (const i of q.issues) issues.push(i)
    }
  } else if (infoLen > 0) {
    // UI/SABME/etc. or non-Q.931 info — fail-closed mask info
    const fill = createProtocolNeutralMaskFill({
      length: infoLen,
      packetIndex,
      offset: infoOff,
      domain: 'lapd-info',
    })
    try {
      collector.add(infoOff, fill)
    } catch {
      /* overlap */
    }
    intents?.recordMaskRange(packetIndex, infoOff, infoLen, 'lapd-info', 'lapd')
    coverage.push({ protocol: 'lapd-info', offset: infoOff, length: infoLen, status: 'redacted' })
    issues.push('lapd-info-masked')
  }

  coverage.unshift({ protocol: 'lapd', offset, length, status: 'covered' })
  return { coverage, issues }
}

/** LINKTYPE_LINUX_LAPD: 16-octet cooked header + LAPD. */
export function sanitizeLinuxLapdLink(
  buffer: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (buffer.length < LINUX_LAPD_COOKED_LEN) {
    const fill = createProtocolNeutralMaskFill({
      length: buffer.length,
      packetIndex,
      offset: 0,
      domain: 'lapd-cooked-short',
    })
    try {
      collector.add(0, fill)
    } catch {
      /* */
    }
    return {
      coverage: [{ protocol: 'lapd', offset: 0, length: buffer.length, status: 'malformed' }],
      issues: ['lapd-cooked-short'],
    }
  }
  coverage.push({
    protocol: 'lapd-cooked',
    offset: 0,
    length: LINUX_LAPD_COOKED_LEN,
    status: 'covered',
  })
  const bodyOff = LINUX_LAPD_COOKED_LEN
  const bodyLen = buffer.length - bodyOff
  const lapd = sanitizeLapd(buffer, bodyOff, bodyLen, collector, mapping, intents, packetIndex, {
    hasFcs: false,
  })
  if (lapd) {
    coverage.push(...lapd.coverage)
    if (lapd.issues) for (const i of lapd.issues) issues.push(i)
  } else if (bodyLen > 0) {
    const fill = createProtocolNeutralMaskFill({
      length: bodyLen,
      packetIndex,
      offset: bodyOff,
      domain: 'lapd-body',
    })
    try {
      collector.add(bodyOff, fill)
    } catch {
      /* */
    }
    coverage.push({ protocol: 'lapd', offset: bodyOff, length: bodyLen, status: 'redacted' })
    issues.push('lapd-unparsed')
  }
  coverage.unshift({ protocol: 'lapd', offset: 0, length: buffer.length, status: 'covered' })
  return { coverage, issues }
}

function lapdLinkScope(buffer: Uint8Array, offset: number): string {
  const a0 = buffer[offset]!
  const a1 = buffer[offset + 1]!
  const sapi = (a0 >> 2) & 0x3f
  const tei = a1 >> 1
  return `lapd:sapi=${sapi}:tei=${tei}`
}

function mapTei(
  buffer: Uint8Array,
  teiOctetOffset: number,
  tei: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  void buffer
  void mapping
  const token = String(tei)
  const aliasSpelling = token.padStart(3, '0')
  const canon = canonicalizeIdentity('opaque-id', `isdn-tei:${token}`) ?? `isdn-tei:${token}`
  // Keep EA bit (LSB=1); replace TEI field (7 bits)
  const aliasConstraint = { kind: 'text-ascii' as const, byteLength: 3 }
  intents?.recordEntityReplacement(
    packetIndex,
    teiOctetOffset,
    'opaque-id',
    canon,
    1,
    aliasConstraint,
    aliasSpelling,
  )
  try {
    collector.addDeferred(
      teiOctetOffset,
      1,
      ({ mapping: live }) => {
        try {
          const alias = live.aliasFor('opaque-id', canon, aliasConstraint, aliasSpelling)
          let h = 0
          for (let i = 0; i < alias.length; i++) h = (h * 33 + alias.charCodeAt(i)) >>> 0
          const mappedTei = h % 127 // avoid 127 broadcast
          return Uint8Array.of(((mappedTei & 0x7f) << 1) | 0x01)
        } catch {
          return createProtocolNeutralMaskFill({
            length: 1,
            packetIndex,
            offset: teiOctetOffset,
            domain: 'lapd-tei',
          })
        }
      },
      { fallbackKind: 'text-x', protocol: 'lapd', category: 'opaque-id', packetIndex },
    )
  } catch {
    /* overlap */
  }
  void computeFixedLengthAsciiBytes
  coverage.push({ protocol: 'lapd-tei', offset: teiOctetOffset, length: 1, status: 'covered' })
}
