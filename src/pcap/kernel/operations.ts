/**
 * Symbolic operations — length-preserving plan ops without payload closures or full mask buffers.
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { WireRepresentationConstraint } from '../../mapping/types'
import type { MappingLike } from '../anonymization/mapping'
import {
  addU32Mod,
  type FingerprintSession,
  u32ToBytes,
} from '../anonymization/fingerprintSession'
import type { IncidentLog } from '../../domain/anonymizationIncident'
import type { BytePatch } from '../sanitize/types'
import { createMaskFill, createProtocolNeutralMaskFill } from '../sanitize/maskFill'
import {
  createFieldFallbackBytes,
  defaultFallbackKindForCategory,
} from '../sanitize/fieldFallback'
import { ipv6TextToBytes16 } from '../sanitize/ipv6Wire'
import { MappingLookupError, MappingPatchError } from '../anonymization/mappingErrors'
import { sdpSessionIdDigits } from '../../mapping/pcapCanonical'
import { shiftSessionVersion } from '../protocols/application/sdp/sessionVersionShift'

export const FILL_KINDS = [
  'protocol-neutral',
  'domain-stream',
  'zeros',
] as const
export type FillKind = (typeof FILL_KINDS)[number]

export const WIRE_ENCODERS = [
  'raw-alias-utf8',
  'ipv4-octets',
  'ipv6-octets',
  'mac-octets',
  'u16-be',
  'u16-le',
  'u24-be',
  'u32-be',
  'fixed-ascii',
] as const
export type WireEncoderKind = (typeof WIRE_ENCODERS)[number]

export const FINGERPRINT_FIELDS = ['ipv4-id', 'flow-label', 'tcp-u32'] as const
export type FingerprintField = (typeof FINGERPRINT_FIELDS)[number]

export const TCP_SEQ_FINGERPRINT_KINDS = [
  'seq',
  'ack',
  'sack-left',
  'sack-right',
  'ts-val',
  'ts-ecr',
] as const
export type TcpSeqFingerprintKind = (typeof TCP_SEQ_FINGERPRINT_KINDS)[number]

export type SymbolicOperation =
  | MapOperation
  | MaskOperation
  | SecretOperation
  | FingerprintOperation
  | SessionVersionShiftOperation
  | PreserveOperation
  | FixedBytesOperation
  | ChecksumOperation

/**
 * T01 / T-01.B — SDP/MGCP o= session-version is not a MappingAuthority identity.
 * Journal op derives digits from the resolved sdp-session-id alias (preview === export).
 */
export interface SessionVersionShiftOperation {
  readonly kind: 'session-version-shift'
  readonly packetIndex: number
  readonly offset: number
  readonly length: number
  readonly versionDigits: string
  readonly sessionIdCanonical: string
  readonly reasonCode: string
}

/** Session-scoped fingerprint remap — render uses live FingerprintSession at plan time. */
export interface FingerprintOperation {
  readonly kind: 'fingerprint'
  readonly packetIndex: number
  readonly offset: number
  readonly length: number
  readonly field: FingerprintField
  readonly reasonCode: string
  readonly srcIp: string
  readonly dstIp: string
  readonly ipProto?: number
  readonly originalU16?: number
  readonly originalU32?: number
  readonly srcPort?: number
  readonly dstPort?: number
  readonly flowHeaderByte0?: number
  readonly flowHeaderByte1?: number
  readonly tcpSeqKind?: TcpSeqFingerprintKind
}

export interface MapOperation {
  readonly kind: 'map'
  readonly packetIndex: number
  readonly offset: number
  readonly length: number
  readonly category: IdentityCategory
  readonly canonical: string
  readonly constraint: WireRepresentationConstraint
  readonly encoder: WireEncoderKind
  readonly originalSpelling?: string
}

export interface MaskOperation {
  readonly kind: 'mask'
  readonly packetIndex: number
  readonly offset: number
  readonly length: number
  readonly fillKind: FillKind
  readonly domain: string
  readonly reasonCode: string
}

export interface SecretOperation {
  readonly kind: 'secret'
  readonly packetIndex: number
  readonly offset: number
  readonly length: number
  readonly reasonCode: string
}

export interface PreserveOperation {
  readonly kind: 'preserve'
  readonly packetIndex: number
  readonly offset: number
  readonly length: number
  readonly reasonCode: string
}

/** Eager concrete bytes already length-checked (legacy bridge / tiny structural fixes). */
export interface FixedBytesOperation {
  readonly kind: 'fixed'
  readonly packetIndex: number
  readonly offset: number
  readonly data: Uint8Array
}

export interface ChecksumOperation {
  readonly kind: 'checksum'
  readonly packetIndex: number
  readonly layer: 'ipv4' | 'tcp' | 'udp' | 'icmp'
  readonly reasonCode: string
}

export interface RenderContext {
  readonly mapping: MappingLike
  readonly fingerprints: FingerprintSession
  /**
   * The packet being rendered. Frozen plans share identical map/mask ops across the packets of
   * a flow (identityIntern), so their own `packetIndex` is only the first creator's — always
   * pass the plan's index when rendering a frozen plan.
   */
  readonly packetIndex?: number
  readonly incidentLog?: IncidentLog
  readonly sourceId?: string
  readonly packetNumber?: number
}

/**
 * Render symbolic ops into length-preserving BytePatches.
 * Mask fills are generated per-block from (domain, packetIndex, offset, length) — never stored.
 */
export function renderSymbolicOperations(
  ops: readonly SymbolicOperation[],
  ctx: RenderContext,
): BytePatch[] {
  const patches: BytePatch[] = []
  for (const op of ops) {
    switch (op.kind) {
      case 'map': {
        try {
          const bytes = encodeMappedAlias(op, ctx.mapping)
          if (bytes === null) continue
          if (bytes.length !== op.length) {
            throw new MappingPatchError(
              'length-mismatch',
              `Symbolic map length mismatch at packetIndex=${ctx.packetIndex ?? op.packetIndex} offset=${op.offset}`,
            )
          }
          patches.push({ offset: op.offset, data: bytes })
        } catch (err) {
          const fill = createFieldFallbackBytes({
            length: op.length,
            kind: defaultFallbackKindForCategory(op.category),
            packetIndex: ctx.packetIndex ?? op.packetIndex,
            offset: op.offset,
            domain: op.category,
          })
          patches.push({ offset: op.offset, data: fill })
          ctx.incidentLog?.record({
            unit: 'field',
            sourceId: ctx.sourceId ?? 'pcap',
            packetIndex: ctx.packetIndex ?? op.packetIndex,
            packetNumber: ctx.packetNumber,
            category: op.category,
            stage: 'plan',
            reason:
              err instanceof MappingLookupError && err.code === 'canonicalize-failed'
                ? 'mapping-canonicalize-failed'
                : err instanceof MappingPatchError && err.code === 'length-mismatch'
                  ? 'patch-length-mismatch'
                  : 'mapping-alias-missing',
            fallback: 'field-masked',
          })
        }
        break
      }
      case 'mask':
      case 'secret': {
        const length = op.length
        const fill =
          op.kind === 'secret' || (op.kind === 'mask' && op.fillKind === 'protocol-neutral')
            ? createProtocolNeutralMaskFill({
                length,
                packetIndex: ctx.packetIndex ?? op.packetIndex,
                offset: op.offset,
                domain: op.kind === 'mask' ? op.domain : 'secret',
              })
            : createMaskFill({
                length,
                packetIndex: ctx.packetIndex ?? op.packetIndex,
                offset: op.offset,
                domain: op.kind === 'mask' ? op.domain : 'secret',
                mode: op.kind === 'mask' && op.fillKind === 'zeros' ? 'zeros' : 'stream',
              })
        patches.push({ offset: op.offset, data: fill })
        break
      }
      case 'fingerprint': {
        const bytes = renderFingerprintOperation(op, ctx.fingerprints)
        if (bytes.length !== op.length) {
          throw new MappingPatchError(
            'length-mismatch',
            `Fingerprint op length mismatch at packetIndex=${op.packetIndex} offset=${op.offset}`,
          )
        }
        patches.push({ offset: op.offset, data: bytes })
        break
      }
      case 'session-version-shift': {
        const bytes = renderSessionVersionShift(op, ctx.mapping)
        if (bytes.length !== op.length) {
          throw new MappingPatchError(
            'length-mismatch',
            `Session-version shift length mismatch at packetIndex=${op.packetIndex} offset=${op.offset}`,
          )
        }
        patches.push({ offset: op.offset, data: bytes })
        break
      }
      case 'fixed':
        patches.push({ offset: op.offset, data: op.data })
        break
      case 'preserve':
      case 'checksum':
        break
      default: {
        const _exhaustive: never = op
        void _exhaustive
      }
    }
  }
  return patches
}

function renderFingerprintOperation(
  op: FingerprintOperation,
  fingerprints: FingerprintSession,
): Uint8Array {
  switch (op.field) {
    case 'ipv4-id': {
      const mapped = fingerprints.mapIpv4Id(
        op.srcIp,
        op.dstIp,
        op.ipProto ?? 0,
        op.originalU16 ?? 0,
      )
      return new Uint8Array([(mapped >> 8) & 0xff, mapped & 0xff])
    }
    case 'flow-label': {
      const origLabel = op.originalU32 ?? 0
      const mapped = fingerprints.mapFlowLabel(op.srcIp, op.dstIp, origLabel)
      const b0 = op.flowHeaderByte0 ?? 0x60
      const b1 = op.flowHeaderByte1 ?? 0
      return new Uint8Array([
        b0,
        (b1 & 0xf0) | ((mapped >> 16) & 0x0f),
        (mapped >> 8) & 0xff,
        mapped & 0xff,
      ])
    }
    case 'tcp-u32': {
      const ep = {
        srcIp: op.srcIp,
        dstIp: op.dstIp,
        srcPort: op.srcPort ?? 0,
        dstPort: op.dstPort ?? 0,
      }
      const { forward, reverse } = fingerprints.tcpSeqOffsetForEndpoint(ep)
      const base = op.originalU32 ?? 0
      const kind = op.tcpSeqKind ?? 'seq'
      if (kind === 'sack-left' || kind === 'sack-right' || kind === 'ts-ecr' || kind === 'ack') {
        return u32ToBytes(addU32Mod(base, reverse))
      }
      return u32ToBytes(addU32Mod(base, forward))
    }
    default: {
      const _exhaustive: never = op.field
      void _exhaustive
      return new Uint8Array(op.length)
    }
  }
}

function renderSessionVersionShift(
  op: SessionVersionShiftOperation,
  mapping: MappingLike,
): Uint8Array {
  const sessionIdDigits = sdpSessionIdDigits(op.sessionIdCanonical)
  const constraint = { kind: 'text-ascii' as const, byteLength: sessionIdDigits.length }
  let idAlias: string
  try {
    idAlias = mapping.aliasFor('sdp-session-id', op.sessionIdCanonical, constraint, sessionIdDigits)
  } catch {
    idAlias = '0'.repeat(sessionIdDigits.length)
  }
  const shifted = shiftSessionVersion(op.versionDigits, sessionIdDigits, idAlias)
  const out = new Uint8Array(op.length)
  out.fill(0x30) // '0'
  const enc = new TextEncoder().encode(shifted)
  out.set(enc.subarray(0, Math.min(enc.length, op.length)))
  return out
}

/**
 * Integer wire value of a mapped alias. Port aliases are transport-qualified (`udp/49154`);
 * VLAN/SSRC/TEID/radio aliases are bare decimals. Anything else is unrepresentable — throw so
 * the caller masks the field and records an incident instead of writing a silent 0.
 */
function wireIntegerAlias(op: MapOperation, alias: string, max: number): number {
  const digits = op.category === 'port' ? alias.slice(alias.lastIndexOf('/') + 1) : alias
  const n = /^\d+$/.test(digits) ? Number.parseInt(digits, 10) : Number.NaN
  if (!Number.isInteger(n) || n < 0 || n > max) {
    throw new MappingLookupError('representation-unavailable', { category: op.category })
  }
  return n
}

function encodeMappedAlias(op: MapOperation, mapping: MappingLike): Uint8Array | null {
  const alias = mapping.aliasFor(op.category, op.canonical, op.constraint, op.originalSpelling)
  if (alias === op.canonical && op.encoder !== 'fixed-ascii') {
    // Port / VLAN preserve path may return identical wire value — suppress no-op patch.
    if (op.category === 'port' || op.category === 'vlan') return null
  }
  switch (op.encoder) {
    case 'ipv4-octets': {
      const parts = alias.split('.')
      if (parts.length !== 4) return null
      const out = new Uint8Array(4)
      for (let i = 0; i < 4; i++) out[i] = Number(parts[i]) & 0xff
      return out
    }
    case 'ipv6-octets':
      return ipv6TextToBytes16(alias)
    case 'mac-octets': {
      const hex = alias.replace(/[^0-9a-fA-F]/g, '')
      if (hex.length !== 12) return null
      const out = new Uint8Array(6)
      for (let i = 0; i < 6; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
      return out
    }
    case 'u16-be': {
      const n = wireIntegerAlias(op, alias, 0xffff)
      return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
    }
    case 'u16-le': {
      const n = wireIntegerAlias(op, alias, 0xffff)
      return new Uint8Array([n & 0xff, (n >> 8) & 0xff])
    }
    case 'u24-be': {
      const n = wireIntegerAlias(op, alias, 0xffffff)
      return new Uint8Array([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
    }
    case 'u32-be': {
      const n = wireIntegerAlias(op, alias, 0xffffffff)
      return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
    }
    case 'fixed-ascii':
    case 'raw-alias-utf8': {
      const encoded = new TextEncoder().encode(alias)
      if (encoded.length === op.length) return encoded
      const out = new Uint8Array(op.length)
      out.fill(0x20)
      out.set(encoded.subarray(0, Math.min(encoded.length, op.length)))
      return out
    }
    default: {
      const _exhaustive: never = op.encoder
      void _exhaustive
      return null
    }
  }
}
