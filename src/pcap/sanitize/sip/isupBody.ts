/**
 * T37 SIP-I / SIP-T — ISUP MIME body plan via shared T25 {@link analyzeIsupPdu} walk.
 */

import type { ByteSpan } from '../../protocols/application/sip/types.ts'
import type { LayerCoverage } from '../types.ts'
import type { SipBodyOperation } from '../../protocols/application/sip/bodyOperations.ts'
import { SIP_REDACT_MASK_BYTE } from '../../protocols/application/sip/redactPlan.ts'
import type { PortContext } from '../../protocols/application/sip/mappingWire.ts'
import { analyzeIsupPdu, type IsupPduSink } from '../isup/pdu.ts'
import { canonicalTbcdSipPhone } from '../isup/tbcdPhoneMap.ts'

const SIG: PortContext = 'signaling'

function protocolId(part: string): string {
  return part ? `sip-isup-${part}` : 'sip-isup'
}

export function buildIsupBodyPlan(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
): {
  readonly operations: readonly SipBodyOperation[]
  readonly coverage: readonly LayerCoverage[]
  readonly issues: readonly string[]
} {
  const operations: SipBodyOperation[] = []
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const abs = bodySpan.offset
  const len = bodySpan.length

  class PlanIsupSink implements IsupPduSink {
    cover(part: string, offset: number, length: number, status: LayerCoverage['status']): void {
      coverage.push({ protocol: protocolId(part), offset, length, status })
    }

    issue(token: string): void {
      issues.push(token)
    }

    mapNumberParam(valueOffset: number, paramLen: number): void {
      if (paramLen < 3) {
        operations.push(redactOp(valueOffset, paramLen))
        return
      }
      coverage.push({ protocol: 'sip-isup-number-hdr', offset: valueOffset, length: 2, status: 'covered' })
      const tbcdLen = paramLen - 2
      const tbcdOff = valueOffset + 2
      const canon = canonicalTbcdSipPhone(buffer, tbcdOff, tbcdLen)
      if (!canon) {
        operations.push(redactOp(tbcdOff, tbcdLen))
        return
      }
      operations.push({
        span: { offset: tbcdOff, length: tbcdLen },
        action: 'map',
        mappingCategory: 'sip-phone',
        canonicalText: canon,
        maskByte: SIP_REDACT_MASK_BYTE,
        portContext: SIG,
      })
      coverage.push({ protocol: 'sip-isup-number', offset: tbcdOff, length: tbcdLen, status: 'covered' })
    }

    redact(offset: number, length: number, _domain: string): void {
      if (length <= 0) return
      operations.push(redactOp(offset, length))
    }
  }

  analyzeIsupPdu(buffer, abs, len, 'sip-i', new PlanIsupSink())

  if (issues.some((i) => i.startsWith('isup-unsupported-type:'))) {
    operations.length = 0
    operations.push(redactOp(abs, len))
  }

  return { operations, coverage, issues }
}

function redactOp(offset: number, length: number): SipBodyOperation {
  return {
    span: { offset, length },
    action: 'redact',
    mappingCategory: null,
    canonicalText: '',
    maskByte: SIP_REDACT_MASK_BYTE,
    portContext: SIG,
  }
}
