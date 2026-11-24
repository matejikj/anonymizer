/**
 * Single source of truth for SIP body sanitization ops (T02).
 *
 * Discovery and plan both call {@link planSipBodyOperations} so multipart/SIPREC
 * identities cannot diverge (B2). Header ops stay in extract/redactPlan.
 */

import type { ByteSpan, SipMessage } from './types'
import { decideSipBodyPolicy } from './bodyPolicy'
import {
  contentTypeHeaderRaw,
  isMultipartContentType,
  isNonIdentityTransferEncoding,
  isSdpPartContentType,
  MAX_MULTIPART_NESTING,
  parseSipMultipartBody,
} from './multipartBody'
import { buildSiprecMetadataPlan } from './siprecMetadataPlan'
import { parseSdpFromSipMessage } from '../sdp/attach'
import { extractSdpEntities } from '../sdp/extract'
import { buildSdpRedactionPlan, SDP_REDACT_MASK_BYTE } from '../sdp/redactPlan'
import { DEFAULT_SDP_REDACTION_POLICY } from '../sdp/types'
import { buildRadioProtocolBodyPlan } from './radioProtocolBody'
import {
  buildDialogInfoBodyPlan,
  buildDtmfRelayBodyPlan,
  buildMcpttBodyPlan,
  looksLikeMcpttBody,
  looksLikeDtmfRelayBody,
  looksLikeDialogInfoBody,
  looksLikeIsupBody,
} from './mcpttBody'
import {
  buildCstaXmlBodyPlan,
  cstaIdentityScopeForUaCsta,
  looksLikeCstaContentType,
  looksLikeCstaXmlText,
} from '../csta/xmlPlan'
import { protocolGraphCaptureGeneration } from '../../../sanitize/protocolGraphState.ts'
import {
  buildPidfLoBodyPlan,
  buildLostBodyPlan,
  looksLikePidfContentType,
  looksLikePidfXmlText,
  looksLikeLostContentType,
  looksLikeLostXmlText,
} from '../location/index.ts'
import { buildIsupBodyPlan } from './isupBody.ts'
import { decodeLatin1Span } from './bytes'
import { SIP_REDACT_MASK_BYTE } from './redactPlan'
import { parseSdp } from '../sdp/parser'
import type { PortContext } from './mappingWire'
import type { LayerCoverage } from '../../../sanitize/types'

/** Coverage protocol ids emitted for body regions (never silent `covered` on SIPREC XML). */
export type SipBodyCoverageProtocol =
  | 'sdp'
  | 'sip-multipart'
  | 'sip-siprec-metadata'
  | 'radio-protocol-body'
  | 'sip-mcptt'
  | 'sip-dtmf-relay'
  | 'sip-dialog-info'
  | 'sip-sipfrag'
  | 'sip-csta'
  | 'sip-pidf'
  | 'sip-lost'
  | 'sip-isup'
  | 'sip-body'

export interface SipBodyOperation {
  readonly span: ByteSpan
  readonly action: 'map' | 'redact'
  readonly mappingCategory: string | null
  readonly canonicalText: string
  readonly maskByte: number
  readonly portContext: PortContext
  readonly sessionIdForVersion?: string
}

export interface SipBodyPlanResult {
  readonly operations: readonly SipBodyOperation[]
  readonly issues: readonly string[]
  readonly coverage: readonly LayerCoverage[]
}

export function isSiprecMetadataContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return base === 'application/rs-metadata+xml'
}

/**
 * Plan all body-level map/redact operations for a parsed SIP message.
 * Does not include SIP header entities — callers handle those separately.
 */
export function planSipBodyOperations(
  message: SipMessage,
  buffer: Uint8Array,
): SipBodyPlanResult {
  const operations: SipBodyOperation[] = []
  const issues: string[] = []
  const coverage: LayerCoverage[] = []
  const bodyDecision = decideSipBodyPolicy(message, buffer)

  if (bodyDecision.kind === 'empty' || !bodyDecision.bodySpan) {
    return { operations, issues, coverage }
  }

  if (bodyDecision.kind === 'structured-sanitized') {
    appendTopLevelSdpOps(operations, message, buffer, bodyDecision.bodySpan, coverage)
    return { operations, issues, coverage }
  }

  if (bodyDecision.kind === 'structured-multipart') {
    appendMultipartOps(operations, message, buffer, bodyDecision.bodySpan, issues, coverage)
    return { operations, issues, coverage }
  }

  if (bodyDecision.kind === 'structured-radio-protocol') {
    appendRadioOps(operations, buffer, bodyDecision.bodySpan, coverage)
    return { operations, issues, coverage }
  }

  if (bodyDecision.kind === 'structured-mcptt') {
    appendMcpttFamilyOps(operations, buffer, bodyDecision.bodySpan, coverage, 'sip-mcptt', buildMcpttBodyPlan)
    return { operations, issues, coverage }
  }
  if (bodyDecision.kind === 'structured-dtmf-relay') {
    appendMcpttFamilyOps(
      operations,
      buffer,
      bodyDecision.bodySpan,
      coverage,
      'sip-dtmf-relay',
      buildDtmfRelayBodyPlan,
    )
    return { operations, issues, coverage }
  }
  if (bodyDecision.kind === 'structured-dialog-info') {
    appendMcpttFamilyOps(
      operations,
      buffer,
      bodyDecision.bodySpan,
      coverage,
      'sip-dialog-info',
      buildDialogInfoBodyPlan,
    )
    return { operations, issues, coverage }
  }
  if (bodyDecision.kind === 'structured-csta') {
    appendCstaOps(operations, message, buffer, bodyDecision.bodySpan, coverage, issues)
    return { operations, issues, coverage }
  }
  if (bodyDecision.kind === 'structured-pidf') {
    appendLocationOps(operations, buffer, bodyDecision.bodySpan, coverage, issues, 'sip-pidf', buildPidfLoBodyPlan)
    return { operations, issues, coverage }
  }
  if (bodyDecision.kind === 'structured-lost') {
    appendLocationOps(operations, buffer, bodyDecision.bodySpan, coverage, issues, 'sip-lost', buildLostBodyPlan)
    return { operations, issues, coverage }
  }
  if (bodyDecision.kind === 'structured-isup') {
    const isupPlan = buildIsupBodyPlan(buffer, bodyDecision.bodySpan)
    for (const op of isupPlan.operations) operations.push(op)
    coverage.push(...isupPlan.coverage)
    if (isupPlan.issues.length) issues.push(...isupPlan.issues)
    return { operations, issues, coverage }
  }

  if (bodyDecision.kind === 'structured-sipfrag') {
    // Partial SIP fragment — fail-closed mask (not a complete SIP message).
    // T63 — status matches the redact op (masked bytes), not heuristic.
    operations.push(redactOp(bodyDecision.bodySpan, SIP_REDACT_MASK_BYTE))
    coverage.push({
      protocol: 'sip-sipfrag',
      offset: bodyDecision.bodySpan.offset,
      length: bodyDecision.bodySpan.length,
      status: 'redacted',
    })
    issues.push('sip-body:sipfrag-partial')
    return { operations, issues, coverage }
  }

  // unsupported / malformed / fully-redacted — whole body mask
  operations.push(redactOp(bodyDecision.bodySpan, SIP_REDACT_MASK_BYTE))
  coverage.push({
    protocol: 'sip-body',
    offset: bodyDecision.bodySpan.offset,
    length: bodyDecision.bodySpan.length,
    status: bodyDecision.kind === 'malformed' ? 'malformed' : 'redacted',
  })
  if (bodyDecision.kind === 'malformed' || bodyDecision.kind === 'unsupported') {
    issues.push(`sip-body:${bodyDecision.reason}`)
  }
  return { operations, issues, coverage }
}

function appendTopLevelSdpOps(
  operations: SipBodyOperation[],
  message: SipMessage,
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  coverage: LayerCoverage[],
): void {
  const attached = parseSdpFromSipMessage(message, buffer)
  if (attached.kind === 'parsed' && attached.sdp.kind === 'complete') {
    pushSdpPlanOps(operations, buffer, attached.sdp.session)
    coverage.push({
      protocol: 'sdp',
      offset: bodySpan.offset,
      length: bodySpan.length,
      status: 'covered',
    })
    return
  }
  operations.push(redactOp(bodySpan, SIP_REDACT_MASK_BYTE))
  coverage.push({
    protocol: 'sdp',
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: 'malformed',
  })
}

function appendMultipartOps(
  operations: SipBodyOperation[],
  message: SipMessage,
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  issues: string[],
  coverage: LayerCoverage[],
  nestingDepth = 0,
  contentTypeHeaderOverride?: string | null,
): void {
  const ctRaw = contentTypeHeaderOverride ?? contentTypeHeaderRaw(message.headers)
  if (!ctRaw) {
    operations.push(redactOp(bodySpan, SIP_REDACT_MASK_BYTE))
    coverage.push({
      protocol: 'sip-multipart',
      offset: bodySpan.offset,
      length: bodySpan.length,
      status: 'malformed',
    })
    issues.push('sip-multipart:missing-content-type')
    return
  }

  if (nestingDepth > MAX_MULTIPART_NESTING) {
    operations.push(redactOp(bodySpan, SIP_REDACT_MASK_BYTE))
    coverage.push({
      protocol: 'sip-multipart',
      offset: bodySpan.offset,
      length: bodySpan.length,
      status: 'malformed',
    })
    issues.push('sip-multipart:nesting-exceeded')
    return
  }

  const parsed = parseSipMultipartBody(buffer, bodySpan, ctRaw)
  if (!parsed.ok) {
    issues.push(`sip-multipart:${parsed.reason ?? 'parse-failed'}`)
    operations.push(redactOp(bodySpan, SIP_REDACT_MASK_BYTE))
    coverage.push({
      protocol: 'sip-multipart',
      offset: bodySpan.offset,
      length: bodySpan.length,
      status: 'malformed',
    })
    return
  }

  // Framing itself is structured; part dispositions follow below.
  coverage.push({
    protocol: 'sip-multipart',
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: 'covered',
  })

  for (const part of parsed.parts) {
    if (part.bodySpan.length <= 0) continue

    // T02: encoded parts without a length-preserving inverse → physical mask.
    if (isNonIdentityTransferEncoding(part.transferEncoding)) {
      operations.push(redactOp(part.bodySpan, SIP_REDACT_MASK_BYTE))
      coverage.push({
        protocol: 'sip-body',
        offset: part.bodySpan.offset,
        length: part.bodySpan.length,
        status: 'redacted',
      })
      issues.push(`sip-multipart:cte-${part.transferEncoding ?? 'encoded'}`)
      continue
    }

    // Nested multipart (mixed/related/…) — recurse with full Content-Type (boundary).
    if (isMultipartContentType(part.contentType) && part.contentTypeHeader) {
      appendMultipartOps(
        operations,
        message,
        buffer,
        part.bodySpan,
        issues,
        coverage,
        nestingDepth + 1,
        part.contentTypeHeader,
      )
      continue
    }

    if (isSdpPartContentType(part.contentType)) {
      const sdp = parseSdp(buffer, {
        offset: part.bodySpan.offset,
        length: part.bodySpan.length,
      })
      if (sdp.kind === 'complete') {
        pushSdpPlanOps(operations, buffer, sdp.session)
        coverage.push({
          protocol: 'sdp',
          offset: part.bodySpan.offset,
          length: part.bodySpan.length,
          status: 'covered',
        })
        continue
      }
      issues.push('sip-multipart:sdp-part-malformed')
      operations.push(redactOp(part.bodySpan, SIP_REDACT_MASK_BYTE))
      coverage.push({
        protocol: 'sdp',
        offset: part.bodySpan.offset,
        length: part.bodySpan.length,
        status: 'malformed',
      })
      continue
    }

    if (isSiprecMetadataContentType(part.contentType)) {
      const siprec = buildSiprecMetadataPlan(buffer, part.bodySpan)
      for (const op of siprec.operations) {
        operations.push({
          span: op.span,
          action: op.action,
          mappingCategory: op.mappingCategory,
          canonicalText: op.canonicalText,
          maskByte: op.maskByte,
          portContext: 'signaling',
        })
      }
      if (siprec.issues.length) issues.push(...siprec.issues)
      const wholeBodyFallback = siprec.operations.some(
        (op) => op.action === 'redact' && op.span.offset === part.bodySpan.offset
          && op.span.length === part.bodySpan.length,
      )
      coverage.push({
        protocol: 'sip-siprec-metadata',
        offset: part.bodySpan.offset,
        length: part.bodySpan.length,
        status: wholeBodyFallback ? 'redacted' : 'covered',
      })
      continue
    }

    if (looksLikeMcpttBody(part.contentType)) {
      appendMcpttFamilyOps(operations, buffer, part.bodySpan, coverage, 'sip-mcptt', buildMcpttBodyPlan)
      continue
    }
    if (looksLikeDtmfRelayBody(part.contentType)) {
      appendMcpttFamilyOps(
        operations,
        buffer,
        part.bodySpan,
        coverage,
        'sip-dtmf-relay',
        buildDtmfRelayBodyPlan,
      )
      continue
    }
    if (looksLikeDialogInfoBody(part.contentType)) {
      appendMcpttFamilyOps(
        operations,
        buffer,
        part.bodySpan,
        coverage,
        'sip-dialog-info',
        buildDialogInfoBodyPlan,
      )
      continue
    }
    if (looksLikeIsupBody(part.contentType)) {
      const isupPlan = buildIsupBodyPlan(buffer, part.bodySpan)
      for (const op of isupPlan.operations) {
        operations.push({ ...op, portContext: 'signaling' })
      }
      coverage.push(...isupPlan.coverage)
      if (isupPlan.issues.length) issues.push(...isupPlan.issues)
      continue
    }

    if (looksLikeCstaContentType(part.contentType)) {
      const base = part.contentType?.trim().split(';')[0]?.trim().toLowerCase() ?? ''
      const bodyText = decodeLatin1Span(buffer, part.bodySpan)
      if (
        base === 'application/csta+xml'
        || base === 'application/x-csta+xml'
        || (base.includes('csta') && looksLikeCstaXmlText(bodyText))
        || ((base === 'text/xml' || base === 'application/xml') && looksLikeCstaXmlText(bodyText))
      ) {
        appendCstaOps(operations, message, buffer, part.bodySpan, coverage, issues)
        continue
      }
    }

    if (looksLikePidfContentType(part.contentType)) {
      appendLocationOps(operations, buffer, part.bodySpan, coverage, issues, 'sip-pidf', buildPidfLoBodyPlan)
      continue
    }
    if (looksLikeLostContentType(part.contentType)) {
      appendLocationOps(operations, buffer, part.bodySpan, coverage, issues, 'sip-lost', buildLostBodyPlan)
      continue
    }
    {
      const base = part.contentType?.trim().split(';')[0]?.trim().toLowerCase() ?? ''
      if (base === 'text/xml' || base === 'application/xml') {
        const bodyText = decodeLatin1Span(buffer, part.bodySpan)
        if (looksLikeLostXmlText(bodyText)) {
          appendLocationOps(operations, buffer, part.bodySpan, coverage, issues, 'sip-lost', buildLostBodyPlan)
          continue
        }
        if (looksLikePidfXmlText(bodyText)) {
          appendLocationOps(operations, buffer, part.bodySpan, coverage, issues, 'sip-pidf', buildPidfLoBodyPlan)
          continue
        }
      }
    }

    operations.push(redactOp(part.bodySpan, SIP_REDACT_MASK_BYTE))
    coverage.push({
      protocol: 'sip-body',
      offset: part.bodySpan.offset,
      length: part.bodySpan.length,
      status: 'redacted',
    })
  }
}

function appendMcpttFamilyOps(
  operations: SipBodyOperation[],
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  coverage: LayerCoverage[],
  protocol: SipBodyCoverageProtocol,
  planner: (buffer: Uint8Array, bodySpan: ByteSpan) => readonly {
    readonly span: ByteSpan
    readonly action: 'map' | 'redact'
    readonly mappingCategory: string | null
    readonly canonicalText: string
    readonly maskByte: number
  }[],
): void {
  const planned = planner(buffer, bodySpan)
  for (const op of planned) {
    operations.push({
      span: op.span,
      action: op.action,
      mappingCategory: op.mappingCategory,
      canonicalText: op.canonicalText,
      maskByte: op.maskByte,
      portContext: 'signaling',
    })
  }
  coverage.push({
    protocol,
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: 'covered',
  })
}

function appendRadioOps(
  operations: SipBodyOperation[],
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  coverage: LayerCoverage[],
): void {
  const radioPlan = buildRadioProtocolBodyPlan(buffer, bodySpan)
  if (radioPlan.ok) {
    for (const op of radioPlan.operations) {
      operations.push({
        span: op.span,
        action: op.action,
        mappingCategory: op.mappingCategory,
        canonicalText: op.canonicalText,
        maskByte: op.maskByte ?? SIP_REDACT_MASK_BYTE,
        portContext: 'signaling',
      })
    }
    coverage.push({
      protocol: 'radio-protocol-body',
      offset: bodySpan.offset,
      length: bodySpan.length,
      status: 'covered',
    })
    return
  }
  operations.push(redactOp(bodySpan, SIP_REDACT_MASK_BYTE))
  coverage.push({
    protocol: 'radio-protocol-body',
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: 'malformed',
  })
}

function pushSdpPlanOps(
  operations: SipBodyOperation[],
  buffer: Uint8Array,
  session: import('../sdp/types').SdpSession,
): void {
  const { entities } = extractSdpEntities(session, buffer, {
    policy: DEFAULT_SDP_REDACTION_POLICY,
  })
  const sdpPlan = buildSdpRedactionPlan(entities)
  for (const op of sdpPlan.operations) {
    const portContext: PortContext = op.mappingCategory === 'port' ? 'media' : 'signaling'
    operations.push({
      span: op.span,
      action: op.action,
      mappingCategory: op.mappingCategory,
      canonicalText: op.canonicalText,
      maskByte: op.maskByte ?? SDP_REDACT_MASK_BYTE,
      portContext,
      ...(op.sessionIdForVersion !== undefined
        ? { sessionIdForVersion: op.sessionIdForVersion }
        : {}),
    })
  }
}

function sipHeaderValue(message: SipMessage, canonicalName: string): string | null {
  for (const h of message.headers) {
    if (h.canonicalNameText === canonicalName) return h.valueText.trim()
  }
  return null
}

function appendCstaOps(
  operations: SipBodyOperation[],
  message: SipMessage,
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const identityScope = cstaIdentityScopeForUaCsta(sipHeaderValue(message, 'call-id'))
  const planned = buildCstaXmlBodyPlan(
    buffer,
    bodySpan,
    identityScope,
    protocolGraphCaptureGeneration(),
  )
  for (const issue of planned.issues) issues.push(issue)
  for (const op of planned.operations) {
    operations.push({
      span: op.span,
      action: op.action,
      mappingCategory: op.mappingCategory,
      canonicalText: op.canonicalText,
      maskByte: op.maskByte,
      portContext: 'signaling',
    })
  }
  coverage.push({
    protocol: 'sip-csta',
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: planned.issues.includes('csta-xxe-forbidden') ? 'malformed' : 'covered',
  })
}

function appendLocationOps(
  operations: SipBodyOperation[],
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  coverage: LayerCoverage[],
  issues: string[],
  protocol: 'sip-pidf' | 'sip-lost',
  planner: typeof buildPidfLoBodyPlan,
): void {
  const planned = planner(buffer, bodySpan)
  for (const issue of planned.issues) issues.push(issue)
  for (const op of planned.operations) {
    operations.push({
      span: op.span,
      action: op.action,
      mappingCategory: op.mappingCategory,
      canonicalText: op.canonicalText,
      maskByte: op.maskByte,
      portContext: 'signaling',
    })
  }
  const xxe = planned.issues.some((i) => i.includes('xxe'))
  coverage.push({
    protocol,
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: xxe ? 'malformed' : 'covered',
  })
}

function redactOp(span: ByteSpan, maskByte: number): SipBodyOperation {
  return {
    span,
    action: 'redact',
    mappingCategory: null,
    canonicalText: '',
    maskByte,
    portContext: 'signaling',
  }
}
