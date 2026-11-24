/**
 * T-01.F — application dispatch registry (strangler over engine.ts if-chain).
 * Handlers migrate from inline branches to registry entries keyed by APPLICATION_HANDLER_ORDER id.
 */

import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import { MediaFlowIndex as MediaFlowIndexCtor } from '../discovery/mediaFlowIndex'
import type { MappingLike } from '../anonymization/mapping'
import {
  APPLICATION_HANDLER_ORDER,
  type ApplicationHandlerId,
} from '../kernel/applicationHandlers.ts'
import { tryKernelNativeApplicationSanitize } from '../kernel/sanitizeBridge.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { AppLayerResult, LayerCoverage, SanitizationPolicy } from './types.ts'
import type {
  ApplicationDispatchContext,
  ApplicationDispatchEntry,
  ApplicationDispatchHit,
  ApplicationFlowEndpoint,
} from './applicationDispatchTypes.ts'
import { APPLICATION_CLUSTER_DISPATCH_ENTRIES } from './applicationDispatchRegistryClusters.ts'

export type {
  ApplicationDispatchContext,
  ApplicationDispatchEntry,
  ApplicationDispatchHit,
  ApplicationFlowEndpoint,
} from './applicationDispatchTypes.ts'
import { sanitizeDns } from './dns.ts'
import { sanitizeDhcpv4, sanitizeDhcpv6 } from './dhcp.ts'
import { looksLikeTlsRecord } from './mediaPolicy.ts'
import { sanitizeTls } from './tls.ts'
import { sanitizeSsh, looksLikeSsh } from './ssh.ts'
import { sanitizeQuic, looksLikeQuicLongHeader } from './quic.ts'
import { sanitizeIke, isIkePort, looksLikeIke } from './ike.ts'
import { sanitizeDtls, looksLikeDtls } from './dtls.ts'
import {
  sanitizeOpenVpn,
  looksLikeOpenVpn,
  looksLikeOpenVpnTcp,
  isOpenVpnPortHint,
} from './openvpn.ts'
import { sanitizeWireGuard, looksLikeWireGuard } from './wireguard.ts'
import { isGtpPortHint } from './gtp.ts'
import { classifySipPayload, isSipPortHint } from '../protocols/application/sip/classify.ts'
import { recordSipSdpDiscoveryIntents } from '../protocols/application/sip/discoverIntents.ts'
import { planSipBodyOperations } from '../protocols/application/sip/bodyOperations.ts'
import { emitSiprecMetadataKernelFacts } from '../kernel/siprecKernelFacts.ts'
import { sanitizeSipMessage } from './sip.ts'
import { classifyMgcpPayload, isMgcpPortHint } from '../protocols/application/mgcp/parse.ts'
import { recordMgcpDiscoveryIntents } from '../protocols/application/mgcp/discoverIntents.ts'
import { sanitizeMgcpMessageBatch } from './mgcp.ts'
import { sanitizeCsta, looksLikeCsta } from './csta.ts'
import {
  sanitizeAmi,
  sanitizeAri,
  isAmiPortHint,
  isAriPortHint,
  looksLikeAmi,
  looksLikeAri,
} from './asterisk/index.ts'
import { sanitizeH248, looksLikeH248Text, looksLikeH248Binary, isH248PortHint } from './h248.ts'
import { sanitizeRtsp, looksLikeRtsp, isRtspPortHint } from './rtsp.ts'
import { sanitizeIax2, looksLikeIax2, isIax2PortHint } from './iax2.ts'
import { sanitizeSkinny, looksLikeSkinny, isSkinnyPortHint } from './skinny.ts'
import {
  sanitizeH323,
  sanitizeH323Ras,
  looksLikeTpktQ931,
  isH323PortHint,
  isH323RasPortHint,
} from './h323.ts'
import { sanitizeStun, looksLikeStun } from './stun.ts'
import { sanitizeMsrp, looksLikeMsrp } from './msrp.ts'
import { sanitizeBfcp, looksLikeBfcp } from './bfcp.ts'
import { sanitizeZrtp, looksLikeZrtp } from './zrtp.ts'
import { sanitizeT38Udptl, looksLikeUdptl } from './t38.ts'
import { sanitizeSmpp, isSmppPortHint, looksLikeSmpp } from './smpp.ts'
import { sanitizeRtpOrSrtp } from './rtp.ts'
import { sanitizeRtcp } from './rtcp.ts'
import { applyVoipMediaPolicy } from './mediaPolicy.ts'
import { isStripPayloadMediaPolicy } from './types.ts'
import { createMaskFill } from './maskFill.ts'
import { tcpTransportSessionKey } from './protocolGraphState.ts'

const DNS_PORT = 53
const MDNS_PORT = 5353
const DHCPV4_SERVER_PORT = 67
const DHCPV4_CLIENT_PORT = 68
const DHCPV6_SERVER_PORT = 547
const DHCPV6_CLIENT_PORT = 546

export const APPLICATION_DISPATCH_REGISTRY = new Map<
  ApplicationHandlerId,
  ApplicationDispatchEntry
>()

function registerApplicationDispatch(entry: ApplicationDispatchEntry): void {
  if (APPLICATION_DISPATCH_REGISTRY.has(entry.id)) {
    throw new Error(`Duplicate application dispatch registry id: ${entry.id}`)
  }
  APPLICATION_DISPATCH_REGISTRY.set(entry.id, entry)
}

function dispatchDns(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!ctx.policy.dns) return null
  const { srcPort, dstPort, transport } = ctx
  if (
    srcPort !== DNS_PORT
    && dstPort !== DNS_PORT
    && srcPort !== MDNS_PORT
    && dstPort !== MDNS_PORT
  ) {
    return null
  }

  const { data, offset, length, collector, mapping, intents, packetIndex, coverage, lastCovered } =
    ctx
  let dnsOffset = offset
  let dnsLength = length
  if (transport === 'tcp' && length > 2) {
    const msgLen = (data[offset]! << 8) | data[offset + 1]!
    if (msgLen + 2 > length) {
      coverage.push({ protocol: 'dns', offset, length, status: 'requires-reassembly' })
      ctx.issues.push('DNS over TCP spans multiple segments')
      return { lastCoveredOffset: lastCovered }
    }
    dnsOffset = offset + 2
    dnsLength = msgLen
  }

  if (sanitizeDns(data, dnsOffset, dnsLength, collector, mapping, intents, packetIndex)) {
    coverage.push({ protocol: 'dns', offset, length, status: 'covered' })
    return { lastCoveredOffset: offset + length }
  }
  coverage.push({ protocol: 'dns', offset, length, status: 'malformed' })
  return { lastCoveredOffset: lastCovered }
}

function mergeAppLayerResult(
  ctx: ApplicationDispatchContext,
  result: AppLayerResult,
  lastCoveredFallback: number,
): ApplicationDispatchHit {
  ctx.coverage.push(...result.coverage)
  if (result.issues) {
    for (const issue of result.issues) ctx.issues.push(issue)
  }
  const maxOffset = result.coverage.reduce(
    (max, c) => Math.max(max, c.offset + c.length),
    lastCoveredFallback,
  )
  return { lastCoveredOffset: maxOffset }
}

function dispatchDhcpv4(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!ctx.policy.dhcp) return null
  const { srcPort, dstPort, transport } = ctx
  if (transport !== 'udp') return null
  if (
    srcPort !== DHCPV4_SERVER_PORT
    && srcPort !== DHCPV4_CLIENT_PORT
    && dstPort !== DHCPV4_SERVER_PORT
    && dstPort !== DHCPV4_CLIENT_PORT
  ) {
    return null
  }

  const { data, offset, length, collector, mapping, intents, packetIndex, coverage, lastCovered } =
    ctx
  if (sanitizeDhcpv4(data, offset, length, collector, mapping, intents, packetIndex)) {
    coverage.push({ protocol: 'dhcpv4', offset, length, status: 'covered' })
    return { lastCoveredOffset: offset + length }
  }
  coverage.push({ protocol: 'dhcpv4', offset, length, status: 'malformed' })
  return { lastCoveredOffset: lastCovered }
}

function dispatchDhcpv6(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!ctx.policy.dhcp) return null
  const { srcPort, dstPort, transport } = ctx
  if (transport !== 'udp') return null
  if (
    srcPort !== DHCPV6_SERVER_PORT
    && srcPort !== DHCPV6_CLIENT_PORT
    && dstPort !== DHCPV6_SERVER_PORT
    && dstPort !== DHCPV6_CLIENT_PORT
  ) {
    return null
  }

  const { data, offset, length, collector, mapping, intents, packetIndex, coverage, lastCovered } =
    ctx
  if (sanitizeDhcpv6(data, offset, length, collector, mapping, intents, packetIndex)) {
    coverage.push({ protocol: 'dhcpv6', offset, length, status: 'covered' })
    return { lastCoveredOffset: offset + length }
  }
  coverage.push({ protocol: 'dhcpv6', offset, length, status: 'malformed' })
  return { lastCoveredOffset: lastCovered }
}

function dispatchTls(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, policy, collector, mapping, intents, packetIndex, issues, lastCovered } =
    ctx
  if (!policy.tls && !(policy.sipSdp && looksLikeTlsRecord(data, offset, length))) {
    return null
  }

  const tlsResult = sanitizeTls(data, offset, length, collector, mapping, intents, packetIndex)
  if (!tlsResult) return null

  ctx.coverage.push(...tlsResult.coverage)
  if (tlsResult.issues) {
    for (const issue of tlsResult.issues) issues.push(issue)
  }
  if (
    tlsResult.coverage.some(
      (c) =>
        (c.protocol === 'tls-clienthello'
          || c.protocol === 'tls-serverhello'
          || c.protocol === 'tls-certificate'
          || c.protocol === 'tls')
        && (c.status === 'covered' || c.status === 'redacted'),
    )
  ) {
    issues.push('crypto-integrity-modified:tls')
  }
  const maxOffset = tlsResult.coverage.reduce(
    (max, c) => Math.max(max, c.offset + c.length),
    lastCovered,
  )
  return { lastCoveredOffset: maxOffset }
}

function dispatchSsh(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, collector, mapping, intents, packetIndex, policy, lastCovered } =
    ctx
  if (transport !== 'tcp' || !looksLikeSsh(data, offset, length)) return null

  const sshResult = sanitizeSsh(
    data,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    policy,
  )
  if (!sshResult) return null
  return mergeAppLayerResult(ctx, sshResult, lastCovered)
}

function dispatchOpenVpn(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { transport } = ctx
  if (transport !== 'udp' && transport !== 'tcp') return null

  const { data, offset, length, srcPort, dstPort, collector, mapping, intents, packetIndex } = ctx
  const ovpnProbe =
    transport === 'tcp'
      ? looksLikeOpenVpnTcp(data, offset, length)
      : looksLikeOpenVpn(data, offset, length)
  if (
    !isOpenVpnPortHint(srcPort, dstPort)
    && (isGtpPortHint(srcPort, dstPort) || !ovpnProbe)
  ) {
    return null
  }

  const ovpn = sanitizeOpenVpn(
    data,
    offset,
    length,
    srcPort,
    dstPort,
    collector,
    mapping,
    intents,
    packetIndex,
    transport,
  )
  if (!ovpn) return null
  ctx.coverage.push(...ovpn.coverage)
  if (ovpn.issues) for (const issue of ovpn.issues) ctx.issues.push(issue)
  return { lastCoveredOffset: offset + length }
}

function dispatchDtls(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, collector, mapping, intents, packetIndex, lastCovered } =
    ctx
  if (transport !== 'udp' || !looksLikeDtls(data, offset, length)) return null

  const dtlsResult = sanitizeDtls(data, offset, length, collector, mapping, intents, packetIndex)
  if (!dtlsResult) return null
  return mergeAppLayerResult(ctx, dtlsResult, lastCovered)
}

function dispatchQuic(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort, collector, mapping, intents, packetIndex, lastCovered } =
    ctx
  if (
    transport !== 'udp'
    || !looksLikeQuicLongHeader(data, offset, length)
    || isIax2PortHint(srcPort, dstPort)
  ) {
    return null
  }

  const quicResult = sanitizeQuic(
    data,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
  )
  if (!quicResult) return null
  return mergeAppLayerResult(ctx, quicResult, lastCovered)
}

function dispatchIke(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort, collector, mapping, intents, packetIndex, lastCovered } =
    ctx
  if (transport !== 'udp') return null
  const nattUdp4500 = srcPort === 4500 || dstPort === 4500
  if (!isIkePort(srcPort, dstPort) || !looksLikeIke(data, offset, length, { nattUdp4500 })) {
    return null
  }

  const ikeResult = sanitizeIke(
    data,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    { nattUdp4500 },
  )
  if (!ikeResult) return null
  return mergeAppLayerResult(ctx, ikeResult, lastCovered)
}

function dispatchWireGuard(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, collector, mapping, intents, packetIndex, lastCovered } =
    ctx
  if (transport !== 'udp' || !looksLikeWireGuard(data, offset, length)) return null

  const wgResult = sanitizeWireGuard(
    data,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
  )
  if (!wgResult) return null
  return mergeAppLayerResult(ctx, wgResult, lastCovered)
}

function dispatchFullPayloadAppResult(
  ctx: ApplicationDispatchContext,
  result: AppLayerResult | null,
): ApplicationDispatchHit | null {
  if (!result) return null
  ctx.coverage.push(...result.coverage)
  if (result.issues) {
    for (const issue of result.issues) ctx.issues.push(issue)
  }
  return { lastCoveredOffset: ctx.offset + ctx.length }
}

function recordSipPortFlowHints(
  ctx: ApplicationDispatchContext,
): void {
  if (!ctx.intents) return
  const { transport, srcPort, dstPort } = ctx
  ctx.intents.recordPortFlowHint(`${transport}/${srcPort}`, 'sip')
  ctx.intents.recordPortFlowHint(`${transport}/${dstPort}`, 'sip')
}

function dispatchSip(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.skipAppLayer || !ctx.policy.sipSdp) return null
  const { data, offset, length, srcPort, dstPort, transport, collector, mapping, intents, lastCovered } =
    ctx
  const portHint = isSipPortHint(srcPort, dstPort)
  const classification = classifySipPayload(data, offset, length, { portHint })

  switch (classification.kind) {
    case 'complete': {
      const sipLength = classification.consumed
      ctx.mediaFlowIndex?.registerFromSipMessage(classification.message, data)
      if (intents) {
        intents.recordPortFlowHint(`${transport}/${srcPort}`, 'sip')
        intents.recordPortFlowHint(`${transport}/${dstPort}`, 'sip')
        recordSipSdpDiscoveryIntents(intents, data, classification.message, transport, ctx.packetIndex)
      }
      const sipIssues = sanitizeSipMessage(
        data,
        classification.message,
        transport,
        collector,
        mapping,
        ctx.packetIndex,
      )
      for (const issue of sipIssues) ctx.issues.push(issue)
      const body = classification.message.body
      const headersEnd = body ? body.span.offset : offset + sipLength
      const headerLength = Math.max(0, headersEnd - offset)
      ctx.coverage.push({ protocol: 'sip', offset, length: headerLength, status: 'covered' })
      const bodyPlan = planSipBodyOperations(classification.message, data)
      for (const region of bodyPlan.coverage) ctx.coverage.push(region)
      if (ctx.journal) {
        emitSiprecMetadataKernelFacts({
          message: classification.message,
          buffer: data,
          packetIndex: ctx.packetIndex,
          logicalMessageId: ctx.packetIndex,
          journal: ctx.journal,
          symbolicOps: ctx.kernelSymbolicOps,
        })
      }
      return { lastCoveredOffset: offset + sipLength }
    }
    case 'incomplete':
      ctx.coverage.push({ protocol: 'sip', offset, length, status: 'requires-reassembly' })
      ctx.issues.push('SIP message incomplete')
      return { lastCoveredOffset: lastCovered }
    case 'malformed':
      if (portHint) {
        ctx.coverage.push({ protocol: 'sip', offset, length, status: 'malformed' })
        return { lastCoveredOffset: lastCovered }
      }
      return null
    case 'not-sip':
      return null
  }
}

function dispatchCsta(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'tcp' || !looksLikeCsta(ctx.data, ctx.offset, ctx.length)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  const { flowEndpoint } = ctx
  const csta = sanitizeCsta(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.srcPort,
    ctx.dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    highPrivacy,
    ctx.intents,
    { srcIp: flowEndpoint?.srcIp, dstIp: flowEndpoint?.dstIp },
  )
  return dispatchFullPayloadAppResult(ctx, csta)
}

function dispatchAmi(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort, flowEndpoint } = ctx
  if (transport !== 'tcp' || (!isAmiPortHint(srcPort, dstPort) && !looksLikeAmi(data, offset, length))) {
    return null
  }
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  const amiTransportKey = tcpTransportSessionKey({
    srcIp: flowEndpoint?.srcIp,
    dstIp: flowEndpoint?.dstIp,
    srcPort,
    dstPort,
  })
  const ami = sanitizeAmi(
    data,
    offset,
    length,
    srcPort,
    dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    highPrivacy,
    ctx.intents,
    { transportSessionKey: amiTransportKey },
  )
  return dispatchFullPayloadAppResult(ctx, ami)
}

function dispatchMgcp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!ctx.policy.sipSdp || ctx.transport !== 'udp') return null
  const { data, offset, length, srcPort, dstPort, transport, collector, mapping, intents, lastCovered } =
    ctx
  const portHint = isMgcpPortHint(srcPort, dstPort)
  const classification = classifyMgcpPayload(data, offset, length, { portHint })
  switch (classification.kind) {
    case 'complete': {
      if (intents) {
        intents.recordPortFlowHint(`${transport}/${srcPort}`, 'sip')
        intents.recordPortFlowHint(`${transport}/${dstPort}`, 'sip')
        recordMgcpDiscoveryIntents(intents, data, classification.messages, transport, ctx.packetIndex)
      }
      const analyzed = sanitizeMgcpMessageBatch(
        data,
        classification.messages,
        transport,
        collector,
        mapping,
        ctx.packetIndex,
      )
      for (const issue of analyzed.issues) ctx.issues.push(issue)
      for (const region of analyzed.coverage) ctx.coverage.push(region)
      for (const bundle of analyzed.sdpBundles) {
        ctx.mediaFlowIndex?.registerBundle(bundle, data)
      }
      return { lastCoveredOffset: offset + classification.consumed }
    }
    case 'malformed':
      if (portHint) {
        ctx.coverage.push({ protocol: 'mgcp', offset, length, status: 'malformed' })
        return { lastCoveredOffset: lastCovered }
      }
      return null
    case 'not-mgcp':
      return null
  }
}

function dispatchH248(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, srcPort, dstPort } = ctx
  if (
    !(isH248PortHint(srcPort, dstPort)
      && (looksLikeH248Text(data, offset, length) || looksLikeH248Binary(data, offset, length)))
    && !looksLikeH248Text(data, offset, length)
  ) {
    return null
  }
  const h248 = sanitizeH248(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
    ctx.mediaFlowIndex,
  )
  if (!h248) return null
  recordSipPortFlowHints(ctx)
  return dispatchFullPayloadAppResult(ctx, h248)
}

function dispatchRtsp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || (!isRtspPortHint(srcPort, dstPort) && !looksLikeRtsp(data, offset, length))) {
    return null
  }
  if (!looksLikeRtsp(data, offset, length) || (!isRtspPortHint(srcPort, dstPort) && data[offset] === 0x24)) {
    return null
  }
  const rtsp = sanitizeRtsp(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
    ctx.mediaFlowIndex,
  )
  if (!rtsp) return null
  recordSipPortFlowHints(ctx)
  return dispatchFullPayloadAppResult(ctx, rtsp)
}

function dispatchIax2(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isIax2PortHint(srcPort, dstPort) || !looksLikeIax2(data, offset, length)) {
    return null
  }
  const iax = sanitizeIax2(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex)
  if (!iax) return null
  recordSipPortFlowHints(ctx)
  return dispatchFullPayloadAppResult(ctx, iax)
}

function dispatchSkinny(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'tcp'
    || !isSkinnyPortHint(srcPort, dstPort)
    || !looksLikeSkinny(data, offset, length)
  ) {
    return null
  }
  const skinny = sanitizeSkinny(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
  )
  if (!skinny) return null
  recordSipPortFlowHints(ctx)
  return dispatchFullPayloadAppResult(ctx, skinny)
}

function dispatchH323(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport === 'tcp' && isH323PortHint(srcPort, dstPort) && looksLikeTpktQ931(data, offset, length)) {
    const h323 = sanitizeH323(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex)
    if (h323) {
      recordSipPortFlowHints(ctx)
      return dispatchFullPayloadAppResult(ctx, h323)
    }
  }
  if (transport === 'udp' && isH323RasPortHint(srcPort, dstPort)) {
    const ras = sanitizeH323Ras(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex)
    return dispatchFullPayloadAppResult(ctx, ras)
  }
  return null
}

function dispatchStun(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort, collector, mapping, intents, issues } = ctx
  if (!looksLikeStun(data, offset, length)) return null
  const stunResult = sanitizeStun(data, offset, length, collector, mapping, intents, ctx.packetIndex, issues)
  if (!stunResult.ok) return null
  if (intents) {
    intents.recordPortFlowHint(`${transport}/${srcPort}`, 'stun')
    intents.recordPortFlowHint(`${transport}/${dstPort}`, 'stun')
  }
  ctx.coverage.push({
    protocol: 'stun',
    offset,
    length,
    status: stunResult.hadMessageIntegrity ? 'redacted' : 'covered',
  })
  return { lastCoveredOffset: offset + length }
}

function dispatchMsrp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'tcp' || !looksLikeMsrp(ctx.data, ctx.offset, ctx.length)) return null
  const msrp = sanitizeMsrp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
  )
  return dispatchFullPayloadAppResult(ctx, msrp)
}

function dispatchBfcp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'udp' || !looksLikeBfcp(ctx.data, ctx.offset, ctx.length)) return null
  const bfcp = sanitizeBfcp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
  )
  return dispatchFullPayloadAppResult(ctx, bfcp)
}

function dispatchZrtp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'udp' || !looksLikeZrtp(ctx.data, ctx.offset, ctx.length)) return null
  const zrtp = sanitizeZrtp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
  )
  return dispatchFullPayloadAppResult(ctx, zrtp)
}

function dispatchT38(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { transport, data, offset, length, flowEndpoint, dstPort, srcPort } = ctx
  if (transport !== 'udp' || !flowEndpoint || !looksLikeUdptl(data, offset, length)) return null
  const mediaIndex = ctx.mediaFlowIndex
  const t38Endpoint =
    mediaIndex?.isLikelyT38Endpoint(flowEndpoint.dstIp, dstPort)
    || mediaIndex?.isLikelyT38Endpoint(flowEndpoint.srcIp, srcPort)
  if (!t38Endpoint) return null
  const t38 = sanitizeT38Udptl(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
  )
  return dispatchFullPayloadAppResult(ctx, t38)
}

function dispatchVoipMedia(
  ctx: ApplicationDispatchContext,
  rtcpOnly: boolean,
): ApplicationDispatchHit | null {
  if (ctx.transport !== 'udp' || !ctx.flowEndpoint) return null
  const mediaIndex = ctx.mediaFlowIndex ?? new MediaFlowIndexCtor()
  const { data, offset, length, srcPort, dstPort, policy, coverage, issues, lastCovered, intents } = ctx
  const flowEndpoint = ctx.flowEndpoint
  const mediaClass = mediaIndex.classify({
    srcIp: flowEndpoint.srcIp,
    dstIp: flowEndpoint.dstIp,
    srcPort,
    dstPort,
    payload: data,
    payloadOffset: offset,
    payloadLength: length,
  })
  if (!mediaClass) return null
  const isRtcp = mediaClass.kind === 'rtcp'
  if (rtcpOnly !== isRtcp) return null

  if (intents) {
    const mediaFlow = isRtcp ? 'rtcp' : 'rtp'
    intents.recordPortFlowHint(`udp/${srcPort}`, mediaFlow)
    intents.recordPortFlowHint(`udp/${dstPort}`, mediaFlow)
  }
  const mediaResult = applyVoipMediaPolicy(mediaClass, policy, offset, length, coverage, issues, data)
  if (mediaResult.drop) {
    return { lastCoveredOffset: lastCovered, drop: true }
  }
  if (
    (isStripPayloadMediaPolicy(policy.mediaPolicy) || mediaResult.telephoneEvent)
    && mediaResult.status === 'redacted'
  ) {
    if (mediaResult.protocol === 'rtcp') {
      sanitizeRtcp(data, offset, length, ctx.collector, ctx.mapping, intents, ctx.packetIndex)
    } else if (mediaResult.protocol === 'rtp' || mediaResult.protocol === 'srtp') {
      const knownExt = new Set(mediaClass.entry?.headerExtensionIds ?? [])
      sanitizeRtpOrSrtp(
        data,
        offset,
        length,
        ctx.collector,
        ctx.mapping,
        intents,
        ctx.packetIndex,
        mediaResult.protocol,
        knownExt,
      )
    } else {
      const fill = createMaskFill({
        length,
        packetIndex: ctx.packetIndex,
        offset,
        domain: `media-strip:${mediaResult.protocol}`,
      })
      ctx.collector.maskRange(offset, fill)
      intents?.recordMaskRange(ctx.packetIndex, offset, length, 'strip-payload', mediaResult.protocol)
    }
    return { lastCoveredOffset: offset + length }
  }
  if (mediaResult.status === 'unsupported' || mediaResult.status === 'preserved-unsafe') {
    return { lastCoveredOffset: lastCovered }
  }
  return { lastCoveredOffset: offset + length }
}

function dispatchRtp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return dispatchVoipMedia(ctx, false)
}

function dispatchRtcp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return dispatchVoipMedia(ctx, true)
}

function dispatchSmpp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort, flowEndpoint } = ctx
  if (
    transport !== 'tcp'
    || (!isSmppPortHint(srcPort, dstPort) && !looksLikeSmpp(data, offset, length))
    || !looksLikeSmpp(data, offset, length)
  ) {
    return null
  }
  const smppTransportKey = tcpTransportSessionKey({
    srcIp: flowEndpoint?.srcIp,
    dstIp: flowEndpoint?.dstIp,
    srcPort,
    dstPort,
  })
  const smppResult = sanitizeSmpp(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
    { transportSessionKey: smppTransportKey },
  )
  return dispatchFullPayloadAppResult(ctx, smppResult)
}

function dispatchAri(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || (!isAriPortHint(srcPort, dstPort) && !looksLikeAri(data, offset, length))) {
    return null
  }
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  const ari = sanitizeAri(
    data,
    offset,
    length,
    srcPort,
    dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    highPrivacy,
    ctx.intents,
  )
  return dispatchFullPayloadAppResult(ctx, ari)
}

/** Registered for APPLICATION_HANDLER_ORDER parity; sanitize runs on LINKTYPE_LINUX_LAPD / SCTP IUA. */
function dispatchLapd(_ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return null
}

/** Child of LAPD / H.323 TPKT — no bare TCP/UDP app branch in engine (T51). */
function dispatchQ931(_ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return null
}

/** SCTP PPID IUA only (see sctp.ts); UDP/TCP content probe would false-positive on VoIP/HTTP. */
function dispatchIua(_ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return null
}

function dispatchKernelNative(
  protocolId: ApplicationHandlerId,
): (ctx: ApplicationDispatchContext) => ApplicationDispatchHit | null {
  return (ctx) => {
    if (ctx.transport !== 'tcp' && ctx.transport !== 'udp') return null
    const kernelHit = tryKernelNativeApplicationSanitize({
      buffer: ctx.data,
      offset: ctx.offset,
      length: ctx.length,
      srcPort: ctx.srcPort,
      dstPort: ctx.dstPort,
      transport: ctx.transport,
      collector: ctx.collector,
      mapping: ctx.mapping,
      intents: ctx.intents,
      coverage: ctx.coverage,
      issues: ctx.issues,
      packetIndex: ctx.packetIndex,
      protocolId,
    })
    if (!kernelHit) return null
    return { lastCoveredOffset: kernelHit.lastCoveredOffset }
  }
}

registerApplicationDispatch({ id: 'dns', dispatch: dispatchDns })
registerApplicationDispatch({ id: 'dhcpv4', dispatch: dispatchDhcpv4 })
registerApplicationDispatch({ id: 'dhcpv6', dispatch: dispatchDhcpv6 })
registerApplicationDispatch({ id: 'tls', dispatch: dispatchTls })
registerApplicationDispatch({ id: 'ssh', dispatch: dispatchSsh })
registerApplicationDispatch({ id: 'quic', dispatch: dispatchQuic })
registerApplicationDispatch({ id: 'dtls', dispatch: dispatchDtls })
registerApplicationDispatch({ id: 'ike', dispatch: dispatchIke })
registerApplicationDispatch({ id: 'openvpn', dispatch: dispatchOpenVpn })
registerApplicationDispatch({ id: 'wireguard', dispatch: dispatchWireGuard })
registerApplicationDispatch({ id: 'sip', dispatch: dispatchSip })
registerApplicationDispatch({ id: 'csta', dispatch: dispatchCsta })
registerApplicationDispatch({ id: 'ami', dispatch: dispatchAmi })
registerApplicationDispatch({ id: 'mgcp', dispatch: dispatchMgcp })
registerApplicationDispatch({ id: 'h248', dispatch: dispatchH248 })
registerApplicationDispatch({ id: 'rtsp', dispatch: dispatchRtsp })
registerApplicationDispatch({ id: 'iax2', dispatch: dispatchIax2 })
registerApplicationDispatch({ id: 'skinny', dispatch: dispatchSkinny })
registerApplicationDispatch({ id: 'h323', dispatch: dispatchH323 })
registerApplicationDispatch({ id: 'stun', dispatch: dispatchStun })
registerApplicationDispatch({ id: 'lapd', dispatch: dispatchLapd })
registerApplicationDispatch({ id: 'q931', dispatch: dispatchQ931 })
registerApplicationDispatch({ id: 'iua', dispatch: dispatchIua })
registerApplicationDispatch({ id: 'msrp', dispatch: dispatchMsrp })
registerApplicationDispatch({ id: 'bfcp', dispatch: dispatchBfcp })
registerApplicationDispatch({ id: 'zrtp', dispatch: dispatchZrtp })
registerApplicationDispatch({ id: 't38', dispatch: dispatchT38 })
registerApplicationDispatch({ id: 'smpp', dispatch: dispatchSmpp })
registerApplicationDispatch({ id: 'rtp', dispatch: dispatchRtp })
registerApplicationDispatch({ id: 'rtcp', dispatch: dispatchRtcp })
registerApplicationDispatch({ id: 'ari', dispatch: dispatchAri })
registerApplicationDispatch({
  id: 'rnd-dispatch-lite',
  dispatch: dispatchKernelNative('rnd-dispatch-lite'),
})
registerApplicationDispatch({
  id: 'echo-udp-example',
  dispatch: dispatchKernelNative('echo-udp-example'),
})

for (const entry of APPLICATION_CLUSTER_DISPATCH_ENTRIES) {
  registerApplicationDispatch(entry)
}

/**
 * Handler ids still implemented inline in engine.ts::handleApplicationPayload.
 * Shrinks as handlers migrate into APPLICATION_DISPATCH_REGISTRY.
 */
export const TEMP_LEGACY_INLINE_HANDLERS: ReadonlySet<ApplicationHandlerId> = new Set(
  APPLICATION_HANDLER_ORDER.map((h) => h.id).filter((id) => !APPLICATION_DISPATCH_REGISTRY.has(id)),
)

/** Walk APPLICATION_HANDLER_ORDER; first registered handler that claims the payload wins. */
export function dispatchRegisteredApplicationHandlers(
  ctx: ApplicationDispatchContext,
): ApplicationDispatchHit | null {
  for (const { id } of APPLICATION_HANDLER_ORDER) {
    const entry = APPLICATION_DISPATCH_REGISTRY.get(id)
    if (!entry) continue
    const hit = entry.dispatch(ctx)
    if (hit) return hit
  }
  return null
}
