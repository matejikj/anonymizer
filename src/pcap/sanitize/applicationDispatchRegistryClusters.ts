/**
 * T-01.F — migrated application dispatch handlers (clustered strangler slices).
 * Registered from applicationDispatchRegistry.ts in APPLICATION_HANDLER_ORDER.
 */

import type { IntentCollector } from '../discovery/intentCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { PatchCollector } from './PatchCollector.ts'
import type {
  ApplicationDispatchContext,
  ApplicationDispatchEntry,
  ApplicationDispatchHit,
} from './applicationDispatchTypes.ts'
import type { AppLayerResult } from './types.ts'
import { sanitizeHttp } from './http.ts'
import { sanitizeHttp2, looksLikeHttp2Preface, looksLikeHttp2Frame } from './http2.ts'
import { sanitizeWebSocket, looksLikeWebSocketFrame } from './websocket.ts'
import { sanitizeSyslog, looksLikeSyslog, isSyslogPortHint } from './syslog.ts'
import { sanitizeSnmp, looksLikeSnmp, isSnmpPortHint } from './snmp.ts'
import { sanitizeNtp, looksLikeNtp, isNtpPortHint } from './ntp.ts'
import { sanitizeTftp, looksLikeTftp, isTftpPortHint } from './tftp.ts'
import { sanitizeLlmnr, looksLikeLlmnr, isLlmnrPortHint } from './llmnr.ts'
import { sanitizeNbns, looksLikeNbns, isNbnsPortHint } from './nbns.ts'
import { sanitizeSsdp, looksLikeSsdp, isSsdpPortHint } from './ssdp.ts'
import { sanitizeWsDiscovery, looksLikeWsDiscovery, isWsDiscoveryPortHint } from './wsDiscovery.ts'
import { sanitizeRadius, looksLikeRadius, isRadiusPortHint } from './radius.ts'
import { sanitizeTacacs, looksLikeTacacs, isTacacsPortHint } from './tacacs.ts'
import { sanitizeDiameter, looksLikeDiameter, isDiameterPortHint } from './diameter.ts'
import { sanitizeHep, looksLikeHep, isHepPortHint } from './hep.ts'
import { sanitizeTzsp, looksLikeTzsp, isTzspPortHint } from './tzsp.ts'
import {
  sanitizeNetflowV5,
  sanitizeNetflowV9OrIpfix,
  looksLikeNetflowV5,
  looksLikeNetflowV9OrIpfix,
  isNetflowV5PortHint,
  isIpfixPortHint,
} from './flowExport.ts'
import { sanitizeSflow, looksLikeSflow, isSflowPortHint } from './sflow.ts'
import { sanitizeLdap, looksLikeLdap, isLdapPortHint } from './ldap.ts'
import { sanitizeKerberos, looksLikeKerberos, isKerberosPortHint } from './kerberos.ts'
import {
  sanitizeGtp,
  looksLikeGtp,
  isGtpPortHint,
  isGtpUPort,
} from './gtp.ts'
import {
  sanitizeSmtp,
  sanitizeImap,
  sanitizePop3,
  looksLikeSmtp,
  looksLikeImap,
  looksLikePop3,
  isSmtpPortHint,
  isImapPortHint,
  isPop3PortHint,
} from './enterpriseMail.ts'
import { sanitizeFtp, looksLikeFtp, isFtpPortHint } from './ftp.ts'
import { sanitizeTelnet, looksLikeTelnet, isTelnetPortHint } from './telnet.ts'
import { sanitizeSmb, looksLikeSmb, isSmbPortHint } from './smb.ts'
import {
  sanitizeRip,
  sanitizeBfd,
  sanitizeHsrpGlbp,
  sanitizeBgp,
  sanitizeLdp,
} from './routing/index.ts'
import {
  sanitizeRdp,
  sanitizeVnc,
  sanitizeX11,
  sanitizeIpmi,
  sanitizeCitrix,
  sanitizeAmtHttp,
  isRdpPortHint,
  isVncPortHint,
  isX11PortHint,
  isIpmiPortHint,
  isCitrixPortHint,
  isAmtPortHint,
} from './remoteAccess/index.ts'
import { sanitizeGsmtap, isGsmtapPortHint } from './wireless/index.ts'
import {
  sanitizeAmqp,
  sanitizeKafka,
  sanitizeNats,
  sanitizeStomp,
  sanitizeXmpp,
  sanitizeGelf,
  sanitizeFluentForward,
  sanitizeOtlp,
  isAmqpPortHint,
  isKafkaPortHint,
  isNatsPortHint,
  looksLikeNats,
  isStompPortHint,
  isXmppPortHint,
  isGelfPortHint,
  isFluentPortHint,
  isOtlpPortHint,
} from './messaging/index.ts'
import {
  sanitizePostgres,
  sanitizeMysql,
  sanitizeTds,
  sanitizeRedis,
  sanitizeMongodb,
  isPostgresPortHint,
  isMysqlPortHint,
  isTdsPortHint,
  isRedisPortHint,
  isMongodbPortHint,
} from './database/index.ts'
import {
  sanitizeMqtt,
  sanitizeCoap,
  sanitizeModbus,
  sanitizeIec104,
  sanitizeDnp3,
  sanitizeOpcua,
  isMqttPortHint,
  isCoapPortHint,
  isModbusPortHint,
  isIec104PortHint,
  isDnp3PortHint,
  isOpcuaPortHint,
} from './industrial/index.ts'
import {
  sanitizeDcerpc,
  sanitizeIscsi,
  sanitizePortmapper,
  sanitizeNfs,
  isDcerpcPortHint,
  isIscsiPortHint,
  isPortmapperPortHint,
  isNfsPortHint,
  looksLikeDcerpc,
} from './storage/index.ts'
import { sanitizeMrcp, isMrcpPortHint, looksLikeMrcp } from './mrcp.ts'
import { sanitizeCwmp, isCwmpPortHint, looksLikeCwmp } from './cwmp.ts'
import { sanitizeUspRecord, looksLikeUspRecord } from './usp.ts'
import { sanitizeNas, looksLikeNas } from './nas.ts'
import { sanitizeSbi5g, looksLikeSbi } from './sbi5g.ts'
import { sanitizePfcp, looksLikePfcp, isPfcpPortHint } from './pfcp.ts'
import { sanitizeDmr } from './dmr.ts'
import { sanitizeMototrboIpsc } from './mototrbo.ts'

/** Engine reassembly overlay — block app probes that ran after the inline gate in engine.ts. */
function reassemblyOwnsPayload(ctx: ApplicationDispatchContext): boolean {
  return ctx.skipAppLayer === true
}

function hitFullPayload(
  ctx: ApplicationDispatchContext,
  result: AppLayerResult | null,
  drop?: boolean,
): ApplicationDispatchHit | null {
  if (!result) return null
  ctx.coverage.push(...result.coverage)
  if (result.issues) {
    for (const issue of result.issues) ctx.issues.push(issue)
  }
  return { lastCoveredOffset: ctx.offset + ctx.length, drop }
}

function hitCoverageMax(
  ctx: ApplicationDispatchContext,
  result: AppLayerResult,
  drop?: boolean,
): ApplicationDispatchHit {
  ctx.coverage.push(...result.coverage)
  if (result.issues) {
    for (const issue of result.issues) ctx.issues.push(issue)
  }
  const maxOffset = result.coverage.reduce(
    (max, c) => Math.max(max, c.offset + c.length),
    ctx.lastCovered,
  )
  return { lastCoveredOffset: maxOffset, drop }
}

type HighPrivacyTcpSanitize = (
  data: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents: IntentCollector | undefined,
) => AppLayerResult | null

function dispatchHighPrivacyTcp(
  ctx: ApplicationDispatchContext,
  portHint: (srcPort: number, dstPort: number) => boolean,
  sanitize: HighPrivacyTcpSanitize,
): ApplicationDispatchHit | null {
  if (ctx.transport !== 'tcp' || !portHint(ctx.srcPort, ctx.dstPort)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitize(
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
    ),
  )
}

function dispatchPidf(_ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return null
}

function dispatchLost(_ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return null
}

function dispatchGrpc(_ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  return null
}

function dispatchMrcp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'tcp'
    || !(isMrcpPortHint(srcPort, dstPort) || looksLikeMrcp(data, offset, length))
    || !looksLikeMrcp(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeMrcp(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchCwmp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'tcp'
    || !(isCwmpPortHint(srcPort, dstPort) || looksLikeCwmp(data, offset, length))
    || !looksLikeCwmp(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeCwmp(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchUsp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport } = ctx
  if (transport !== 'tcp' || !looksLikeUspRecord(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeUspRecord(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchNas(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length } = ctx
  if (!looksLikeNas(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeNas(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchSbi5g(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport } = ctx
  if (transport !== 'tcp' || !looksLikeSbi(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeSbi5g(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchHttp2(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport } = ctx
  if (
    transport !== 'tcp'
    || !(looksLikeHttp2Preface(data, offset, length) || looksLikeHttp2Frame(data, offset, length))
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeHttp2(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      { preferGrpc: true },
    ),
  )
}

function dispatchHttp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx) || !ctx.policy.http) return null
  const { data, offset, length, srcPort, dstPort } = ctx
  // T41 — NATS CONNECT is an HTTP CONNECT verb on TCP 4222 (legacy engine probed NATS first).
  if (isNatsPortHint(srcPort, dstPort) && looksLikeNats(data, offset, length)) {
    return null
  }
  const httpResult = sanitizeHttp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
    ctx.policy.preset === 'high-privacy',
    { mediaFlowIndex: ctx.mediaFlowIndex },
  )
  if (!httpResult) return null
  ctx.coverage.push(...httpResult.coverage)
  const maxOffset = httpResult.coverage.reduce(
    (max, c) => Math.max(max, c.offset + c.length),
    ctx.lastCovered,
  )
  return { lastCoveredOffset: maxOffset }
}

function dispatchWebSocket(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport } = ctx
  if (transport !== 'tcp' || !looksLikeWebSocketFrame(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeWebSocket(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      {
        mediaFlowIndex: ctx.mediaFlowIndex,
        highPrivacy: ctx.policy.preset === 'high-privacy',
      },
    ),
  )
}

function dispatchSyslog(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, srcPort, dstPort } = ctx
  if (
    !(isSyslogPortHint(srcPort, dstPort) || looksLikeSyslog(data, offset, length))
    || !looksLikeSyslog(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeSyslog(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.policy,
      ctx.payloadTime,
    ),
  )
}

function dispatchSnmp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isSnmpPortHint(srcPort, dstPort) || !looksLikeSnmp(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeSnmp(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchNtp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isNtpPortHint(srcPort, dstPort) || !looksLikeNtp(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeNtp(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
    ),
  )
}

function dispatchTftp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'udp'
    || !(isTftpPortHint(srcPort, dstPort) || looksLikeTftp(data, offset, length, srcPort, dstPort))
    || !looksLikeTftp(data, offset, length, srcPort, dstPort)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeTftp(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.policy.preset === 'high-privacy',
      srcPort,
      dstPort,
    ),
  )
}

function dispatchLlmnr(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, srcPort, dstPort, transport } = ctx
  if (!isLlmnrPortHint(srcPort, dstPort) || !looksLikeLlmnr(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeLlmnr(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex, transport),
  )
}

function dispatchNbns(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isNbnsPortHint(srcPort, dstPort) || !looksLikeNbns(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeNbns(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex, srcPort, dstPort),
  )
}

function dispatchSsdp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'udp'
    || !(isSsdpPortHint(srcPort, dstPort) || looksLikeSsdp(data, offset, length))
    || !looksLikeSsdp(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeSsdp(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchWsDiscovery(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'udp'
    || !isWsDiscoveryPortHint(srcPort, dstPort)
    || !looksLikeWsDiscovery(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeWsDiscovery(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchRadius(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isRadiusPortHint(srcPort, dstPort) || !looksLikeRadius(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeRadius(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
    ),
  )
}

function dispatchTacacs(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isTacacsPortHint(srcPort, dstPort) || !looksLikeTacacs(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeTacacs(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchDiameter(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'tcp'
    || !isDiameterPortHint(srcPort, dstPort)
    || !looksLikeDiameter(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeDiameter(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchHep(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    (transport !== 'udp' && transport !== 'tcp')
    || !(isHepPortHint(srcPort, dstPort) || looksLikeHep(data, offset, length))
    || !looksLikeHep(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeHep(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
      ctx.mediaFlowIndex,
      transport === 'tcp' ? 'tcp' : 'udp',
    ),
  )
}

function dispatchTzsp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isTzspPortHint(srcPort, dstPort) || !looksLikeTzsp(data, offset, length)) {
    return null
  }
  const onInner = ctx.onInnerTransport
  if (!onInner) return null
  const tunnelDepth = ctx.tunnelDepth ?? 0
  const tzspResult = sanitizeTzsp(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
    tunnelDepth,
    onInner,
  )
  return hitFullPayload(ctx, tzspResult)
}

function dispatchNetflowV5(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (
    transport !== 'udp'
    || !isNetflowV5PortHint(srcPort, dstPort)
    || !looksLikeNetflowV5(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeNetflowV5(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
    ),
  )
}

function dispatchIpfix(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort, flowEndpoint } = ctx
  if (
    transport !== 'udp'
    || !isIpfixPortHint(srcPort, dstPort)
    || !looksLikeNetflowV9OrIpfix(data, offset, length)
  ) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeNetflowV9OrIpfix(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
      {
        srcIp: flowEndpoint?.srcIp,
        dstIp: flowEndpoint?.dstIp,
        srcPort,
        dstPort,
      },
      {
        generationId: ctx.generationId,
        sourceId: ctx.sourceId,
      },
    ),
  )
}

function dispatchSflow(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isSflowPortHint(srcPort, dstPort) || !looksLikeSflow(data, offset, length)) {
    return null
  }
  const onInner = ctx.onInnerTransport
  if (!onInner) return null
  const tunnelDepth = ctx.tunnelDepth ?? 0
  return hitFullPayload(
    ctx,
    sanitizeSflow(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      tunnelDepth,
      onInner,
    ),
  )
}

function dispatchPfcp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'udp' || !isPfcpPortHint(srcPort, dstPort) || !looksLikePfcp(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizePfcp(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
      ctx.flowEndpoint,
      { srcPort, dstPort },
    ),
  )
}

function dispatchGtp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort, flowEndpoint } = ctx
  if (transport !== 'udp' || !isGtpPortHint(srcPort, dstPort) || !looksLikeGtp(data, offset, length)) {
    return null
  }
  const onInner = ctx.onInnerTransport
  if (!onInner) return null
  const tunnelDepth = ctx.tunnelDepth ?? 0
  const plane = isGtpUPort(srcPort, dstPort) ? ('u' as const) : ('c' as const)
  const gtp = sanitizeGtp(
    data,
    offset,
    length,
    ctx.collector,
    ctx.mapping,
    ctx.intents,
    ctx.packetIndex,
    tunnelDepth,
    onInner,
    plane,
    { receiveEndpoint: flowEndpoint?.dstIp, plane },
  )
  if (!gtp) return null
  ctx.coverage.push(...gtp.coverage)
  if (gtp.issues) for (const issue of gtp.issues) ctx.issues.push(issue)
  return { lastCoveredOffset: ctx.offset + ctx.length, drop: gtp.drop }
}

function dispatchLdap(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, srcPort, dstPort } = ctx
  if (!isLdapPortHint(srcPort, dstPort) || !looksLikeLdap(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeLdap(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchKerberos(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, srcPort, dstPort } = ctx
  if (!isKerberosPortHint(srcPort, dstPort) || !looksLikeKerberos(data, offset, length)) return null
  return hitFullPayload(
    ctx,
    sanitizeKerberos(
      data,
      offset,
      length,
      ctx.collector,
      ctx.mapping,
      ctx.intents,
      ctx.packetIndex,
      ctx.payloadTime,
    ),
  )
}

function dispatchDmr(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (!ctx.policy.dmr || ctx.transport !== 'udp') return null
  const dmrResult = sanitizeDmr(ctx.data, ctx.offset, ctx.length, ctx.collector, ctx.mapping)
  if (!dmrResult) return null
  return hitCoverageMax(ctx, dmrResult)
}

function dispatchMototrbo(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (!ctx.policy.mototrbo || ctx.transport !== 'udp') return null
  const mototrboResult = sanitizeMototrboIpsc(ctx.offset, ctx.length, ctx.dstPort, ctx.collector)
  if (!mototrboResult) return null
  return hitCoverageMax(ctx, mototrboResult)
}

function dispatchBgp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (ctx.transport !== 'tcp') return null
  const bgpResult = sanitizeBgp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.srcPort,
    ctx.dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    ctx.intents,
  )
  if (!bgpResult) return null
  return hitCoverageMax(ctx, bgpResult)
}

function dispatchLdp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const ldpResult = sanitizeLdp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.srcPort,
    ctx.dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    ctx.intents,
  )
  if (!ldpResult) return null
  return hitCoverageMax(ctx, ldpResult)
}

function dispatchRip(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (ctx.transport !== 'udp') return null
  const ripResult = sanitizeRip(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    ctx.intents,
  )
  if (!ripResult) return null
  return hitCoverageMax(ctx, ripResult)
}

function dispatchBfd(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (ctx.transport !== 'udp') return null
  const bfdResult = sanitizeBfd(ctx.data, ctx.offset, ctx.length, ctx.dstPort, ctx.collector, ctx.packetIndex, ctx.intents)
  if (!bfdResult) return null
  return hitCoverageMax(ctx, bfdResult)
}

function dispatchHsrp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (ctx.transport !== 'udp') return null
  const hsrpResult = sanitizeHsrpGlbp(
    ctx.data,
    ctx.offset,
    ctx.length,
    ctx.dstPort,
    ctx.collector,
    ctx.mapping,
    ctx.packetIndex,
    ctx.intents,
  )
  if (!hsrpResult) return null
  return hitCoverageMax(ctx, hsrpResult)
}

function dispatchSmtp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isSmtpPortHint(srcPort, dstPort) || !looksLikeSmtp(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeSmtp(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchImap(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isImapPortHint(srcPort, dstPort) || !looksLikeImap(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeImap(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchPop3(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isPop3PortHint(srcPort, dstPort) || !looksLikePop3(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizePop3(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchFtp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isFtpPortHint(srcPort, dstPort) || !looksLikeFtp(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeFtp(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchTelnet(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isTelnetPortHint(srcPort, dstPort) || !looksLikeTelnet(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeTelnet(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchSmb(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  const { data, offset, length, transport, srcPort, dstPort } = ctx
  if (transport !== 'tcp' || !isSmbPortHint(srcPort, dstPort) || !looksLikeSmb(data, offset, length)) {
    return null
  }
  return hitFullPayload(
    ctx,
    sanitizeSmb(data, offset, length, ctx.collector, ctx.mapping, ctx.intents, ctx.packetIndex),
  )
}

function dispatchRdp(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (!isRdpPortHint(ctx.srcPort, ctx.dstPort)) return null
  if (ctx.transport === 'tcp' || ctx.transport === 'udp') {
    return hitFullPayload(
      ctx,
      sanitizeRdp(
        ctx.data,
        ctx.offset,
        ctx.length,
        ctx.srcPort,
        ctx.dstPort,
        ctx.collector,
        ctx.mapping,
        ctx.packetIndex,
        ctx.intents,
      ),
    )
  }
  return null
}

function dispatchVnc(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx) || ctx.transport !== 'tcp') return null
  if (!isVncPortHint(ctx.srcPort, ctx.dstPort)) return null
  return hitFullPayload(
    ctx,
    sanitizeVnc(
      ctx.data,
      ctx.offset,
      ctx.length,
      ctx.srcPort,
      ctx.dstPort,
      ctx.collector,
      ctx.mapping,
      ctx.packetIndex,
      ctx.intents,
    ),
  )
}

function dispatchX11(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx) || ctx.transport !== 'tcp') return null
  if (!isX11PortHint(ctx.srcPort, ctx.dstPort)) return null
  return hitFullPayload(
    ctx,
    sanitizeX11(
      ctx.data,
      ctx.offset,
      ctx.length,
      ctx.srcPort,
      ctx.dstPort,
      ctx.collector,
      ctx.mapping,
      ctx.packetIndex,
      ctx.intents,
    ),
  )
}

function dispatchIpmi(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (ctx.transport !== 'udp' || !isIpmiPortHint(ctx.srcPort, ctx.dstPort)) return null
  return hitFullPayload(
    ctx,
    sanitizeIpmi(
      ctx.data,
      ctx.offset,
      ctx.length,
      ctx.srcPort,
      ctx.dstPort,
      ctx.collector,
      ctx.mapping,
      ctx.packetIndex,
      ctx.intents,
    ),
  )
}

function dispatchCitrix(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx) || ctx.transport !== 'tcp') return null
  if (!isCitrixPortHint(ctx.srcPort, ctx.dstPort)) return null
  return hitFullPayload(
    ctx,
    sanitizeCitrix(
      ctx.data,
      ctx.offset,
      ctx.length,
      ctx.srcPort,
      ctx.dstPort,
      ctx.collector,
      ctx.packetIndex,
      ctx.intents,
    ),
  )
}

function dispatchAmt(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx) || ctx.transport !== 'tcp') return null
  if (!isAmtPortHint(ctx.srcPort, ctx.dstPort)) return null
  return hitFullPayload(
    ctx,
    sanitizeAmtHttp(
      ctx.data,
      ctx.offset,
      ctx.length,
      ctx.srcPort,
      ctx.dstPort,
      ctx.collector,
      ctx.mapping,
      ctx.packetIndex,
      ctx.intents,
      ctx.policy.preset === 'high-privacy',
    ),
  )
}

function dispatchGsmtap(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (reassemblyOwnsPayload(ctx)) return null
  if (ctx.transport !== 'udp' || !isGsmtapPortHint(ctx.srcPort, ctx.dstPort)) return null
  return hitFullPayload(
    ctx,
    sanitizeGsmtap(
      ctx.data,
      ctx.offset,
      ctx.length,
      ctx.srcPort,
      ctx.dstPort,
      ctx.collector,
      ctx.packetIndex,
      ctx.intents,
      ctx.mapping,
    ),
  )
}

function dispatchDcerpc(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'tcp') return null
  const { data, offset, length, srcPort, dstPort } = ctx
  if (!isDcerpcPortHint(srcPort, dstPort) && !looksLikeDcerpc(data, offset, length)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitizeDcerpc(
      data, offset, length, srcPort, dstPort, ctx.collector, ctx.mapping, ctx.packetIndex, highPrivacy, ctx.intents,
    ),
  )
}

function dispatchIscsi(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'tcp' || !isIscsiPortHint(ctx.srcPort, ctx.dstPort)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitizeIscsi(
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
    ),
  )
}

function dispatchPortmapper(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!isPortmapperPortHint(ctx.srcPort, ctx.dstPort)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  const transport = ctx.transport === 'tcp' ? 'tcp' : ctx.transport === 'udp' ? 'udp' : null
  if (!transport) return null
  return hitFullPayload(
    ctx,
    sanitizePortmapper(
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
      transport,
    ),
  )
}

function dispatchNfs(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!isNfsPortHint(ctx.srcPort, ctx.dstPort)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  const transport = ctx.transport === 'tcp' ? 'tcp' : ctx.transport === 'udp' ? 'udp' : null
  if (!transport) return null
  return hitFullPayload(
    ctx,
    sanitizeNfs(
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
      transport,
    ),
  )
}

function dispatchCoap(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'udp' || !isCoapPortHint(ctx.srcPort, ctx.dstPort)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitizeCoap(
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
      { flowEndpoint: ctx.flowEndpoint, coapBlock2: ctx.coapBlock2 },
    ),
  )
}

function dispatchOpcua(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (ctx.transport !== 'tcp' || !isOpcuaPortHint(ctx.srcPort, ctx.dstPort)) return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitizeOpcua(
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
      { flowEndpoint: ctx.flowEndpoint, opcuaChannel: ctx.opcuaChannel },
    ),
  )
}

function dispatchDnp3(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!isDnp3PortHint(ctx.srcPort, ctx.dstPort)) return null
  if (ctx.transport !== 'tcp' && ctx.transport !== 'udp') return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitizeDnp3(
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
    ),
  )
}

function dispatchGelf(ctx: ApplicationDispatchContext): ApplicationDispatchHit | null {
  if (!isGelfPortHint(ctx.srcPort, ctx.dstPort)) return null
  if (ctx.transport !== 'tcp' && ctx.transport !== 'udp') return null
  const highPrivacy = ctx.policy.preset === 'high-privacy'
  return hitFullPayload(
    ctx,
    sanitizeGelf(
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
    ),
  )
}

export const APPLICATION_CLUSTER_DISPATCH_ENTRIES: readonly ApplicationDispatchEntry[] = [
  { id: 'pidf', dispatch: dispatchPidf },
  { id: 'lost', dispatch: dispatchLost },
  { id: 'mrcp', dispatch: dispatchMrcp },
  { id: 'cwmp', dispatch: dispatchCwmp },
  { id: 'usp', dispatch: dispatchUsp },
  { id: 'nas', dispatch: dispatchNas },
  { id: 'sbi5g', dispatch: dispatchSbi5g },
  { id: 'http2', dispatch: dispatchHttp2 },
  { id: 'http', dispatch: dispatchHttp },
  { id: 'websocket', dispatch: dispatchWebSocket },
  { id: 'grpc', dispatch: dispatchGrpc },
  { id: 'syslog', dispatch: dispatchSyslog },
  { id: 'snmp', dispatch: dispatchSnmp },
  { id: 'ntp', dispatch: dispatchNtp },
  { id: 'tftp', dispatch: dispatchTftp },
  { id: 'llmnr', dispatch: dispatchLlmnr },
  { id: 'nbns', dispatch: dispatchNbns },
  { id: 'ssdp', dispatch: dispatchSsdp },
  { id: 'ws-discovery', dispatch: dispatchWsDiscovery },
  { id: 'radius', dispatch: dispatchRadius },
  { id: 'tacacs', dispatch: dispatchTacacs },
  { id: 'diameter', dispatch: dispatchDiameter },
  { id: 'hep', dispatch: dispatchHep },
  { id: 'tzsp', dispatch: dispatchTzsp },
  { id: 'netflow-v5', dispatch: dispatchNetflowV5 },
  { id: 'ipfix', dispatch: dispatchIpfix },
  { id: 'sflow', dispatch: dispatchSflow },
  { id: 'pfcp', dispatch: dispatchPfcp },
  { id: 'gtp', dispatch: dispatchGtp },
  { id: 'ldap', dispatch: dispatchLdap },
  { id: 'kerberos', dispatch: dispatchKerberos },
  { id: 'dmr', dispatch: dispatchDmr },
  { id: 'mototrbo', dispatch: dispatchMototrbo },
  { id: 'bgp', dispatch: dispatchBgp },
  { id: 'ldp', dispatch: dispatchLdp },
  { id: 'rip', dispatch: dispatchRip },
  { id: 'bfd', dispatch: dispatchBfd },
  { id: 'hsrp', dispatch: dispatchHsrp },
  { id: 'smtp', dispatch: dispatchSmtp },
  { id: 'imap', dispatch: dispatchImap },
  { id: 'pop3', dispatch: dispatchPop3 },
  { id: 'ftp', dispatch: dispatchFtp },
  { id: 'telnet', dispatch: dispatchTelnet },
  { id: 'smb', dispatch: dispatchSmb },
  { id: 'rdp', dispatch: dispatchRdp },
  { id: 'vnc', dispatch: dispatchVnc },
  { id: 'x11', dispatch: dispatchX11 },
  { id: 'ipmi', dispatch: dispatchIpmi },
  { id: 'citrix', dispatch: dispatchCitrix },
  { id: 'amt', dispatch: dispatchAmt },
  { id: 'gsmtap', dispatch: dispatchGsmtap },
  { id: 'amqp', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isAmqpPortHint, sanitizeAmqp) },
  { id: 'kafka', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isKafkaPortHint, sanitizeKafka) },
  { id: 'nats', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isNatsPortHint, sanitizeNats) },
  { id: 'stomp', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isStompPortHint, sanitizeStomp) },
  { id: 'xmpp', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isXmppPortHint, sanitizeXmpp) },
  { id: 'gelf', dispatch: dispatchGelf },
  { id: 'fluent', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isFluentPortHint, sanitizeFluentForward) },
  { id: 'otlp', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isOtlpPortHint, sanitizeOtlp) },
  { id: 'postgres', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isPostgresPortHint, sanitizePostgres) },
  { id: 'mysql', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isMysqlPortHint, sanitizeMysql) },
  { id: 'tds', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isTdsPortHint, sanitizeTds) },
  { id: 'redis', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isRedisPortHint, sanitizeRedis) },
  { id: 'mongodb', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isMongodbPortHint, sanitizeMongodb) },
  { id: 'mqtt', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isMqttPortHint, sanitizeMqtt) },
  { id: 'coap', dispatch: dispatchCoap },
  { id: 'modbus', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isModbusPortHint, sanitizeModbus) },
  { id: 'iec104', dispatch: (ctx) => dispatchHighPrivacyTcp(ctx, isIec104PortHint, sanitizeIec104) },
  { id: 'dnp3', dispatch: dispatchDnp3 },
  { id: 'opcua', dispatch: dispatchOpcua },
  { id: 'dcerpc', dispatch: dispatchDcerpc },
  { id: 'iscsi', dispatch: dispatchIscsi },
  { id: 'portmapper', dispatch: dispatchPortmapper },
  { id: 'nfs', dispatch: dispatchNfs },
] as const
