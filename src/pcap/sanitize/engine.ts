/**
 * Main sanitization engine — orchestrates protocol decoding, patch planning,
 * coverage tracking, and policy enforcement per packet.
 *
 * Three-phase model:
 * 1. Protocol modules plan patches via PatchCollector
 * 2. Patches validated as non-overlapping set
 * 3. Checksums recomputed during export (see ../checksums/engine.ts)
 */

import { PatchCollector } from './PatchCollector';
import { deferredBinaryMapMeta, deferredPortMapMeta } from './deferredMapMeta.ts';
import {
  deferredFlowLabelFingerprintMeta,
  deferredIpv4IdFingerprintMeta,
  deferredTcpU32FingerprintMeta,
} from './deferredFingerprintMeta.ts';
import { maskRangeDeferredProtocolNeutral } from './deferredMaskMeta.ts';
import type {
  SanitizationPolicy,
  PacketSanitizationResult,
  LayerCoverage,
} from './types';
import { presetToSanitizationPolicy } from '../profile/presets';
import type { MappingLike } from '../anonymization/mapping';
import type { IntentCollector } from '../discovery/intentCollector';
import { MediaFlowIndex } from '../discovery/mediaFlowIndex';
import type { ReassemblyContext } from '../reassembly/types';
import { PacketParseError, PlanInvariantError } from '../plan/planErrors';
import { buildIsolatedPacketResult } from './packetIsolation';
import { enforceCoverageStatusInvariant } from './statusInvariant.ts';
import { dispatchRegisteredApplicationHandlers } from './applicationDispatchRegistry';
import type { InnerTransportHandler } from './tunnel';
import { sanitizeTunnel, sanitizeIcmpEmbedded, sanitizeVxlan, sanitizeIcmpv6Ndp, MAX_TUNNEL_DEPTH } from './tunnel';
import { sanitizeEsp, sanitizeAh, IPPROTO_ESP, IPPROTO_AH } from './esp';
import { sanitizeSctp, IPPROTO_SCTP } from './sctp';
import { sanitizeLldp, ETHERTYPE_LLDP } from './lldp';
import { sanitizeLacp, ETHERTYPE_SLOW } from './lacp';
import {
  continueNullLoop,
  continuePppLink,
  continuePppAtOffset,
  continuePppoe,
  continueMpls,
  continueNflog,
  continueMacsec,
  continuePbb,
  LINKTYPE_NULL,
  LINKTYPE_LOOP,
  LINKTYPE_PPP,
  LINKTYPE_PPP_HDLC,
  LINKTYPE_C_HDLC,
  LINKTYPE_NFLOG,
  ETHERTYPE_PPPOE_DISC,
  ETHERTYPE_PPPOE_SES,
  ETHERTYPE_MPLS_UC,
  ETHERTYPE_MPLS_MC,
  ETHERTYPE_MACSEC,
  ETHERTYPE_PBB,
} from './linkEncaps';
import {
  LINKTYPE_LINUX_LAPD,
  sanitizeLinuxLapdLink,
} from './isdn/index.ts';
import {
  sanitizeGeneve,
  sanitizeL2tp,
  looksLikeGeneve,
  isGenevePort,
  isL2tpPort,
} from './geneveL2tp';
import { sanitizeEapol, ETHERTYPE_EAPOL } from './eapol';
import { sanitizeGenericPayload } from './heuristic';
import {
  identifyUnsupportedApplicationPayload,
  unsupportedCoverageProtocolId,
} from './unsupportedIdentification';
import {
  IPPROTO_OSPF,
  IPPROTO_EIGRP,
  IPPROTO_PIM,
  IPPROTO_IGMP,
  sanitizeOspf,
  sanitizeEigrp,
  sanitizePim,
  sanitizeIgmp,
  sanitizeIsis,
  sanitizeTcpAuthOptions,
} from './routing/index.ts';
import {
  LINKTYPE_IEEE802_11,
  LINKTYPE_IEEE802_11_RADIO,
  LINKTYPE_BLUETOOTH_HCI_H4,
  LINKTYPE_BLUETOOTH_LE_LL,
  LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR,
  LINKTYPE_BLUETOOTH_LINUX_MONITOR,
  parseRadiotapHeader,
  sanitizeIeee80211,
  sanitizeBluetoothHci,
  sanitizeBluetoothLeLl,
} from './wireless/index.ts';
import { LINKTYPE_PPI } from '../protocols/types';
import { resolveExportBoundary } from './exportBoundary';
import { patchVlanTci } from './vlanPatch';
import { createProtocolNeutralMaskFill } from './maskFill';
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire';
import {
  FingerprintSession,
  addU32Mod,
  readU32,
  u32ToBytes,
} from '../anonymization/fingerprintSession';
import { findTcpOptionsSeqFields, findTcpOptionsNormalizeFields } from './tcpOptions';
import type { FingerprintFieldPolicy } from './types';
import { sanitizeIpv6Extensions } from './ipv6Extensions';

const IP_PROTO_TCP = 6;
const IP_PROTO_UDP = 17;
const IP_PROTO_ICMP = 1;
const IP_PROTO_ICMPV6 = 58;
const IP_PROTO_IPIP = 4;
const IP_PROTO_IPV6 = 41;
const IP_PROTO_GRE = 47;
const IP_PROTO_VRRP = 112;
const IP_PROTO_OSPF = IPPROTO_OSPF;
const IP_PROTO_EIGRP = IPPROTO_EIGRP;
const IP_PROTO_PIM = IPPROTO_PIM;
const IP_PROTO_IGMP = IPPROTO_IGMP;
const IP_PROTO_ESP = IPPROTO_ESP;
const IP_PROTO_AH = IPPROTO_AH;
const IP_PROTO_SCTP = IPPROTO_SCTP;


export function policyFromPreset(
  preset: 'diagnostic' | 'high-privacy',
): SanitizationPolicy {
  return presetToSanitizationPolicy(preset);
}

export interface PacketInput {
  readonly index: number;
  readonly data: Uint8Array;
  readonly capturedLength: number;
  readonly originalLength: number;
  readonly linkType: number;
  /** True if packet is from SPB (no per-packet metadata). */
  readonly isSimple?: boolean;
  /** True if this is an IP fragment (not first). */
  readonly isFragment?: boolean;
}

export interface SanitizeOptions {
  readonly intents?: IntentCollector;
  readonly mediaFlowIndex?: MediaFlowIndex;
  readonly reassemblyContext?: ReassemblyContext;
  /** Nesting depth for GRE/IPIP/VXLAN recursion (CF-13). */
  readonly tunnelDepth?: number;
  /** Cross-packet TCP SEQ / IPv4 ID / flow-label remapping (step 7). */
  readonly fingerprints?: FingerprintSession;
  /**
   * PF-06: skip resolving deferred entity/fingerprint patches against `mapping` — used by
   * discovery, which runs with a throwaway passthrough mapping purely to find intents/
   * coverage and has no use for concrete patch bytes yet. The returned result's
   * `resolvePatches()` resolves them later against the real mapping, without re-decoding.
   */
  readonly deferPatchResolution?: boolean;
  /** T14 — capture-aligned absolute payload time (HTTP/SIP Date). */
  readonly payloadTime?: import('../kernel/payloadTimeCodec').PayloadTimeSession;
  /** T21 — processing generation / source scope for NetFlow/IPFIX template caches. */
  readonly generationId?: string;
  readonly sourceId?: string;
  /** T04 / T63 — bounded incident log (deferred failures + status-mismatch). */
  readonly incidentLog?: import('../../domain/anonymizationIncident').IncidentLog;
  /** T02.S4 — record analytical protocol facts during sanitize/discovery. */
  readonly journal?: import('../kernel/journal').SemanticJournalBuilder;
  readonly kernelSymbolicOps?: import('../kernel/operations').SymbolicOperation[];
  /** T30 — CoAP Block2 cross-datagram transfer state (capture-scoped). */
  readonly coapBlock2?: import('./industrial/coapBlock2Session.ts').CoapBlock2Session;
  /** T30 — OPC UA SecureChannel SecurityMode (capture-scoped). */
  readonly opcuaChannel?: import('./industrial/opcuaChannelSession.ts').OpcuaChannelSession;
}

/**
 * Sanitize a single packet according to policy.
 */
export function sanitizePacket(
  packet: PacketInput,
  policy: SanitizationPolicy,
  mapping: MappingLike,
  options: SanitizeOptions = {},
): PacketSanitizationResult {
  const collector = new PatchCollector(packet.data.length);
  const coverage: LayerCoverage[] = [];
  const issues: string[] = [];
  let drop = false;
  const resolvedOptions: SanitizeOptions = {
    ...options,
    fingerprints: options.fingerprints ?? new FingerprintSession(),
  };

  // Malformed/SPB handling — diagnostic keeps the record and masks when possible.
  if (packet.isSimple && policy.dropMalformed) {
    return { packetIndex: packet.index, patches: [], drop: true, coverage: [], issues: ['SPB packet dropped by policy'] };
  }

  try {
    const result = decodeAndPatch(
      packet.data,
      packet.linkType,
      collector,
      mapping,
      policy,
      coverage,
      issues,
      packet.index,
      resolvedOptions,
    );

    drop = result.drop ?? false;

    // CF-09 / step 4: truncate (safe) or mask-in-place (diagnostic) from safeExportEnd.
    // T64 — reassembly overlay owns app-layer decode, but the same export boundary applies:
    // compute safeExportEnd over structural coverage ∪ projected overlay coverage, then
    // mask/truncate past that point. Overlay map patches that later collide with the
    // residual mask are dropped (fail-closed) in applyReassemblyPatchesToResults.
    const overlay = options.reassemblyContext?.overlayFor(packet.index)
    const overlayOwnsApp = overlay?.skipAppLayer === true
    const boundaryCoverage =
      overlayOwnsApp && overlay && overlay.coverage.length > 0
        ? [...coverage, ...overlay.coverage]
        : coverage
    const boundary = resolveExportBoundary(boundaryCoverage, policy, packet.capturedLength);
    let truncatedLength: number | undefined;

    if (
      (boundary.disposition === 'mask-in-place' || boundary.disposition === 'mask-application-in-place')
      && packet.capturedLength > 0
      && boundary.safeExportEnd === 0
      && !drop
    ) {
      throw new PlanInvariantError({
        code: 'unsafe-export-boundary',
        message:
          `No safe export boundary for packetIndex=${packet.index}; `
          + 'refusing to mask or export without L2/L3/L4 structure',
        packetIndex: packet.index,
      });
    }
    if (boundary.disposition === 'drop') {
      // Fail-closed: a computed `drop` must never fall back to keeping whatever patches
      // were already collected for the safe prefix — the whole record is excluded from
      // export (see export/engine.ts's `if (planPkt.drop) continue`), so nothing here
      // needs a truncation/mask patch. The reason is discoverable — the blocking coverage
      // status/protocol are already in `coverage` for the report.
      drop = true;
    } else if (boundary.disposition === 'truncate' && boundary.safeExportEnd < packet.capturedLength) {
      truncatedLength = boundary.safeExportEnd;
      coverage.push({
        protocol: 'payload',
        offset: boundary.safeExportEnd,
        length: packet.capturedLength - boundary.safeExportEnd,
        status: 'truncated',
      });
    } else if (
      (boundary.disposition === 'mask-in-place' || boundary.disposition === 'mask-application-in-place')
      && boundary.safeExportEnd > 0
      && boundary.safeExportEnd < packet.capturedLength
    ) {
      applyInPlaceMask({
        collector,
        intents: options.intents,
        coverage,
        issues,
        packetIndex: packet.index,
        safeExportEnd: boundary.safeExportEnd,
        capturedLength: packet.capturedLength,
        disposition: boundary.disposition,
      });
    }

    if (options.deferPatchResolution) {
      return {
        packetIndex: packet.index,
        patches: collector.getPatches(),
        resolvePatches: (ctx) => {
          collector.resolveDeferred(ctx);
          // T63 — status must match patches; remediate gaps (assert left to harness).
          const mismatch = enforceCoverageStatusInvariant({
            collector,
            coverage,
            packetIndex: packet.index,
            incidentLog: ctx.incidentLog,
            sourceId: ctx.sourceId,
            packetNumber: ctx.packetNumber,
          });
          if (mismatch.remediatedSpans > 0) {
            issues.push('status-mismatch');
          }
          return collector.getPatches();
        },
        symbolicMapOps: mergeKernelSymbolicMapOps(
          collector.getSymbolicJournalOps(),
          options.kernelSymbolicOps,
        ),
        deferredFullySymbolized: collector.isDeferredFullySymbolized(),
        truncatedLength,
        coverage,
        drop,
        issues,
      };
    }
    collector.resolveDeferred({
      mapping,
      fingerprints: resolvedOptions.fingerprints!,
      payloadTime: resolvedOptions.payloadTime,
      incidentLog: options.incidentLog,
      sourceId: options.sourceId,
      packetIndex: packet.index,
    });
    {
      const mismatch = enforceCoverageStatusInvariant({
        collector,
        coverage,
        packetIndex: packet.index,
        incidentLog: options.incidentLog,
        sourceId: options.sourceId,
      });
      if (mismatch.remediatedSpans > 0) {
        issues.push('status-mismatch');
      }
    }
    return {
      packetIndex: packet.index,
      patches: collector.getPatches(),
      truncatedLength,
      coverage,
      drop,
      issues,
    };
  } catch (e) {
    // T07: never abort the whole capture for a single-packet failure.
    // PlanInvariantError / MappingLookupError / parse errors → packet isolation.
    void e
    void PacketParseError
    void PlanInvariantError
    const boundary = resolveExportBoundary(coverage, policy, packet.capturedLength)
    const safePrefix =
      boundary.safeExportEnd > 0
        ? boundary.safeExportEnd
        : coverage.reduce((max, span) => Math.max(max, span.offset + span.length), 0)
    return buildIsolatedPacketResult({
      packetIndex: packet.index,
      capturedLength: packet.capturedLength,
      linkType: packet.linkType,
      data: packet.data,
      policy,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: safePrefix,
      priorCoverage: coverage,
      priorIssues: issues,
      deferPatchResolution: options.deferPatchResolution,
    })
  }
}

function applyInPlaceMask(input: {
  collector: PatchCollector
  intents?: IntentCollector
  coverage: LayerCoverage[]
  issues: string[]
  packetIndex: number
  safeExportEnd: number
  capturedLength: number
  disposition: 'mask-in-place' | 'mask-application-in-place'
}): void {
  const length = input.capturedLength - input.safeExportEnd
  if (length <= 0) return
  const protocol = input.disposition === 'mask-application-in-place' ? 'application' : 'payload'
  const reason = input.disposition
  const fill = createProtocolNeutralMaskFill({
    length,
    packetIndex: input.packetIndex,
    offset: input.safeExportEnd,
    domain: `export-boundary:${reason}`,
  })
  input.collector.maskRange(input.safeExportEnd, fill)
  input.intents?.recordMaskRange(
    input.packetIndex,
    input.safeExportEnd,
    length,
    reason,
    protocol,
  )
  input.coverage.push({
    protocol,
    offset: input.safeExportEnd,
    length,
    status: 'redacted',
  })
  input.issues.push(`masked-in-place:${reason}:${input.safeExportEnd}+${length}`)
}

interface DecodeResult {
  lastCoveredOffset: number;
  drop?: boolean;
}

interface FlowEndpoint {
  readonly srcIp: string;
  readonly dstIp: string;
}

function decodeAndPatch(
  data: Uint8Array,
  linkType: number,
  collector: PatchCollector,
  mapping: MappingLike,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  packetIndex: number,
  options: SanitizeOptions = {},
): DecodeResult {
  const intents = options.intents;
  let offset = 0;
  let etherType = 0;
  let lastCovered = 0;

  // Link layer
  switch (linkType) {
    case 1: { // Ethernet
      if (data.length < 14) {
        coverage.push({ protocol: 'ethernet', offset: 0, length: data.length, status: 'malformed' });
        return { lastCoveredOffset: data.length };
      }
      // Patch MACs
      patchMac(data, 0, collector, mapping, packetIndex, intents); // dst
      patchMac(data, 6, collector, mapping, packetIndex, intents); // src
      offset = 12;

      // Handle VLAN tags — map VID, preserve PCP/DEI (step 3).
      etherType = (data[offset]! << 8) | data[offset + 1]!;
      while ((etherType === 0x8100 || etherType === 0x88a8) && offset + 4 <= data.length) {
        patchVlanTci(data, offset + 2, collector, mapping, packetIndex, intents, coverage, issues);
        offset += 4;
        etherType = (data[offset]! << 8) | data[offset + 1]!;
      }
      offset += 2;
      coverage.push({ protocol: 'ethernet', offset: 0, length: offset, status: 'covered' });
      lastCovered = offset;
      break;
    }
    case 113: { // Linux SLL
      if (data.length < 16) {
        coverage.push({ protocol: 'sll', offset: 0, length: data.length, status: 'malformed' });
        return { lastCoveredOffset: data.length };
      }
      etherType = (data[14]! << 8) | data[15]!;
      offset = 16;
      coverage.push({ protocol: 'sll', offset: 0, length: 16, status: 'covered' });
      lastCovered = 16;
      break;
    }
    case 276: { // Linux SLL2
      if (data.length < 20) {
        coverage.push({ protocol: 'sll2', offset: 0, length: data.length, status: 'malformed' });
        return { lastCoveredOffset: data.length };
      }
      etherType = (data[0]! << 8) | data[1]!;
      offset = 20;
      coverage.push({ protocol: 'sll2', offset: 0, length: 20, status: 'covered' });
      lastCovered = 20;
      break;
    }
    case 101: // Raw IPv4
      etherType = 0x0800;
      break;
    case 228: // Raw IPv4
      etherType = 0x0800;
      break;
    case 229: // Raw IPv6
      etherType = 0x86dd;
      break;
    case LINKTYPE_NULL:
    case LINKTYPE_LOOP: {
      const nl = continueNullLoop(data, linkType, collector, packetIndex, intents);
      coverage.push(...nl.coverage);
      for (const i of nl.issues) issues.push(i);
      if (nl.done) return { lastCoveredOffset: nl.lastCoveredOffset ?? data.length };
      offset = nl.offset;
      etherType = nl.etherType;
      lastCovered = offset;
      break;
    }
    case LINKTYPE_PPP:
    case LINKTYPE_PPP_HDLC:
    case LINKTYPE_C_HDLC: {
      const ppp = continuePppLink(data, linkType, collector, mapping, packetIndex, intents);
      coverage.push(...ppp.coverage);
      for (const i of ppp.issues) issues.push(i);
      if (ppp.done) return { lastCoveredOffset: ppp.lastCoveredOffset ?? data.length };
      offset = ppp.offset;
      etherType = ppp.etherType;
      lastCovered = offset;
      break;
    }
    case LINKTYPE_LINUX_LAPD: {
      // T51 — Linux cooked LAPD + Q.931 D-channel (no IP).
      const lapd = sanitizeLinuxLapdLink(data, collector, mapping, intents, packetIndex);
      coverage.push(...lapd.coverage);
      if (lapd.issues) for (const i of lapd.issues) issues.push(i);
      return { lastCoveredOffset: data.length };
    }
    case LINKTYPE_NFLOG: {
      const nf = continueNflog(data, collector, mapping, packetIndex, intents);
      coverage.push(...nf.coverage);
      for (const i of nf.issues) issues.push(i);
      if (nf.done) return { lastCoveredOffset: nf.lastCoveredOffset ?? data.length };
      offset = nf.offset;
      etherType = nf.etherType;
      lastCovered = offset;
      break;
    }
    case LINKTYPE_IEEE802_11_RADIO: {
      const rt = parseRadiotapHeader(data, 0, collector, packetIndex, intents);
      if (!rt) {
        coverage.push({ protocol: 'radiotap', offset: 0, length: data.length, status: 'malformed' });
        const fill = createProtocolNeutralMaskFill({
          length: data.length, packetIndex, offset: 0, domain: 'radiotap-malformed',
        });
        collector.maskRange(0, fill);
        return { lastCoveredOffset: data.length };
      }
      coverage.push(...rt.coverage);
      for (const i of rt.issues) issues.push(i);
      const ieee = sanitizeIeee80211(
        data,
        rt.headerLen,
        collector,
        mapping,
        packetIndex,
        intents,
        policy.preset === 'high-privacy',
      );
      coverage.push(...ieee.coverage);
      for (const i of ieee.issues) issues.push(i);
      if (ieee.done) return { lastCoveredOffset: ieee.lastCoveredOffset };
      offset = ieee.payloadOffset;
      etherType = ieee.etherType ?? 0;
      lastCovered = offset;
      break;
    }
    case LINKTYPE_IEEE802_11: {
      const ieee = sanitizeIeee80211(
        data,
        0,
        collector,
        mapping,
        packetIndex,
        intents,
        policy.preset === 'high-privacy',
      );
      coverage.push(...ieee.coverage);
      for (const i of ieee.issues) issues.push(i);
      if (ieee.done) return { lastCoveredOffset: ieee.lastCoveredOffset };
      offset = ieee.payloadOffset;
      etherType = ieee.etherType ?? 0;
      lastCovered = offset;
      break;
    }
    case LINKTYPE_PPI: {
      // PPI — identify + fail-closed mask (GPS/common fields need PPI field dictionary).
      coverage.push({ protocol: 'ppi', offset: 0, length: Math.min(8, data.length), status: 'covered' });
      if (data.length > 8) {
        const fill = createProtocolNeutralMaskFill({
          length: data.length - 8, packetIndex, offset: 8, domain: 'ppi-body',
        });
        collector.maskRange(8, fill);
        intents?.recordMaskRange(packetIndex, 8, data.length - 8, 'ppi-body', 'ppi');
        coverage.push({ protocol: 'ppi-body', offset: 8, length: data.length - 8, status: 'redacted' });
      }
      coverage.push({ protocol: 'ppi', offset: 0, length: data.length, status: 'covered' });
      issues.push('ppi-identify-mask');
      return { lastCoveredOffset: data.length };
    }
    case LINKTYPE_BLUETOOTH_HCI_H4:
    case LINKTYPE_BLUETOOTH_LINUX_MONITOR: {
      const bt = sanitizeBluetoothHci(data, collector, mapping, packetIndex, intents);
      coverage.push(...bt.coverage);
      for (const i of bt.issues) issues.push(i);
      return { lastCoveredOffset: bt.lastCoveredOffset };
    }
    case LINKTYPE_BLUETOOTH_LE_LL:
    case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: {
      const ble = sanitizeBluetoothLeLl(data, collector, mapping, packetIndex, intents);
      coverage.push(...ble.coverage);
      for (const i of ble.issues) issues.push(i);
      return { lastCoveredOffset: ble.lastCoveredOffset };
    }
    default:
      coverage.push({
        protocol: `unsupported:link-${linkType}`,
        offset: 0,
        length: data.length,
        status: 'unsupported',
      });
      issues.push(`unsupported-linktype:${linkType}`);
      // Fail-closed mask whole frame (same as prior `link` unsupported)
      {
        const fill = createProtocolNeutralMaskFill({
          length: data.length,
          packetIndex,
          offset: 0,
          domain: `unsupported-link-${linkType}`,
        });
        collector.maskRange(0, fill);
        intents?.recordMaskRange(packetIndex, 0, data.length, `link-${linkType}`, 'link');
      }
      return { lastCoveredOffset: 0 };
  }

  // T34 — Ethernet ethertypes that unwrap to IP / nested Ethernet
  if (
    etherType === ETHERTYPE_MPLS_UC
    || etherType === ETHERTYPE_MPLS_MC
    || etherType === ETHERTYPE_PPPOE_DISC
    || etherType === ETHERTYPE_PPPOE_SES
    || etherType === ETHERTYPE_MACSEC
    || etherType === ETHERTYPE_PBB
  ) {
    let cont =
      etherType === ETHERTYPE_MPLS_UC || etherType === ETHERTYPE_MPLS_MC
        ? continueMpls(data, offset, collector, mapping, packetIndex, intents)
        : etherType === ETHERTYPE_PPPOE_DISC || etherType === ETHERTYPE_PPPOE_SES
          ? continuePppoe(
            data,
            offset,
            etherType === ETHERTYPE_PPPOE_DISC,
            collector,
            mapping,
            packetIndex,
            intents,
          )
          : etherType === ETHERTYPE_MACSEC
            ? continueMacsec(data, offset, collector, mapping, packetIndex, intents)
            : continuePbb(data, offset, collector, mapping, packetIndex, intents);
    coverage.push(...cont.coverage);
    for (const i of cont.issues) issues.push(i);
    if (cont.done) return { lastCoveredOffset: cont.lastCoveredOffset ?? data.length };
    offset = cont.offset;
    etherType = cont.etherType;
    lastCovered = Math.max(lastCovered, offset);
    // Nested MPLS over MACsec / PBB rare — one extra unwrap of MPLS/PPPoE
    if (etherType === ETHERTYPE_MPLS_UC || etherType === ETHERTYPE_MPLS_MC) {
      cont = continueMpls(data, offset, collector, mapping, packetIndex, intents);
      coverage.push(...cont.coverage);
      for (const i of cont.issues) issues.push(i);
      if (cont.done) return { lastCoveredOffset: cont.lastCoveredOffset ?? data.length };
      offset = cont.offset;
      etherType = cont.etherType;
      lastCovered = Math.max(lastCovered, offset);
    }
  }

  // Network layer
  if (etherType === 0x0800) {
    // IPv4
    if (offset + 20 > data.length) {
      coverage.push({ protocol: 'ipv4', offset, length: data.length - offset, status: 'malformed' });
      return { lastCoveredOffset: lastCovered };
    }
    const ihl = (data[offset]! & 0xf) * 4;
    if (ihl < 20 || offset + ihl > data.length) {
      coverage.push({ protocol: 'ipv4', offset, length: data.length - offset, status: 'malformed' });
      return { lastCoveredOffset: lastCovered };
    }

    // Patch src/dst IP
    patchIpv4(data, offset + 12, collector, mapping, packetIndex, intents);
    patchIpv4(data, offset + 16, collector, mapping, packetIndex, intents);

    const ipProto = data[offset + 9]!;
    applyIpv4FingerprintPolicy(
      data,
      offset,
      ihl,
      collector,
      policy,
      coverage,
      issues,
      options.fingerprints,
      formatIpv4Address(data, offset + 12),
      formatIpv4Address(data, offset + 16),
      ipProto,
      packetIndex,
    );

    const fragOffset = ((data[offset + 6]! & 0x1f) << 8) | data[offset + 7]!;
    // First fragment (offset==0, maybe MF=1) still carries L4/app headers — decode it.
    // Non-first fragments skip transport; payload is masked via export boundary.
    const isNonFirstFragment = fragOffset > 0;

    lastCovered = offset + ihl;

    if (isNonFirstFragment) {
      coverage.push({
        protocol: 'fragment',
        offset: lastCovered,
        length: data.length - lastCovered,
        status: 'requires-reassembly',
      });
      issues.push('IP non-first fragment — transport layer not decoded');
      return { lastCoveredOffset: lastCovered };
    }

    return decodeTransport(
      data,
      offset + ihl,
      ipProto,
      false,
      { srcIp: formatIpv4Address(data, offset + 12), dstIp: formatIpv4Address(data, offset + 16) },
      collector,
      mapping,
      policy,
      coverage,
      issues,
      lastCovered,
      packetIndex,
      options,
    );
  } else if (etherType === 0x86dd) {
    // IPv6
    if (offset + 40 > data.length) {
      coverage.push({ protocol: 'ipv6', offset, length: data.length - offset, status: 'malformed' });
      return { lastCoveredOffset: lastCovered };
    }

    patchIpv6(data, offset + 8, collector, mapping, packetIndex, intents); // src
    patchIpv6(data, offset + 24, collector, mapping, packetIndex, intents); // dst

    applyIpv6FingerprintPolicy(
      data,
      offset,
      collector,
      policy,
      coverage,
      issues,
      options.fingerprints,
      formatIpv6Address(data, offset + 8),
      formatIpv6Address(data, offset + 24),
      packetIndex,
    );

    let nextHeader = data[offset + 6]!;
    let hdrOffset = offset + 40;
    lastCovered = offset + 40;

    const ext = sanitizeIpv6Extensions({
      buffer: data,
      startOffset: hdrOffset,
      initialNextHeader: nextHeader,
      collector,
      mapping,
      packetIndex,
      intents,
    });
    coverage.push(...ext.coverage);
    nextHeader = ext.nextHeader;
    hdrOffset = ext.payloadOffset;
    lastCovered = Math.max(lastCovered, ext.lastCoveredOffset);

    if (ext.isFragment) {
      coverage.push({ protocol: 'fragment', offset: hdrOffset, length: data.length - hdrOffset, status: 'requires-reassembly' });
      issues.push('IPv6 fragment detected — transport layer not decoded');
      return { lastCoveredOffset: lastCovered };
    }

    return decodeTransport(
      data,
      hdrOffset,
      nextHeader,
      true,
      { srcIp: formatIpv6Address(data, offset + 8), dstIp: formatIpv6Address(data, offset + 24) },
      collector,
      mapping,
      policy,
      coverage,
      issues,
      lastCovered,
      packetIndex,
      options,
    );
  } else if (etherType === 0x0806) {
    // ARP
    if (offset + 28 > data.length) {
      coverage.push({ protocol: 'arp', offset, length: data.length - offset, status: 'malformed' });
      return { lastCoveredOffset: lastCovered };
    }
    // Sender hardware address (offset+8, 6 bytes), sender IP (offset+14, 4 bytes)
    // Target hardware address (offset+18, 6 bytes), target IP (offset+24, 4 bytes)
    patchMac(data, offset + 8, collector, mapping, packetIndex, intents);
    patchIpv4(data, offset + 14, collector, mapping, packetIndex, intents);
    patchMac(data, offset + 18, collector, mapping, packetIndex, intents);
    patchIpv4(data, offset + 24, collector, mapping, packetIndex, intents);
    coverage.push({ protocol: 'arp', offset, length: 28, status: 'covered' });
    // Ethernet padding after the 28-byte ARP body — zero in-place, keep frame length.
    const padStart = offset + 28;
    if (padStart < data.length) {
      const padLen = data.length - padStart;
      const zeros = new Uint8Array(padLen);
      collector.maskRange(padStart, zeros);
      intents?.recordMaskRange(packetIndex, padStart, padLen, 'arp-padding', 'arp');
      coverage.push({ protocol: 'arp-padding', offset: padStart, length: padLen, status: 'redacted' });
      return { lastCoveredOffset: data.length };
    }
    return { lastCoveredOffset: padStart };
  } else if (etherType <= 0x05dc) {
    // <= 1500: an 802.3 length field, not an EtherType — inspect the LLC header for STP/CDP.
    const llcResult = decodeLlcFrame(data, offset, collector, mapping, packetIndex, policy, intents);
    coverage.push(...llcResult.coverage);
    return { lastCoveredOffset: llcResult.lastCoveredOffset };
  } else if (etherType === ETHERTYPE_LLDP && policy.lldp) {
    // T19 — LLDP / LLDP-MED
    const payloadLen = data.length - offset;
    const lldpResult = sanitizeLldp(
      data,
      offset,
      payloadLen,
      collector,
      mapping,
      intents,
      packetIndex,
      policy,
    );
    coverage.push(...lldpResult.coverage);
    if (lldpResult.issues) {
      for (const issue of lldpResult.issues) issues.push(issue);
    }
    return { lastCoveredOffset: offset + payloadLen };
  } else if (etherType === ETHERTYPE_SLOW && policy.lacp) {
    // T19 — LACP / Slow Protocols
    const payloadLen = data.length - offset;
    const lacpResult = sanitizeLacp(data, offset, payloadLen, collector, mapping, intents, packetIndex);
    coverage.push(...lacpResult.coverage);
    if (lacpResult.issues) {
      for (const issue of lacpResult.issues) issues.push(issue);
    }
    return { lastCoveredOffset: offset + payloadLen };
  } else if (etherType === ETHERTYPE_EAPOL && policy.eapol) {
    // T19 — EAPOL / 802.1X
    const payloadLen = data.length - offset;
    const eapolResult = sanitizeEapol(data, offset, payloadLen, collector, mapping, intents, packetIndex);
    coverage.push(...eapolResult.coverage);
    if (eapolResult.issues) {
      for (const issue of eapolResult.issues) issues.push(issue);
    }
    return { lastCoveredOffset: offset + payloadLen };
  } else {
    coverage.push({ protocol: `ether-0x${etherType.toString(16)}`, offset, length: data.length - offset, status: 'unsupported' });
    return { lastCoveredOffset: lastCovered };
  }
}

/** 802.3 LLC header (DSAP/SSAP/Control) dispatch — STP (0x42/0x42) and CDP (SNAP, OUI 00-00-0c, PID 0x2000). */
function decodeLlcFrame(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  policy: SanitizationPolicy,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = [];
  if (offset + 3 > data.length) {
    coverage.push({ protocol: 'llc', offset, length: data.length - offset, status: 'malformed' });
    return { coverage, lastCoveredOffset: offset };
  }
  const dsap = data[offset]!;
  const ssap = data[offset + 1]!;

  if (policy.stp && dsap === 0x42 && ssap === 0x42) {
    const stpResult = sanitizeStp(data, offset + 3, collector, mapping, packetIndex, intents);
    coverage.push({ protocol: 'llc', offset, length: 3, status: 'covered' });
    coverage.push(...stpResult.coverage);
    return { coverage, lastCoveredOffset: stpResult.lastCoveredOffset };
  }

  // T38 — IS-IS (LLC DSAP/SSAP 0xFE)
  if (dsap === 0xfe && ssap === 0xfe) {
    const isisResult = sanitizeIsis(data, offset + 3, collector, mapping, packetIndex, intents);
    coverage.push({ protocol: 'llc', offset, length: 3, status: 'covered' });
    coverage.push(...isisResult.coverage);
    return { coverage, lastCoveredOffset: isisResult.lastCoveredOffset };
  }

  if (policy.cdp && dsap === 0xaa && ssap === 0xaa && offset + 8 <= data.length) {
    const oui = (data[offset + 3]! << 16) | (data[offset + 4]! << 8) | data[offset + 5]!;
    const pid = (data[offset + 6]! << 8) | data[offset + 7]!;
    if (oui === 0x00000c && pid === 0x2000) {
      const cdpResult = sanitizeCdp(data, offset + 8, collector, mapping, packetIndex, intents);
      coverage.push({ protocol: 'llc-snap', offset, length: 8, status: 'covered' });
      coverage.push(...cdpResult.coverage);
      return { coverage, lastCoveredOffset: cdpResult.lastCoveredOffset };
    }
  }

  coverage.push({ protocol: `llc-0x${dsap.toString(16)}`, offset, length: data.length - offset, status: 'unsupported' });
  return { coverage, lastCoveredOffset: offset };
}

/**
 * Classic/RSTP Spanning Tree Configuration BPDU (IEEE 802.1D/w). Only the Root/Bridge
 * Identifier's embedded MAC is a real host identity; version, type, flags, path cost, port
 * ID and all timers are exactly the topology/timing information an AI needs to diagnose
 * flapping, root changes or misconfigured timers, so they pass through untouched.
 */
function sanitizeStp(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = [];
  if (offset + 4 > data.length) {
    coverage.push({ protocol: 'stp', offset, length: data.length - offset, status: 'malformed' });
    return { coverage, lastCoveredOffset: offset };
  }
  const version = data[offset + 2]!;
  const bpduType = data[offset + 3]!;
  if (bpduType === 0x80) {
    // Topology Change Notification BPDU — 4 bytes total, nothing identifying in it.
    coverage.push({ protocol: 'stp-tcn', offset, length: 4, status: 'covered' });
    return { coverage, lastCoveredOffset: offset + 4 };
  }

  const CONFIG_LEN = 35;
  if (offset + CONFIG_LEN > data.length) {
    coverage.push({ protocol: 'stp', offset, length: data.length - offset, status: 'malformed' });
    return { coverage, lastCoveredOffset: offset };
  }
  // Root Identifier: 2-byte priority (offset+5,6) + 6-byte bridge MAC (offset+7..12).
  patchMac(data, offset + 7, collector, mapping, packetIndex, intents);
  // Bridge Identifier: 2-byte priority (offset+17,18) + 6-byte bridge MAC (offset+19..24).
  patchMac(data, offset + 19, collector, mapping, packetIndex, intents);
  coverage.push({ protocol: 'stp', offset, length: CONFIG_LEN, status: 'covered' });

  let lastCoveredOffset = offset + CONFIG_LEN;
  // MSTP (version 3, IEEE 802.1Q clause 14.6): Version 1 Length(1) + Version 3 Length(2),
  // then the MST Configuration Identifier — Format Selector(1) + Configuration Name(32,
  // admin-set, null-padded ASCII — a real identity, unlike everything else in this BPDU) +
  // Revision Level(2) + Configuration Digest(16) — then CIST Internal Root Path Cost(4) +
  // CIST Bridge Identifier(8, embeds another bridge MAC) + CIST Remaining Hops(1), then
  // per-instance MSTI Configuration Messages. Fail closed to the existing structural
  // passthrough below if the lengths don't check out (e.g. RSTP's Version 1 Length isn't 0).
  if (version === 3 && lastCoveredOffset + 3 <= data.length) {
    const v1Len = data[lastCoveredOffset]!;
    const v3Len = (data[lastCoveredOffset + 1]! << 8) | data[lastCoveredOffset + 2]!;
    const mstpStart = lastCoveredOffset + 3;
    const MCID_LEN = 51; // format selector(1) + config name(32) + revision(2) + digest(16)
    const CIST_FIXED_LEN = 4 + 8 + 1; // root path cost + bridge id + remaining hops
    if (v1Len === 0 && mstpStart + MCID_LEN + CIST_FIXED_LEN <= data.length && mstpStart + v3Len <= data.length) {
      // Version 1 Length(1) + Version 3 Length(2) + MCID Format Selector(1) — all fixed/reserved.
      coverage.push({ protocol: 'stp-mstp-header', offset: lastCoveredOffset, length: 4, status: 'covered' });
      const configNameOffset = mstpStart + 1;
      patchMstpConfigName(data, configNameOffset, collector, mapping, packetIndex, intents);
      coverage.push({ protocol: 'stp-mstp-config-name', offset: configNameOffset, length: 32, status: 'covered' });
      const afterName = configNameOffset + 32;
      coverage.push({ protocol: 'stp-mstp-config-id', offset: afterName, length: 18, status: 'covered' }); // revision(2) + digest(16)
      const cistOffset = afterName + 18;
      patchMac(data, cistOffset + 4 + 2, collector, mapping, packetIndex, intents); // root path cost(4) + bridge priority(2)
      coverage.push({ protocol: 'stp-mstp-cist', offset: cistOffset, length: CIST_FIXED_LEN, status: 'covered' });
      const mstiStart = mstpStart + MCID_LEN + CIST_FIXED_LEN;
      const mstiEnd = mstpStart + v3Len;
      if (mstiEnd > mstiStart) {
        coverage.push({ protocol: 'stp-msti', offset: mstiStart, length: mstiEnd - mstiStart, status: 'covered' });
      }
      lastCoveredOffset = mstiEnd;
    }
  }
  // RSTP appends its own 1-byte Version 1 Length (0); anything else unaccounted for above
  // (or a structure that didn't validate) passes through as structural rather than risk a
  // partial/wrong parse.
  if (data.length > lastCoveredOffset) {
    coverage.push({ protocol: 'stp-ext', offset: lastCoveredOffset, length: data.length - lastCoveredOffset, status: 'covered' });
    lastCoveredOffset = data.length;
  }
  return { coverage, lastCoveredOffset };
}

/** MSTP Configuration Name: 32-byte null-padded ASCII, admin-set — pseudonymize like a hostname. */
function patchMstpConfigName(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const FIELD_LEN = 32;
  let strLen = 0;
  while (strLen < FIELD_LEN && data[offset + strLen] !== 0) strLen++;
  if (strLen === 0) return;
  const name = Array.from(data.slice(offset, offset + strLen)).map((b) => String.fromCharCode(b)).join('');
  intents?.recordEntityReplacement(packetIndex, offset, 'hostname', name, strLen);
  try {
    collector.addDeferred(offset, FIELD_LEN, ({ mapping: liveMapping }) => {
      const alias = liveMapping.aliasFor('hostname', name, { kind: 'text-ascii', byteLength: strLen }, name);
      const patchBytes = new Uint8Array(FIELD_LEN);
      for (let i = 0; i < alias.length && i < FIELD_LEN; i++) patchBytes[i] = alias.charCodeAt(i);
      return patchBytes;
    });
  } catch { /* overlap */ }
}

/**
 * Cisco Discovery Protocol — a TLV stream. Device-ID and VTP domain are genuine identities
 * and get redacted; embedded management addresses are remapped like any other IP; port-ID,
 * capabilities, software version and platform strings are diagnostic, not identifying, and
 * pass through untouched (this is exactly the "capability/platform TLV" the audit asked to
 * stop over-redacting).
 */
function sanitizeCdp(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = [];
  const HEADER_LEN = 4; // version(1) + ttl(1) + checksum(2)
  if (offset + HEADER_LEN > data.length) {
    coverage.push({ protocol: 'cdp', offset, length: data.length - offset, status: 'malformed' });
    return { coverage, lastCoveredOffset: offset };
  }
  coverage.push({ protocol: 'cdp', offset, length: HEADER_LEN, status: 'covered' });

  const DEVICE_ID_TYPE = 0x0001;
  const VTP_DOMAIN_TYPE = 0x0009;
  const REDACT_TYPES = new Set([VTP_DOMAIN_TYPE]);
  const ADDRESS_TYPES = new Set([0x0002, 0x0016]); // Addresses, Management-Addresses
  const NATIVE_VLAN_TYPE = 0x000a;
  let pos = offset + HEADER_LEN;
  while (pos + 4 <= data.length) {
    const tlvType = (data[pos]! << 8) | data[pos + 1]!;
    const tlvLen = (data[pos + 2]! << 8) | data[pos + 3]!;
    if (tlvLen < 4 || pos + tlvLen > data.length) {
      coverage.push({ protocol: 'cdp-tlv', offset: pos, length: data.length - pos, status: 'malformed' });
      return { coverage, lastCoveredOffset: pos };
    }
    const valueOffset = pos + 4;
    const valueLen = tlvLen - 4;
    coverage.push({ protocol: 'cdp-tlv-header', offset: pos, length: 4, status: 'covered' });

    if (tlvType === DEVICE_ID_TYPE && valueLen > 0) {
      sanitizeCdpDeviceId(data, valueOffset, valueLen, collector, mapping, packetIndex, intents, coverage);
    } else if (REDACT_TYPES.has(tlvType) && valueLen > 0) {
      const fill = createProtocolNeutralMaskFill({ length: valueLen, packetIndex, offset: valueOffset, domain: 'cdp-identity' });
      collector.maskRange(valueOffset, fill);
      intents?.recordMaskRange(packetIndex, valueOffset, valueLen, 'cdp-identity', 'cdp');
      coverage.push({ protocol: 'cdp-value', offset: valueOffset, length: valueLen, status: 'redacted' });
    } else if (ADDRESS_TYPES.has(tlvType) && valueLen >= 4) {
      sanitizeCdpAddresses(data, valueOffset, valueLen, collector, mapping, packetIndex, intents, coverage);
    } else if (tlvType === NATIVE_VLAN_TYPE && valueLen === 2) {
      // Same VLAN mapping used for the 802.1Q tag elsewhere (vlanPatch.ts) — this TLV must
      // never leak the original VLAN ID just because it's carried as a TLV instead of a tag.
      const vlanId = (data[valueOffset]! << 8) | data[valueOffset + 1]!;
      if (vlanId === 0 || vlanId === 4095) {
        coverage.push({ protocol: 'cdp-value', offset: valueOffset, length: valueLen, status: 'covered' });
      } else {
        const canonical = `${vlanId}`;
        intents?.recordEntityReplacement(packetIndex, valueOffset, 'vlan', canonical, 2);
        collector.addDeferred(valueOffset, 2, ({ mapping: liveMapping }) => {
          const mapped = liveMapping.map('vlan', canonical);
          const mappedId = Number.parseInt(mapped, 10);
          if (!Number.isInteger(mappedId) || mappedId < 0 || mappedId > 4095) return null;
          return new Uint8Array([(mappedId >> 8) & 0xff, mappedId & 0xff]);
        }, deferredBinaryMapMeta('cdp', packetIndex, 'vlan', canonical));
        coverage.push({ protocol: 'cdp-value', offset: valueOffset, length: valueLen, status: 'covered' });
      }
    } else if (valueLen > 0) {
      coverage.push({ protocol: 'cdp-value', offset: valueOffset, length: valueLen, status: 'covered' });
    }
    pos += tlvLen;
  }
  if (pos < data.length) {
    coverage.push({ protocol: 'cdp-trailer', offset: pos, length: data.length - pos, status: 'covered' });
  }
  return { coverage, lastCoveredOffset: data.length };
}

const SEP_MAC_DEVICE_ID = /^SEP([0-9A-Fa-f]{12})$/;

/**
 * CDP Device-ID. Cisco IP phones use the `SEP<12-hex-digit MAC>` convention — extracting and
 * remapping the embedded MAC through the same `mac` mapping entry used everywhere else means
 * a phone's Device-ID and its real Ethernet source MAC (if it appears elsewhere in the same
 * capture) get the SAME alias, instead of two unrelated-looking pseudonyms for one device.
 * Anything not matching this convention falls back to a full opaque redaction.
 */
function sanitizeCdpDeviceId(
  data: Uint8Array,
  valueOffset: number,
  valueLen: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
): void {
  const text = Array.from(data.slice(valueOffset, valueOffset + valueLen)).map((b) => String.fromCharCode(b)).join('');
  const match = SEP_MAC_DEVICE_ID.exec(text);
  if (match) {
    const macHex = match[1]!;
    const mac = (macHex.match(/.{2}/g) ?? []).join(':').toLowerCase();
    const macOffset = valueOffset + 3; // after "SEP"
    intents?.recordEntityReplacement(packetIndex, macOffset, 'mac', mac, 12);
    collector.addDeferred(macOffset, 12, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('mac', mac);
      const hex = mapped.replace(/:/g, '').toUpperCase();
      return new Uint8Array(Array.from(hex, (c) => c.charCodeAt(0)));
    }, deferredBinaryMapMeta('cdp', packetIndex, 'mac', mac));
    coverage.push({ protocol: 'cdp-value', offset: valueOffset, length: valueLen, status: 'covered' });
    return;
  }
  const fill = createProtocolNeutralMaskFill({ length: valueLen, packetIndex, offset: valueOffset, domain: 'cdp-identity' });
  collector.maskRange(valueOffset, fill);
  intents?.recordMaskRange(packetIndex, valueOffset, valueLen, 'cdp-identity', 'cdp');
  coverage.push({ protocol: 'cdp-value', offset: valueOffset, length: valueLen, status: 'redacted' });
}

/** CDP Address/Management-Address TLV value: a count + a sequence of (protocol, address) entries. */
function sanitizeCdpAddresses(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
): void {
  const end = offset + length;
  let pos = offset + 4; // skip "number of addresses"
  const count = length >= 4
    ? ((data[offset]! << 24) | (data[offset + 1]! << 16) | (data[offset + 2]! << 8) | data[offset + 3]!)
    : -1;
  let ok = count > 0 && count < 64;
  for (let i = 0; i < count && ok; i++) {
    if (pos + 2 > end) { ok = false; break; }
    const protocolType = data[pos]!;
    const protoLen = data[pos + 1]!;
    const protoStart = pos + 2;
    if (protoStart + protoLen + 2 > end) { ok = false; break; }
    const addrLenOffset = protoStart + protoLen;
    const addrLen = (data[addrLenOffset]! << 8) | data[addrLenOffset + 1]!;
    const addrStart = addrLenOffset + 2;
    if (addrStart + addrLen > end) { ok = false; break; }

    // Only the common IP shape (NLPID 0xcc, 4-byte address) is remapped precisely; anything
    // else in this entry is masked rather than risk misinterpreting an unfamiliar protocol field.
    if (protocolType === 1 && protoLen === 1 && data[protoStart] === 0xcc && addrLen === 4) {
      patchIpv4(data, addrStart, collector, mapping, packetIndex, intents);
    } else if (addrLen > 0) {
      const fill = createProtocolNeutralMaskFill({ length: addrLen, packetIndex, offset: addrStart, domain: 'cdp-address' });
      collector.maskRange(addrStart, fill);
      intents?.recordMaskRange(packetIndex, addrStart, addrLen, 'cdp-address', 'cdp');
    }
    pos = addrStart + addrLen;
  }
  if (!ok) {
    // Unexpected shape — fail safe: redact the whole value instead of risking a partial parse.
    const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain: 'cdp-address-fallback' });
    collector.maskRange(offset, fill);
    intents?.recordMaskRange(packetIndex, offset, length, 'cdp-address-fallback', 'cdp');
    coverage.push({ protocol: 'cdp-value', offset, length, status: 'redacted' });
    return;
  }
  coverage.push({ protocol: 'cdp-value', offset, length, status: 'covered' });
}

function decodeTransport(
  data: Uint8Array,
  offset: number,
  ipProto: number,
  _isIpv6: boolean,
  flowEndpoint: FlowEndpoint | null,
  collector: PatchCollector,
  mapping: MappingLike,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  lastCovered: number,
  packetIndex: number,
  options: SanitizeOptions = {},
): DecodeResult {
  const intents = options.intents;
  if (offset >= data.length) return { lastCoveredOffset: lastCovered };

  // Tunnel protocols — recurse into L4/app with shared policy/mapping (CF-13)
  if (ipProto === IP_PROTO_IPIP || ipProto === IP_PROTO_IPV6 || ipProto === IP_PROTO_GRE) {
    const depth = options.tunnelDepth ?? 0;
    if (depth >= MAX_TUNNEL_DEPTH) {
      coverage.push({ protocol: 'tunnel', offset, length: data.length - offset, status: 'unsupported' });
      issues.push('Tunnel depth limit reached');
      return { lastCoveredOffset: lastCovered };
    }

    const identity = { packetIndex, intents };
    const result = sanitizeTunnel(
      data,
      offset,
      data.length - offset,
      ipProto,
      collector,
      mapping,
      depth,
      (inner) => {
        const nestedCoverage: LayerCoverage[] = [];
        const nested = decodeTransport(
          data,
          inner.offset,
          inner.ipProto,
          inner.isIpv6,
          { srcIp: inner.srcIp, dstIp: inner.dstIp },
          collector,
          mapping,
          policy,
          nestedCoverage,
          issues,
          inner.offset,
          packetIndex,
          { ...options, tunnelDepth: inner.depth },
        );
        return { coverage: nestedCoverage, drop: nested.drop };
      },
      identity,
    );
    coverage.push(...result.coverage);
    if (result.depthExceeded) issues.push('Tunnel depth limit reached');
    const maxOffset = result.coverage.reduce((max, c) => Math.max(max, c.offset + c.length), lastCovered);
    return { lastCoveredOffset: maxOffset, drop: result.drop };
  }

  switch (ipProto) {
    case IP_PROTO_TCP: {
      if (offset + 20 > data.length) {
        coverage.push({ protocol: 'tcp', offset, length: data.length - offset, status: 'malformed' });
        return { lastCoveredOffset: lastCovered };
      }
      const dataOffsetField = (data[offset + 12]! >> 4) * 4;
      if (dataOffsetField < 20 || offset + dataOffsetField > data.length) {
        coverage.push({ protocol: 'tcp', offset, length: data.length - offset, status: 'malformed' });
        return { lastCoveredOffset: lastCovered };
      }

      const srcPort = (data[offset]! << 8) | data[offset + 1]!;
      const dstPort = (data[offset + 2]! << 8) | data[offset + 3]!;

      patchPort(data, offset, 'tcp', srcPort, collector, mapping, packetIndex, intents);
      patchPort(data, offset + 2, 'tcp', dstPort, collector, mapping, packetIndex, intents);

      applyTcpFingerprintPolicy(
        data,
        offset,
        dataOffsetField,
        collector,
        policy,
        coverage,
        issues,
        options.fingerprints,
        flowEndpoint,
        srcPort,
        dstPort,
        packetIndex,
        intents,
      );

      lastCovered = offset + dataOffsetField;

      const payloadOffset = offset + dataOffsetField;
      const payloadLength = data.length - payloadOffset;

      if (payloadLength > 0) {
        return runApplicationPayloadIsolated(
          data, payloadOffset, payloadLength, srcPort, dstPort, 'tcp',
          flowEndpoint, collector, mapping, policy, coverage, issues, lastCovered, packetIndex, options,
        );
      }
      return { lastCoveredOffset: lastCovered };
    }

    case IP_PROTO_UDP: {
      if (offset + 8 > data.length) {
        coverage.push({ protocol: 'udp', offset, length: data.length - offset, status: 'malformed' });
        return { lastCoveredOffset: lastCovered };
      }

      const srcPort = (data[offset]! << 8) | data[offset + 1]!;
      const dstPort = (data[offset + 2]! << 8) | data[offset + 3]!;

      patchPort(data, offset, 'udp', srcPort, collector, mapping, packetIndex, intents);
      patchPort(data, offset + 2, 'udp', dstPort, collector, mapping, packetIndex, intents);

      coverage.push({ protocol: 'udp', offset, length: 8, status: 'covered' });
      lastCovered = offset + 8;

      const payloadOffset = offset + 8;
      const payloadLength = data.length - payloadOffset;

      // Check VXLAN first — continue into inner L4/app (CF-13)
      const vxlanDepth = options.tunnelDepth ?? 0;
      const vxlanResult = sanitizeVxlan(
        data,
        payloadOffset,
        payloadLength,
        dstPort,
        collector,
        mapping,
        vxlanDepth,
        (inner) => {
          const nestedCoverage: LayerCoverage[] = [];
          const nested = decodeTransport(
            data,
            inner.offset,
            inner.ipProto,
            inner.isIpv6,
            { srcIp: inner.srcIp, dstIp: inner.dstIp },
            collector,
            mapping,
            policy,
            nestedCoverage,
            issues,
            inner.offset,
            packetIndex,
            { ...options, tunnelDepth: inner.depth },
          );
          return { coverage: nestedCoverage, drop: nested.drop };
        },
        { packetIndex, intents },
      );
      if (vxlanResult) {
        coverage.push(...vxlanResult.coverage);
        if (vxlanResult.depthExceeded) issues.push('Tunnel depth limit reached');
        const maxOffset = vxlanResult.coverage.reduce((max, c) => Math.max(max, c.offset + c.length), lastCovered);
        return { lastCoveredOffset: maxOffset, drop: vxlanResult.drop };
      }

      // T34 — Geneve / L2TP
      if (payloadLength > 0 && isGenevePort(srcPort, dstPort) && looksLikeGeneve(data, payloadOffset, payloadLength)) {
        const geneve = sanitizeGeneve(
          data,
          payloadOffset,
          payloadLength,
          collector,
          mapping,
          packetIndex,
          intents,
          vxlanDepth,
          (inner) => {
            const nestedCoverage: LayerCoverage[] = [];
            const nested = decodeTransport(
              data,
              inner.offset,
              inner.ipProto,
              inner.isIpv6,
              { srcIp: inner.srcIp, dstIp: inner.dstIp },
              collector,
              mapping,
              policy,
              nestedCoverage,
              issues,
              inner.offset,
              packetIndex,
              { ...options, tunnelDepth: inner.depth },
            );
            return { coverage: nestedCoverage, drop: nested.drop };
          },
        );
        coverage.push(...geneve.coverage);
        for (const i of geneve.issues) issues.push(i);
        return { lastCoveredOffset: geneve.lastCoveredOffset, drop: geneve.drop };
      }
      if (payloadLength > 0 && isL2tpPort(srcPort, dstPort)) {
        const l2tp = sanitizeL2tp(
          data,
          payloadOffset,
          payloadLength,
          collector,
          mapping,
          packetIndex,
          intents,
          (pppOff, _pppLen) => {
            const sliceIssues: string[] = []
            const sliceCov: LayerCoverage[] = []
            const r = continuePppAtOffset(data, pppOff, collector, mapping, packetIndex, intents)
            sliceCov.push(...r.coverage)
            for (const i of r.issues) sliceIssues.push(i)
            if (!r.done && (r.etherType === 0x0800 || r.etherType === 0x86dd)) {
              const nestedCoverage: LayerCoverage[] = []
              const isV6 = r.etherType === 0x86dd
              if (!isV6 && r.offset + 20 <= data.length) {
                patchIpv4(data, r.offset + 12, collector, mapping, packetIndex, intents)
                patchIpv4(data, r.offset + 16, collector, mapping, packetIndex, intents)
                const ihl = (data[r.offset]! & 0xf) * 4
                nestedCoverage.push({ protocol: 'ipv4', offset: r.offset, length: ihl, status: 'covered' })
                const ipProto = data[r.offset + 9]!
                const nested = decodeTransport(
                  data,
                  r.offset + ihl,
                  ipProto,
                  false,
                  {
                    srcIp: formatIpv4Address(data, r.offset + 12),
                    dstIp: formatIpv4Address(data, r.offset + 16),
                  },
                  collector,
                  mapping,
                  policy,
                  nestedCoverage,
                  issues,
                  r.offset + ihl,
                  packetIndex,
                  { ...options, tunnelDepth: vxlanDepth + 1 },
                )
                sliceCov.push(...nestedCoverage)
                return {
                  coverage: sliceCov,
                  issues: sliceIssues,
                  lastCoveredOffset: nested.lastCoveredOffset,
                }
              }
              if (isV6 && r.offset + 40 <= data.length) {
                patchIpv6(data, r.offset + 8, collector, mapping, packetIndex, intents)
                patchIpv6(data, r.offset + 24, collector, mapping, packetIndex, intents)
                nestedCoverage.push({ protocol: 'ipv6', offset: r.offset, length: 40, status: 'covered' })
                const next = data[r.offset + 6]!
                const nested = decodeTransport(
                  data,
                  r.offset + 40,
                  next,
                  true,
                  {
                    srcIp: formatIpv6Address(data, r.offset + 8),
                    dstIp: formatIpv6Address(data, r.offset + 24),
                  },
                  collector,
                  mapping,
                  policy,
                  nestedCoverage,
                  issues,
                  r.offset + 40,
                  packetIndex,
                  { ...options, tunnelDepth: vxlanDepth + 1 },
                )
                sliceCov.push(...nestedCoverage)
                return {
                  coverage: sliceCov,
                  issues: sliceIssues,
                  lastCoveredOffset: nested.lastCoveredOffset,
                }
              }
            }
            return {
              coverage: sliceCov,
              issues: sliceIssues,
              lastCoveredOffset: r.lastCoveredOffset ?? data.length,
            }
          },
        )
        coverage.push(...l2tp.coverage)
        for (const i of l2tp.issues) issues.push(i)
        return { lastCoveredOffset: l2tp.lastCoveredOffset }
      }

      if (payloadLength > 0) {
        return runApplicationPayloadIsolated(
          data, payloadOffset, payloadLength, srcPort, dstPort, 'udp',
          flowEndpoint, collector, mapping, policy, coverage, issues, lastCovered, packetIndex, options,
        );
      }
      return { lastCoveredOffset: lastCovered };
    }

    case IP_PROTO_ICMP: {
      if (offset + 8 > data.length) {
        coverage.push({ protocol: 'icmpv4', offset, length: data.length - offset, status: 'malformed' });
        return { lastCoveredOffset: lastCovered };
      }

      const icmpType = data[offset]!;
      coverage.push({ protocol: 'icmpv4', offset, length: 8, status: 'covered' });
      lastCovered = offset + 8;

      // Error messages (type 3, 4, 5, 11, 12) contain embedded IP header + ports (CF-13)
      if ((icmpType === 3 || icmpType === 4 || icmpType === 5 || icmpType === 11 || icmpType === 12) &&
          data.length > offset + 8) {
        const embeddedCoverage = sanitizeIcmpEmbedded(
          data,
          offset + 8,
          data.length - offset - 8,
          collector,
          mapping,
          { packetIndex, intents },
        );
        coverage.push(...embeddedCoverage);
        for (const c of embeddedCoverage) {
          if (c.status === 'covered' || c.status === 'redacted' || c.status === 'encrypted') {
            lastCovered = Math.max(lastCovered, c.offset + c.length);
          }
        }
      } else if ((icmpType === 0 || icmpType === 8) && data.length > offset + 8) {
        // Echo reply/request — mask opaque payload in-place (step 5).
        const payloadOffset = offset + 8;
        const payloadLen = data.length - payloadOffset;
        maskRangeDeferredProtocolNeutral(
          collector,
          payloadOffset,
          payloadLen,
          packetIndex,
          'icmp-echo-payload',
          'icmpv4',
          'icmp-echo-payload',
        );
        intents?.recordMaskRange(packetIndex, payloadOffset, payloadLen, 'icmp-echo', 'icmpv4');
        coverage.push({
          protocol: 'icmp-echo-payload',
          offset: payloadOffset,
          length: payloadLen,
          status: 'redacted',
        });
        lastCovered = data.length;
      } else if (data.length > offset + 8) {
        const payloadOffset = offset + 8;
        const payloadLen = data.length - payloadOffset;
        maskRangeDeferredProtocolNeutral(
          collector,
          payloadOffset,
          payloadLen,
          packetIndex,
          'icmp-unknown-payload',
          'icmpv4',
          'icmp-unknown-payload',
        );
        intents?.recordMaskRange(packetIndex, payloadOffset, payloadLen, 'icmp-unknown', 'icmpv4');
        coverage.push({
          protocol: 'icmp-payload',
          offset: payloadOffset,
          length: payloadLen,
          status: 'redacted',
        });
        lastCovered = data.length;
      }
      return { lastCoveredOffset: lastCovered };
    }

    case IP_PROTO_ICMPV6: {
      if (offset + 8 > data.length) {
        coverage.push({ protocol: 'icmpv6', offset, length: data.length - offset, status: 'malformed' });
        return { lastCoveredOffset: lastCovered };
      }

      const icmpType = data[offset]!;
      const icmpLength = data.length - offset;

      // NDP (CF-13) — before generic ICMP header coverage
      const ndpCoverage = sanitizeIcmpv6Ndp(
        data,
        offset,
        icmpLength,
        icmpType,
        collector,
        mapping,
        { packetIndex, intents },
      );
      if (ndpCoverage) {
        coverage.push(...ndpCoverage);
        const blocking = ndpCoverage.some(
          (c) => c.status === 'malformed' || c.status === 'unsupported',
        );
        let ndpCovered = lastCovered;
        for (const c of ndpCoverage) {
          if (c.status === 'covered' || c.status === 'redacted' || c.status === 'encrypted') {
            ndpCovered = Math.max(ndpCovered, c.offset + c.length);
          }
        }
        return { lastCoveredOffset: blocking ? lastCovered : ndpCovered };
      }

      coverage.push({ protocol: 'icmpv6', offset, length: 8, status: 'covered' });
      lastCovered = offset + 8;

      // Error messages (type 1-4) contain embedded IP header + ports (CF-13)
      if (icmpType >= 1 && icmpType <= 4 && data.length > offset + 8) {
        const embeddedCoverage = sanitizeIcmpEmbedded(
          data,
          offset + 8,
          data.length - offset - 8,
          collector,
          mapping,
          { packetIndex, intents },
        );
        coverage.push(...embeddedCoverage);
        for (const c of embeddedCoverage) {
          if (c.status === 'covered' || c.status === 'redacted' || c.status === 'encrypted') {
            lastCovered = Math.max(lastCovered, c.offset + c.length);
          }
        }
      } else if ((icmpType === 128 || icmpType === 129) && data.length > offset + 8) {
        const payloadOffset = offset + 8;
        const payloadLen = data.length - payloadOffset;
        maskRangeDeferredProtocolNeutral(
          collector,
          payloadOffset,
          payloadLen,
          packetIndex,
          'icmpv6-echo-payload',
          'icmpv6',
          'icmpv6-echo-payload',
        );
        intents?.recordMaskRange(packetIndex, payloadOffset, payloadLen, 'icmpv6-echo', 'icmpv6');
        coverage.push({
          protocol: 'icmp-echo-payload',
          offset: payloadOffset,
          length: payloadLen,
          status: 'redacted',
        });
        lastCovered = data.length;
      } else if (data.length > offset + 8) {
        const payloadOffset = offset + 8;
        const payloadLen = data.length - payloadOffset;
        maskRangeDeferredProtocolNeutral(
          collector,
          payloadOffset,
          payloadLen,
          packetIndex,
          'icmpv6-unknown-payload',
          'icmpv6',
          'icmpv6-unknown-payload',
        );
        intents?.recordMaskRange(packetIndex, payloadOffset, payloadLen, 'icmpv6-unknown', 'icmpv6');
        coverage.push({
          protocol: 'icmp-payload',
          offset: payloadOffset,
          length: payloadLen,
          status: 'redacted',
        });
        lastCovered = data.length;
      }
      return { lastCoveredOffset: lastCovered };
    }

    case IP_PROTO_VRRP: {
      if (!policy.vrrp) {
        coverage.push({ protocol: 'ipproto-112', offset, length: data.length - offset, status: 'unsupported' });
        return { lastCoveredOffset: lastCovered };
      }
      const vrrpResult = sanitizeVrrp(data, offset, _isIpv6, collector, mapping, packetIndex, intents);
      coverage.push(...vrrpResult.coverage);
      return { lastCoveredOffset: vrrpResult.lastCoveredOffset };
    }

    case IP_PROTO_OSPF: {
      const ospfResult = sanitizeOspf(data, offset, collector, mapping, packetIndex, intents);
      coverage.push(...ospfResult.coverage);
      return { lastCoveredOffset: ospfResult.lastCoveredOffset };
    }

    case IP_PROTO_EIGRP: {
      const eigrpResult = sanitizeEigrp(data, offset, collector, mapping, packetIndex, intents);
      coverage.push(...eigrpResult.coverage);
      return { lastCoveredOffset: eigrpResult.lastCoveredOffset };
    }

    case IP_PROTO_PIM: {
      const pimResult = sanitizePim(data, offset, collector, mapping, packetIndex, intents);
      coverage.push(...pimResult.coverage);
      return { lastCoveredOffset: pimResult.lastCoveredOffset };
    }

    case IP_PROTO_IGMP: {
      const igmpResult = sanitizeIgmp(data, offset, collector, mapping, packetIndex, intents);
      coverage.push(...igmpResult.coverage);
      return { lastCoveredOffset: igmpResult.lastCoveredOffset };
    }

    case IP_PROTO_SCTP: {
      const sctpResult = sanitizeSctp(
        data,
        offset,
        collector,
        mapping,
        packetIndex,
        intents,
        options.reassemblyContext,
        flowEndpoint ?? undefined,
      );
      coverage.push(...sctpResult.coverage);
      for (const issue of sctpResult.issues) issues.push(issue);
      return { lastCoveredOffset: sctpResult.lastCoveredOffset };
    }

    case IP_PROTO_ESP: {
      // T28 — ESP without SA proof is mask-only (NULL encryption is not confidentiality).
      const espResult = sanitizeEsp(data, offset, collector, mapping, packetIndex, intents);
      coverage.push(...espResult.coverage);
      for (const issue of espResult.issues) issues.push(issue);
      return { lastCoveredOffset: espResult.lastCoveredOffset };
    }

    case IP_PROTO_AH: {
      const ahResult = sanitizeAh(data, offset, collector, packetIndex, intents);
      coverage.push(...ahResult.coverage);
      for (const issue of ahResult.issues) issues.push(issue);
      return { lastCoveredOffset: ahResult.lastCoveredOffset };
    }

    default:
      coverage.push({ protocol: `ipproto-${ipProto}`, offset, length: data.length - offset, status: 'unsupported' });
      return { lastCoveredOffset: lastCovered };
  }
}

/**
 * VRRP (RFC 3768 v2 / RFC 5798 v3) — the only genuinely identifying field is the virtual IP
 * list; version, type, VRID, priority, address count, interval and checksum are protocol
 * mechanics an AI/analyst needs intact to reason about failover behaviour, so they pass through.
 */
function sanitizeVrrp(
  data: Uint8Array,
  offset: number,
  isIpv6: boolean,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = [];
  const HEADER_LEN = 8;
  if (offset + HEADER_LEN > data.length) {
    coverage.push({ protocol: 'vrrp', offset, length: data.length - offset, status: 'malformed' });
    return { coverage, lastCoveredOffset: offset };
  }

  const version = data[offset]! >> 4;
  const countAddr = data[offset + 3]!;
  const addrSize = isIpv6 ? 16 : 4;
  const addrStart = offset + HEADER_LEN;
  const addrEnd = addrStart + countAddr * addrSize;
  if (countAddr === 0 || addrEnd > data.length) {
    coverage.push({ protocol: 'vrrp', offset, length: data.length - offset, status: 'malformed' });
    return { coverage, lastCoveredOffset: offset };
  }

  for (let i = 0; i < countAddr; i++) {
    const addrOffset = addrStart + i * addrSize;
    if (isIpv6) patchIpv6(data, addrOffset, collector, mapping, packetIndex, intents);
    else patchIpv4(data, addrOffset, collector, mapping, packetIndex, intents);
  }
  coverage.push({ protocol: 'vrrp', offset, length: addrEnd - offset, status: 'covered' });

  let lastCoveredOffset = addrEnd;
  // v2 appends an 8-byte Authentication Data trailer (dropped entirely in v3/RFC 5798).
  if (version === 2 && addrEnd + 8 <= data.length) {
    const authType = data[offset + 4]!;
    const authOffset = addrEnd;
    if (authType === 1) {
      // Type 1 "Simple Text Authentication" carries a cleartext password — redact it.
      const fill = createProtocolNeutralMaskFill({ length: 8, packetIndex, offset: authOffset, domain: 'vrrp-auth' });
      collector.maskRange(authOffset, fill);
      intents?.recordMaskRange(packetIndex, authOffset, 8, 'vrrp-auth', 'vrrp');
      coverage.push({ protocol: 'vrrp-auth', offset: authOffset, length: 8, status: 'redacted' });
    } else {
      coverage.push({ protocol: 'vrrp-auth', offset: authOffset, length: 8, status: 'covered' });
    }
    lastCoveredOffset = authOffset + 8;
  }
  return { coverage, lastCoveredOffset };
}

/**
 * T07 — isolate app-layer exceptions to payload fallback without aborting L3/L4 work.
 */
function runApplicationPayloadIsolated(
  data: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  transport: 'tcp' | 'udp',
  flowEndpoint: FlowEndpoint | null,
  collector: PatchCollector,
  mapping: MappingLike,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  lastCovered: number,
  packetIndex: number,
  options: SanitizeOptions = {},
): DecodeResult {
  try {
    return handleApplicationPayload(
      data, offset, length, srcPort, dstPort, transport,
      flowEndpoint, collector, mapping, policy, coverage, issues, lastCovered, packetIndex, options,
    )
  } catch {
    const highPrivacy = policy.preset === 'high-privacy'
    if (highPrivacy) {
      // Truncate at L4 end (payload removed).
      coverage.push({
        protocol: 'processing-failed',
        offset,
        length,
        status: 'processing-failed',
      })
      issues.push('isolation:payload:sanitizer-exception')
      return { lastCoveredOffset: offset, drop: false }
    }
    const fill = createProtocolNeutralMaskFill({
      length,
      packetIndex,
      offset,
      domain: 'isolation:payload',
    })
    try {
      collector.maskRange(offset, fill)
    } catch {
      // Overlap with prior patches — best-effort; coverage still marks failure.
    }
    options.intents?.recordMaskRange(
      packetIndex,
      offset,
      length,
      'isolation-payload',
      'processing-failed',
    )
    coverage.push({
      protocol: 'processing-failed',
      offset,
      length,
      status: 'processing-failed',
    })
    issues.push('isolation:payload:sanitizer-exception')
    return { lastCoveredOffset: offset + length }
  }
}

/**
 * Application dispatch — order must stay aligned with
 * `kernel/applicationHandlers.ts::APPLICATION_HANDLER_ORDER` (architecture guard).
 * New protocols: register in the kernel catalog/manifest + handler order; avoid a second switch.
 *
 * T-01.F: registered handlers run via `applicationDispatchRegistry.ts` in
 * APPLICATION_HANDLER_ORDER; remaining ids stay in the inline chain below (strangler).
 */
function handleApplicationPayload(
  data: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  transport: 'tcp' | 'udp',
  flowEndpoint: FlowEndpoint | null,
  collector: PatchCollector,
  mapping: MappingLike,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  lastCovered: number,
  packetIndex: number,
  options: SanitizeOptions = {},
): DecodeResult {
  const intents = options.intents;
  const reassemblyOverlay = options.reassemblyContext?.overlayFor(packetIndex);
  const onInnerTransport: InnerTransportHandler = (inner) => {
    const nestedCoverage: LayerCoverage[] = [];
    const nested = decodeTransport(
      data,
      inner.offset,
      inner.ipProto,
      inner.isIpv6,
      { srcIp: inner.srcIp, dstIp: inner.dstIp },
      collector,
      mapping,
      policy,
      nestedCoverage,
      issues,
      inner.offset,
      packetIndex,
      { ...options, tunnelDepth: inner.depth },
    );
    return { coverage: nestedCoverage, drop: nested.drop };
  };
  const registryHit = dispatchRegisteredApplicationHandlers({
    data,
    offset,
    length,
    srcPort,
    dstPort,
    transport,
    flowEndpoint,
    collector,
    mapping,
    policy,
    coverage,
    issues,
    lastCovered,
    packetIndex,
    intents,
    skipAppLayer: reassemblyOverlay?.skipAppLayer,
    mediaFlowIndex: options.mediaFlowIndex,
    payloadTime: options.payloadTime,
    tunnelDepth: options.tunnelDepth,
    generationId: options.generationId,
    sourceId: options.sourceId,
    journal: options.journal,
    kernelSymbolicOps: options.kernelSymbolicOps,
    coapBlock2: options.coapBlock2,
    opcuaChannel: options.opcuaChannel,
    onInnerTransport,
  });
  if (registryHit) {
    return {
      lastCoveredOffset: registryHit.lastCoveredOffset,
      drop: registryHit.drop,
    };
  }

  // T-01.F — remaining inline strangler tail (heuristic only; handlers live in registry).
  if (reassemblyOverlay?.skipAppLayer) {
    return { lastCoveredOffset: lastCovered };
  }

  // T09 — identify-only name before generic fallback (same function for discovery + plan).
  const identified = identifyUnsupportedApplicationPayload({
    data,
    offset,
    length,
    srcPort,
    dstPort,
    transport: transport === 'tcp' || transport === 'udp' ? transport : 'unknown',
  });
  const fallbackProtocol = identified
    ? unsupportedCoverageProtocolId(identified)
    : null;

  // Generic best-effort fallback — proprietary / unknown payloads (CF-03: empty scan
  // must not claim the whole range as heuristically covered).
  if (policy.heuristicScan) {
    const genericResult = sanitizeGenericPayload(
      data,
      offset,
      length,
      collector,
      mapping,
      intents,
      packetIndex,
      policy.preset === 'high-privacy',
    );
    if (genericResult.coverage.length === 0) {
      coverage.push({
        protocol: fallbackProtocol ?? 'payload',
        offset,
        length,
        status: 'unsupported',
      });
      return { lastCoveredOffset: lastCovered };
    }
    // Keep status heuristic; rename protocol when signature matched (D4).
    if (fallbackProtocol) {
      coverage.push(
        ...genericResult.coverage.map((span) => ({ ...span, protocol: fallbackProtocol })),
      );
    } else {
      coverage.push(...genericResult.coverage);
    }
    // heuristic is a blocking CF-09 status — do not advance lastCovered past transport.
    return { lastCoveredOffset: lastCovered };
  }

  // Unknown/unsupported payload
  coverage.push({
    protocol: fallbackProtocol ?? 'payload',
    offset,
    length,
    status: 'unsupported',
  });
  return { lastCoveredOffset: lastCovered };
}

function coverageStatusForPreserve(policy: FingerprintFieldPolicy): LayerCoverage['status'] {
  if (policy === 'preserve-for-diagnostics') return 'preserved-for-diagnostics';
  return 'preserved-unsafe';
}

function applyIpv4FingerprintPolicy(
  data: Uint8Array,
  offset: number,
  ihl: number,
  collector: PatchCollector,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  _fingerprints: FingerprintSession | undefined,
  srcIp: string,
  dstIp: string,
  ipProto: number,
  packetIndex: number,
): void {
  const fp = policy.networkFingerprint;

  const origId = (data[offset + 4]! << 8) | data[offset + 5]!;
  if (fp.ipv4Id === 'map') {
    try {
      collector.addDeferred(offset + 4, 2, ({ fingerprints: liveFp }) => {
        const mapped = liveFp.mapIpv4Id(srcIp, dstIp, ipProto, origId);
        return new Uint8Array([(mapped >> 8) & 0xff, mapped & 0xff]);
      }, deferredIpv4IdFingerprintMeta(packetIndex, srcIp, dstIp, ipProto, origId));
    } catch { /* overlap */ }
    coverage.push({ protocol: 'ipv4-id', offset: offset + 4, length: 2, status: 'covered' });
  } else {
    coverage.push({
      protocol: 'ipv4-id',
      offset: offset + 4,
      length: 2,
      status: coverageStatusForPreserve(fp.ipv4Id),
    });
    issues.push('fingerprint:ipv4-id-preserved');
  }

  if (fp.ttl === 'normalize') {
    try { collector.add(offset + 8, new Uint8Array([64])); } catch { /* overlap */ }
    coverage.push({ protocol: 'ipv4-ttl', offset: offset + 8, length: 1, status: 'covered' });
  } else {
    coverage.push({
      protocol: 'ipv4-ttl',
      offset: offset + 8,
      length: 1,
      status: coverageStatusForPreserve(fp.ttl),
    });
    issues.push(
      fp.ttl === 'preserve-for-diagnostics'
        ? 'fingerprint:ipv4-ttl-preserved-for-diagnostics'
        : 'fingerprint:ipv4-ttl-preserved',
    );
  }

  coverage.push({ protocol: 'ipv4', offset, length: ihl, status: 'covered' });
}

function applyIpv6FingerprintPolicy(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  _fingerprints: FingerprintSession | undefined,
  srcIp: string,
  dstIp: string,
  packetIndex: number,
): void {
  const fp = policy.networkFingerprint;

  if (fp.flowLabel === 'normalize') {
    const tcHigh = data[offset]! & 0x0f;
    const tcLow = data[offset + 1]! & 0xf0;
    try {
      collector.add(offset, new Uint8Array([0x60 | tcHigh, tcLow, 0, 0]));
    } catch { /* overlap */ }
    coverage.push({ protocol: 'ipv6-flow', offset, length: 4, status: 'covered' });
  } else if (fp.flowLabel === 'map') {
    const versionTc = data[offset]!;
    const tcHigh = versionTc & 0x0f;
    const b1 = data[offset + 1]!;
    const tcLow = b1 & 0xf0;
    const origLabel =
      ((b1 & 0x0f) << 16) | (data[offset + 2]! << 8) | data[offset + 3]!;
    try {
      collector.addDeferred(offset, 4, ({ fingerprints: liveFp }) => {
        const mapped = liveFp.mapFlowLabel(srcIp, dstIp, origLabel);
        return new Uint8Array([
          0x60 | tcHigh,
          tcLow | ((mapped >> 16) & 0x0f),
          (mapped >> 8) & 0xff,
          mapped & 0xff,
        ]);
      }, deferredFlowLabelFingerprintMeta(
        packetIndex,
        srcIp,
        dstIp,
        0x60 | tcHigh,
        b1,
        origLabel,
      ));
    } catch { /* overlap */ }
    coverage.push({ protocol: 'ipv6-flow', offset, length: 4, status: 'covered' });
  } else {
    coverage.push({
      protocol: 'ipv6-flow',
      offset,
      length: 4,
      status: coverageStatusForPreserve(fp.flowLabel),
    });
    issues.push('fingerprint:ipv6-flow-preserved');
  }

  if (fp.ttl === 'normalize') {
    try { collector.add(offset + 7, new Uint8Array([64])); } catch { /* overlap */ }
    coverage.push({ protocol: 'ipv6-hop', offset: offset + 7, length: 1, status: 'covered' });
  } else {
    coverage.push({
      protocol: 'ipv6-hop',
      offset: offset + 7,
      length: 1,
      status: coverageStatusForPreserve(fp.ttl),
    });
    issues.push(
      fp.ttl === 'preserve-for-diagnostics'
        ? 'fingerprint:ipv6-hop-preserved-for-diagnostics'
        : 'fingerprint:ipv6-hop-preserved',
    );
  }

  coverage.push({ protocol: 'ipv6', offset, length: 40, status: 'covered' });
}

function applyTcpFingerprintPolicy(
  data: Uint8Array,
  offset: number,
  headerLen: number,
  collector: PatchCollector,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  issues: string[],
  _fingerprints: FingerprintSession | undefined,
  flowEndpoint: FlowEndpoint | null,
  srcPort: number,
  dstPort: number,
  packetIndex = 0,
  intents?: IntentCollector,
): void {
  const fp = policy.networkFingerprint;

  if (fp.tcpSeq === 'map' && flowEndpoint) {
    // PF-06: tcpSeqOffsetForEndpoint() memoizes per direction key, so calling it again per
    // deferred field (instead of once eagerly) is safe and returns the same forward/reverse —
    // it just moves *when* the live, seeded FingerprintSession is consulted.
    const ep = { srcIp: flowEndpoint.srcIp, dstIp: flowEndpoint.dstIp, srcPort, dstPort };
    // T-01: capture numeric originals now — deferred computes must not close over packet `data`.
    const origSeq = readU32(data, offset + 4);
    const origAck = readU32(data, offset + 8);
    try {
      collector.addDeferred(offset + 4, 4, ({ fingerprints: liveFp }) => {
        const { forward } = liveFp.tcpSeqOffsetForEndpoint(ep);
        return u32ToBytes(addU32Mod(origSeq, forward));
      }, deferredTcpU32FingerprintMeta(
        packetIndex,
        ep.srcIp,
        ep.dstIp,
        srcPort,
        dstPort,
        'seq',
        origSeq,
      ));
    } catch { /* overlap */ }
    try {
      collector.addDeferred(offset + 8, 4, ({ fingerprints: liveFp }) => {
        const { reverse } = liveFp.tcpSeqOffsetForEndpoint(ep);
        return u32ToBytes(addU32Mod(origAck, reverse));
      }, deferredTcpU32FingerprintMeta(
        packetIndex,
        ep.srcIp,
        ep.dstIp,
        srcPort,
        dstPort,
        'ack',
        origAck,
      ));
    } catch { /* overlap */ }
    coverage.push({ protocol: 'tcp-seq', offset: offset + 4, length: 8, status: 'covered' });

    if (headerLen > 20) {
      // Structural option walk is mapping-independent — do it once now; defer only the
      // per-field value (each field's own deferred patch, matching the per-field overlap
      // semantics patchTcpOptionsSeqSpace already had).
      const fields = findTcpOptionsSeqFields(data, offset + 20, headerLen - 20, true);
      for (const field of fields) {
        const base = readU32(data, field.offset);
        const kind = field.kind;
        try {
          collector.addDeferred(field.offset, 4, ({ fingerprints: liveFp }) => {
            const { forward, reverse } = liveFp.tcpSeqOffsetForEndpoint(ep);
            if (kind === 'sack-left' || kind === 'sack-right') {
              return u32ToBytes(addU32Mod(base, reverse));
            }
            return u32ToBytes(addU32Mod(base, kind === 'ts-val' ? forward : reverse));
          }, deferredTcpU32FingerprintMeta(
            packetIndex,
            ep.srcIp,
            ep.dstIp,
            srcPort,
            dstPort,
            kind,
            base,
          ));
        } catch { /* overlap */ }
      }
    }
  } else {
    coverage.push({
      protocol: 'tcp-seq',
      offset: offset + 4,
      length: 8,
      status: coverageStatusForPreserve(fp.tcpSeq === 'map' ? 'preserve-unsafe' : fp.tcpSeq),
    });
    issues.push('fingerprint:tcp-seq-preserved');
  }

  if (fp.tcpWindow === 'normalize') {
    try { collector.add(offset + 14, new Uint8Array([0x20, 0x00])); } catch { /* overlap */ }
    coverage.push({ protocol: 'tcp-window', offset: offset + 14, length: 2, status: 'covered' });
  } else {
    coverage.push({
      protocol: 'tcp-window',
      offset: offset + 14,
      length: 2,
      status: coverageStatusForPreserve(fp.tcpWindow),
    });
    issues.push(
      fp.tcpWindow === 'preserve-for-diagnostics'
        ? 'fingerprint:tcp-window-preserved-for-diagnostics'
        : 'fingerprint:tcp-window-preserved',
    );
  }

  if (headerLen > 20) {
    // T38 — always mask TCP MD5 (19) / TCP-AO (29) digests regardless of fingerprint policy.
    const authCov = sanitizeTcpAuthOptions(
      data,
      offset + 20,
      headerLen - 20,
      collector,
      packetIndex,
      intents,
    );
    coverage.push(...authCov);

    if (fp.tcpOptions === 'normalize') {
      // Only the MSS value and Window Scale factor carry real p0f-style OS/stack fingerprint
      // information; everything else about the options area (which options are present, their
      // order, NOP padding) stays exactly as captured.
      const normalizeFields = findTcpOptionsNormalizeFields(data, offset + 20, headerLen - 20);
      for (const field of normalizeFields) {
        try {
          if (field.kind === 'mss') {
            collector.add(field.offset, new Uint8Array([0x05, 0xb4])); // 1460, the common Ethernet MSS
          } else {
            collector.add(field.offset, new Uint8Array([0x07])); // a common Window Scale factor
          }
        } catch { /* overlap */ }
      }
      coverage.push({ protocol: 'tcp-options', offset: offset + 20, length: headerLen - 20, status: 'covered' });
    } else {
      coverage.push({
        protocol: 'tcp-options',
        offset: offset + 20,
        length: headerLen - 20,
        status: coverageStatusForPreserve(fp.tcpOptions === 'map' ? 'preserve-for-diagnostics' : fp.tcpOptions),
      });
      issues.push(
        fp.tcpOptions === 'preserve-for-diagnostics'
          ? 'fingerprint:tcp-options-preserved-for-diagnostics'
          : 'fingerprint:tcp-options-preserved',
      );
    }
  }

  coverage.push({ protocol: 'tcp', offset, length: headerLen, status: 'covered' });
}

function patchIpv4(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
  if (ip === '0.0.0.0') return;
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4);
  // PF-06: defer the mapping.map() call + encode so plan-build can resolve this against the
  // real snapshot without re-running the structural decode that found this field.
  try {
    collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv4', ip);
      return new Uint8Array(mapped.split('.').map(Number));
    }, deferredBinaryMapMeta('ipv4', packetIndex, 'ipv4', ip));
  } catch { /* overlap with already patched field */ }
}

function patchIpv6(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = ipv6Bytes16ToText(data, offset);
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16);
  try {
    collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv6', ip);
      return ipv6TextToBytes16(mapped);
    }, deferredBinaryMapMeta('ipv6', packetIndex, 'ipv6', ip));
  } catch { /* overlap */ }
}

function patchMac(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const mac = Array.from(data.slice(offset, offset + 6))
    .map(b => b.toString(16).padStart(2, '0')).join(':');
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'mac', mac, 6);
  try {
    collector.addDeferred(offset, 6, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('mac', mac);
      return new Uint8Array(mapped.split(':').map(s => parseInt(s, 16)));
    }, deferredBinaryMapMeta('mac', packetIndex, 'mac', mac));
  } catch { /* overlap */ }
}

function patchPort(
  _data: Uint8Array,
  offset: number,
  proto: 'tcp' | 'udp',
  port: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const canonical = `${proto}/${port}`;
  if (intents) intents.recordEntityReplacement(packetIndex, offset, 'port', canonical, 2);
  try {
    collector.addDeferred(offset, 2, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('port', canonical);
      const slash = mapped.indexOf('/');
      if (slash < 0) return null;
      const mappedPort = Number.parseInt(mapped.slice(slash + 1), 10);
      if (!Number.isInteger(mappedPort) || mappedPort < 0 || mappedPort > 65535 || mappedPort === port) return null;
      return new Uint8Array([(mappedPort >> 8) & 0xff, mappedPort & 0xff]);
    }, deferredPortMapMeta(proto, packetIndex, proto, port));
  } catch { /* overlap with already patched field */ }
}

function formatIpv4Address(data: Uint8Array, offset: number): string {
  return `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
}

function formatIpv6Address(data: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((data[offset + i]! << 8) | data[offset + i + 1]!).toString(16));
  }
  return parts.join(':');
}

function mergeKernelSymbolicMapOps(
  fromCollector: readonly import('../kernel/operations').SymbolicOperation[],
  fromKernel: readonly import('../kernel/operations').SymbolicOperation[] | undefined,
): readonly import('../kernel/operations').SymbolicOperation[] {
  if (!fromKernel?.length) return fromCollector
  if (!fromCollector.length) return fromKernel
  const byOffset = new Map<number, import('../kernel/operations').SymbolicOperation>()
  for (const op of [...fromCollector, ...fromKernel]) {
    if (
      op.kind === 'map'
      || op.kind === 'mask'
      || op.kind === 'secret'
      || op.kind === 'fingerprint'
    ) {
      byOffset.set(op.offset, op)
    }
  }
  const structured = [...byOffset.values()].sort(
    (a, b) => mergeSymbolicOpOffset(a) - mergeSymbolicOpOffset(b),
  )
  const other = [
    ...fromCollector.filter((o) =>
      o.kind !== 'map' && o.kind !== 'mask' && o.kind !== 'secret' && o.kind !== 'fingerprint'),
    ...fromKernel.filter((o) =>
      o.kind !== 'map' && o.kind !== 'mask' && o.kind !== 'secret' && o.kind !== 'fingerprint'),
  ]
  return [...other, ...structured]
}

function mergeSymbolicOpOffset(op: import('../kernel/operations').SymbolicOperation): number {
  return op.kind === 'checksum' ? 0 : op.offset
}
