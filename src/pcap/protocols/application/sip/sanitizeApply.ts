/**
 * Structured SIP/SDP sanitization — build combined redaction plan and apply patches (step 7).
 * Body ops come from {@link planSipBodyOperations} (shared with discovery — T02).
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector';
import { patchFixedLengthAscii, computeFixedLengthAsciiBytes } from '../../../sanitize/textPatch';
import type { MappingLike } from '../../../anonymization/mapping';
import type { ByteSpan, SipMessage } from './types';
import { decodeLatin1Span } from './bytes';
import { extractSipEntities } from './extract';
import { buildSipRedactionPlan, SIP_REDACT_MASK_BYTE } from './redactPlan';
import type { SipRedactionOperation } from './entities';
import { resolveIdentityAlias, wirePortCanonical, type PortContext } from './mappingWire';
import { shiftSessionVersion } from '../sdp/sessionVersionShift';
import { sdpSessionIdDigits } from '../../../../mapping/pcapCanonical';
import {
  planSipBodyOperations,
  type SipBodyOperation,
} from './bodyOperations';
import { canonicalizeIdentity } from '../../../../mapping/canonicalize';
import type { IdentityCategory } from '../../../../mapping/identityCategories';
import {
  deferredSessionVersionMeta,
  deferredTextMapMeta,
} from '../../../sanitize/deferredMapMeta.ts';

type CombinedOperation = {
  readonly span: ByteSpan;
  readonly action: 'map' | 'redact';
  readonly mappingCategory: string | null;
  readonly canonicalText: string;
  readonly maskByte: number;
  readonly portContext: PortContext;
  readonly sessionIdForVersion?: string;
  /** T14 — absolute HTTP-date style value; rewrite via PayloadTimeSession. */
  readonly payloadTimeRewrite?: boolean;
};

export function buildCombinedSipSdpPlan(
  message: SipMessage,
  buffer: Uint8Array,
): { readonly operations: CombinedOperation[]; readonly issues: readonly string[] } {
  const operations: CombinedOperation[] = [];
  const issues: string[] = [];

  const { entities: sipEntities, issues: sipIssues } = extractSipEntities(message, buffer);
  issues.push(...sipIssues);
  const sipPlan = buildSipRedactionPlan(sipEntities);
  for (const op of sipPlan.operations) {
    operations.push(toCombined(op, 'signaling', SIP_REDACT_MASK_BYTE));
  }

  const bodyPlan = planSipBodyOperations(message, buffer);
  issues.push(...bodyPlan.issues);
  for (const op of bodyPlan.operations) {
    operations.push(fromBodyOp(op));
  }

  operations.sort((a, b) => a.span.offset - b.span.offset);
  return { operations: dedupeNonOverlapping(operations), issues };
}

function fromBodyOp(op: SipBodyOperation): CombinedOperation {
  return {
    span: op.span,
    action: op.action,
    mappingCategory: op.mappingCategory,
    canonicalText: op.canonicalText,
    maskByte: op.maskByte,
    portContext: op.portContext,
    ...(op.sessionIdForVersion !== undefined
      ? { sessionIdForVersion: op.sessionIdForVersion }
      : {}),
  };
}

function toCombined(
  op: SipRedactionOperation,
  portContext: PortContext,
  defaultMask: number,
): CombinedOperation {
  // T14 — Date header: map + null category + RFC1123-shaped text from extract.
  const payloadTimeRewrite =
    op.action === 'map'
    && op.mappingCategory === null
    && /^[A-Za-z]{3}, \d{2} /.test(op.canonicalText);
  return {
    span: op.span,
    action: op.action,
    mappingCategory: op.mappingCategory,
    canonicalText: op.canonicalText,
    maskByte: op.maskByte ?? defaultMask,
    portContext,
    ...(payloadTimeRewrite ? { payloadTimeRewrite: true } : {}),
  };
}

function dedupeNonOverlapping(ops: CombinedOperation[]): CombinedOperation[] {
  const out: CombinedOperation[] = [];
  let lastEnd = -1;
  for (const op of ops) {
    const end = op.span.offset + op.span.length;
    if (op.span.offset < lastEnd) continue;
    out.push(op);
    lastEnd = end;
  }
  return out;
}

export function applyCombinedSipSdpPlan(
  plan: readonly CombinedOperation[],
  buffer: Uint8Array,
  transport: 'tcp' | 'udp',
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex?: number,
): void {
  for (const op of plan) {
    const { offset, length } = op.span;
    if (length <= 0) continue;

    if (op.action === 'redact') {
      const mask = String.fromCharCode(op.maskByte).repeat(length);
      patchFixedLengthAscii(collector, offset, length, mask, op.maskByte);
      continue;
    }

    const originalSpelling = decodeLatin1Span(buffer, op.span);

    // T14 — SIP Date: capture-aligned shift or same-length mask.
    if (op.payloadTimeRewrite) {
      const original = originalSpelling;
      collector.addDeferred(
        offset,
        length,
        (ctx) => {
          const session = ctx.payloadTime;
          if (!session) {
            return computeFixedLengthAsciiBytes(offset, length, '', op.maskByte);
          }
          const rewrite = session.rewriteHttpDateFixedLength(original.trim());
          if (rewrite.kind === 'mask') {
            return computeFixedLengthAsciiBytes(offset, length, '', op.maskByte);
          }
          // Preserve original whitespace/padding around the date token when lengths match.
          if (rewrite.text.length === original.length) {
            return computeFixedLengthAsciiBytes(offset, length, rewrite.text);
          }
          if (rewrite.text.length === original.trim().length) {
            const leading = original.match(/^\s*/)?.[0] ?? '';
            const trailing = original.match(/\s*$/)?.[0] ?? '';
            const padded = `${leading}${rewrite.text}${trailing}`;
            if (padded.length === original.length) {
              return computeFixedLengthAsciiBytes(offset, length, padded);
            }
          }
          return computeFixedLengthAsciiBytes(offset, length, '', op.maskByte);
        },
        { fallbackKind: 'text-x', protocol: 'sip', category: 'timestamp' },
      );
      continue;
    }

    // T01: session-version is not an identity — shift from mapped session-id alias.
    if (op.sessionIdForVersion !== undefined) {
      const sessionIdCanonical = op.sessionIdForVersion;
      const versionOriginal = originalSpelling;
      const versionMeta =
        packetIndex === undefined
          ? { fallbackKind: 'digits' as const, protocol: 'sdp', category: 'sdp-session-id' }
          : deferredSessionVersionMeta(packetIndex, versionOriginal, sessionIdCanonical);
      collector.addDeferred(
        offset,
        length,
        ({ mapping: liveMapping }) => {
          const sessionIdDigits = sdpSessionIdDigits(sessionIdCanonical);
          const idAlias = resolveIdentityAlias(
            liveMapping,
            'sdp-session-id',
            sessionIdCanonical,
            transport,
            'signaling',
            sessionIdDigits,
          );
          const shifted = shiftSessionVersion(versionOriginal, sessionIdDigits, idAlias);
          return computeFixedLengthAsciiBytes(offset, length, shifted);
        },
        versionMeta,
      );
      continue;
    }

    if (op.mappingCategory === null) continue;
    const mappingCategory = op.mappingCategory as IdentityCategory;
    const canonicalText = op.canonicalText;
    const portContext = op.portContext;
    const protocol =
      mappingCategory === 'sdp-session-id' || mappingCategory === 'port' ? 'sdp' : 'sip';
    const mapMeta =
      packetIndex === undefined
        ? {
            fallbackKind: sipTextFallbackKind(mappingCategory),
            protocol,
            category: mappingCategory,
          }
        : deferredTextMapMeta(
            protocol,
            packetIndex,
            mappingCategory,
            originalSpelling,
            length,
            {
              fallbackKind: sipTextFallbackKind(mappingCategory),
              // Same key as discovery (recordMappedEntity) and resolveIdentityAlias: text ports
              // are registered as `udp/<n>` / `tcp/<n>`, never the bare digits.
              canonical:
                mappingCategory === 'port'
                  ? wirePortCanonical(canonicalText, transport, portContext)
                  : canonicalizeIdentity(mappingCategory, canonicalText) ?? canonicalText,
            },
          );
    collector.addDeferred(
      offset,
      length,
      ({ mapping: liveMapping }) => {
        const alias = resolveIdentityAlias(
          liveMapping,
          mappingCategory,
          canonicalText,
          transport,
          portContext,
          originalSpelling,
        );
        return computeFixedLengthAsciiBytes(offset, length, alias);
      },
      mapMeta,
    );
  }
}

function sipTextFallbackKind(category: string): 'digits' | 'text-x' {
  return category === 'port' || category === 'sdp-session-id' || category === 'vlan'
    ? 'digits'
    : 'text-x';
}

export function sanitizeStructuredSipMessage(
  buffer: Uint8Array,
  message: SipMessage,
  transport: 'tcp' | 'udp',
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex?: number,
): readonly string[] {
  const { operations, issues } = buildCombinedSipSdpPlan(message, buffer);
  applyCombinedSipSdpPlan(operations, buffer, transport, collector, mapping, packetIndex);
  return issues;
}
