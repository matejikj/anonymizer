/**
 * Build redaction plan from extracted SDP entities.
 */

import type { ByteSpan } from '../sip/types';
import type { SdpRedactionPolicy, SdpSensitiveEntity } from './types';

export const SDP_REDACT_MASK_BYTE = 0x2a;

export interface SdpRedactionOperation {
  readonly span: ByteSpan;
  readonly action: 'map' | 'redact';
  readonly mappingCategory: string | null;
  readonly canonicalText: string;
  readonly maskByte: number;
  /** Present for session-version ops — original session-id of the same o= line. */
  readonly sessionIdForVersion?: string;
}

export interface SdpRedactionPlan {
  readonly operations: readonly SdpRedactionOperation[];
}

export interface BuildSdpRedactionPlanOptions {
  readonly maskByte?: number;
}

const SECRET_KINDS = new Set(['ice-ufrag', 'ice-pwd', 'crypto-key']);

export function isSdpSecretEntity(entity: SdpSensitiveEntity): boolean {
  return entity.action === 'redact' || SECRET_KINDS.has(entity.kind);
}

export function buildSdpRedactionPlan(
  entities: readonly SdpSensitiveEntity[],
  options: BuildSdpRedactionPlanOptions = {},
): SdpRedactionPlan {
  const maskByte = options.maskByte ?? SDP_REDACT_MASK_BYTE;
  const operations: SdpRedactionOperation[] = [];

  for (const entity of entities) {
    if (entity.action === 'allow') continue;
    if (entity.action === 'redact' || isSdpSecretEntity(entity)) {
      operations.push({
        span: entity.span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: '',
        maskByte,
      });
      continue;
    }
    operations.push({
      span: entity.span,
      action: 'map',
      mappingCategory: entity.mappingCategory,
      canonicalText: entity.canonicalText,
      maskByte,
      ...(entity.sessionIdForVersion !== undefined
        ? { sessionIdForVersion: entity.sessionIdForVersion }
        : {}),
    });
  }

  operations.sort((a, b) => a.span.offset - b.span.offset);
  return { operations: dedupeNonOverlapping(operations) };
}

function dedupeNonOverlapping(ops: SdpRedactionOperation[]): SdpRedactionOperation[] {
  const out: SdpRedactionOperation[] = [];
  let lastEnd = -1;
  for (const op of ops) {
    const end = op.span.offset + op.span.length;
    if (op.span.offset < lastEnd) continue;
    out.push(op);
    lastEnd = end;
  }
  return out;
}

export function applySdpRedactionPlan(
  buffer: Uint8Array,
  plan: SdpRedactionPlan,
  mapFn: (category: string, canonical: string, length: number) => string = () => '',
): Uint8Array {
  const out = new Uint8Array(buffer);
  for (const op of plan.operations) {
    const { offset, length } = op.span;
    if (offset < 0 || offset + length > out.length) continue;
    const replacement = op.action === 'redact'
      ? String.fromCharCode(op.maskByte).repeat(length)
      : mapFn(op.mappingCategory ?? 'hostname', op.canonicalText, length);
    for (let i = 0; i < length; i++) {
      out[offset + i] = i < replacement.length
        ? replacement.charCodeAt(i)
        : op.maskByte;
    }
  }
  return out;
}

export function fingerprintPolicyRequiresDecision(policy: SdpRedactionPolicy): boolean {
  return policy.fingerprint === 'map' || policy.fingerprint === 'redact';
}
