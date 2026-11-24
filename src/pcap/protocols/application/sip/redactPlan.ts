/**
 * Build a length-preserving redaction plan from extracted SIP entities (step 4).
 */

import type { SipRedactionOperation, SipRedactionPlan, SipSensitiveEntity } from './entities';
import { isCredentialEntity } from './extract';

/** Default mask byte for credential / opaque redaction (`*`). */
export const SIP_REDACT_MASK_BYTE = 0x2a;

export interface BuildRedactionPlanOptions {
  readonly maskByte?: number;
}

/**
 * Convert extracted entities into non-overlapping redaction operations.
 * Credential entities are always redacted — never mapped.
 */
export function buildSipRedactionPlan(
  entities: readonly SipSensitiveEntity[],
  options: BuildRedactionPlanOptions = {},
): SipRedactionPlan {
  const maskByte = options.maskByte ?? SIP_REDACT_MASK_BYTE;
  const operations: SipRedactionOperation[] = [];

  for (const entity of entities) {
    if (entity.action === 'allow') continue;

    if (isCredentialEntity(entity) || entity.action === 'redact') {
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
    });
  }

  operations.sort((a, b) => a.span.offset - b.span.offset);
  return { operations: dedupeNonOverlapping(operations) };
}

function dedupeNonOverlapping(ops: SipRedactionOperation[]): SipRedactionOperation[] {
  const out: SipRedactionOperation[] = [];
  let lastEnd = -1;
  for (const op of ops) {
    const end = op.span.offset + op.span.length;
    if (op.span.offset < lastEnd) continue;
    out.push(op);
    lastEnd = end;
  }
  return out;
}

/** Apply a redaction plan to a copy of the buffer (for tests / preview). */
export function applySipRedactionPlan(
  buffer: Uint8Array,
  plan: SipRedactionPlan,
  mapFn: (category: string, canonical: string, length: number) => string = () => '',
): Uint8Array {
  const out = new Uint8Array(buffer);
  for (const op of plan.operations) {
    const { offset, length } = op.span;
    if (offset < 0 || offset + length > out.length) continue;

    let replacement: string;
    if (op.action === 'redact') {
      replacement = String.fromCharCode(op.maskByte).repeat(length);
    } else {
      replacement = mapFn(op.mappingCategory ?? 'hostname', op.canonicalText, length);
    }

    for (let i = 0; i < length; i++) {
      out[offset + i] = i < replacement.length
        ? replacement.charCodeAt(i)
        : op.maskByte;
    }
  }
  return out;
}

/** True when no credential canonical text would enter a mapping snapshot. */
export function planExcludesCredentialsFromMapping(plan: SipRedactionPlan): boolean {
  return plan.operations.every((op) => op.action !== 'map' || op.canonicalText.length > 0);
}

export function collectDelimiterBytes(buffer: Uint8Array, span: { offset: number; length: number }): number[] {
  const delimiters = new Set([0x40, 0x3a, 0x3b, 0x3c, 0x3e, 0x22, 0x2c, 0x2f]);
  const positions: number[] = [];
  for (let i = span.offset; i < span.offset + span.length; i++) {
    if (delimiters.has(buffer[i]!)) positions.push(i);
  }
  return positions;
}

/** Verify delimiter bytes outside entity spans remain unchanged after redaction. */
export function delimitersPreserved(
  original: Uint8Array,
  redacted: Uint8Array,
  messageSpan: { offset: number; length: number },
  entitySpans: readonly { offset: number; length: number }[],
): boolean {
  const entityRanges = entitySpans.map((s) => [s.offset, s.offset + s.length] as const);

  for (let i = messageSpan.offset; i < messageSpan.offset + messageSpan.length; i++) {
    const insideEntity = entityRanges.some(([start, end]) => i >= start && i < end);
    if (insideEntity) continue;
    if (original[i] !== redacted[i]) return false;
  }
  return true;
}
