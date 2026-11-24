/**
 * T31 — static validation of wire-protocol descriptors (coverage, categories, preserve rules).
 */

import { ENTITY_CATEGORIES } from '../../anonymization/entityRegistry.ts'
import type { IdentityCategory } from '../../../mapping/identityCategories.ts'
import type {
  DescriptorField,
  DescriptorMessageVariant,
  WireProtocolDescriptor,
} from './types.ts'
import { DESCRIPTOR_SCHEMA_VERSION } from './types.ts'

export type DescriptorValidationIssue = {
  readonly code:
    | 'schema-version'
    | 'empty-id'
    | 'magic-mismatch-header'
    | 'gap'
    | 'overlap'
    | 'out-of-header'
    | 'preserve-without-reason'
    | 'unknown-category'
    | 'empty-variants'
    | 'bad-length'
  readonly path: string
  readonly detail: string
}

export type DescriptorValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly issues: readonly DescriptorValidationIssue[] }

const CATEGORY_SET = new Set<string>(ENTITY_CATEGORIES as readonly string[])
// radioId lives in IdentityCategory / SessionMapping but is not always mirrored in ENTITY_CATEGORIES PCAP list.
CATEGORY_SET.add('radioId')
CATEGORY_SET.add('opaque-id')
CATEGORY_SET.add('ipv4')
CATEGORY_SET.add('ipv6')
CATEGORY_SET.add('mac')
CATEGORY_SET.add('hostname')
CATEGORY_SET.add('port')

function issue(
  code: DescriptorValidationIssue['code'],
  path: string,
  detail: string,
): DescriptorValidationIssue {
  return { code, path, detail }
}

function validateFieldCoverage(
  fields: readonly DescriptorField[],
  coverThrough: number,
  path: string,
  issues: DescriptorValidationIssue[],
): void {
  const sorted = [...fields].sort((a, b) => a.offset - b.offset)
  let cursor = 0
  for (const f of sorted) {
    if (f.length <= 0) {
      issues.push(issue('bad-length', `${path}.${f.name}`, 'length must be > 0'))
      continue
    }
    if (f.offset < 0 || f.offset + f.length > coverThrough) {
      issues.push(
        issue(
          'out-of-header',
          `${path}.${f.name}`,
          `span [${f.offset},${f.offset + f.length}) outside 0..${coverThrough}`,
        ),
      )
    }
    if (f.offset < cursor) {
      issues.push(
        issue('overlap', `${path}.${f.name}`, `overlaps previous field ending at ${cursor}`),
      )
    } else if (f.offset > cursor) {
      issues.push(
        issue('gap', `${path}.${f.name}`, `uncovered bytes [${cursor},${f.offset})`),
      )
    }
    cursor = Math.max(cursor, f.offset + f.length)

    if (f.disposition.kind === 'preserve') {
      if (!f.disposition.reason.trim()) {
        issues.push(
          issue('preserve-without-reason', `${path}.${f.name}`, 'preserve requires non-empty reason'),
        )
      }
    }
    if (f.disposition.kind === 'map') {
      const cat = f.disposition.category as string
      if (!CATEGORY_SET.has(cat)) {
        issues.push(
          issue('unknown-category', `${path}.${f.name}`, `unknown identity category ${cat}`),
        )
      }
      // String-shaped wire formats must not use preserve-by-accident via map of free text —
      // map is fine; preserve of ascii without allowlist is rejected above via reason rule.
      void (f.disposition.format as DescriptorWireFormatCheck)
    }
  }
  if (cursor < coverThrough) {
    issues.push(
      issue('gap', path, `uncovered trailing header bytes [${cursor},${coverThrough})`),
    )
  }
}

type DescriptorWireFormatCheck = string

function validateVariant(
  variant: DescriptorMessageVariant,
  headerLength: number,
  path: string,
  issues: DescriptorValidationIssue[],
): void {
  if (variant.trailing?.kind === 'preserve' && !variant.trailing.reason.trim()) {
    issues.push(
      issue('preserve-without-reason', `${path}.trailing`, 'preserve trailing requires reason'),
    )
  }
  validateFieldCoverage(variant.fields, headerLength, path, issues)
}

/**
 * Validate a descriptor. Fail-closed: gaps, overlaps, preserve-without-reason, bad categories.
 */
export function validateWireProtocolDescriptor(
  desc: WireProtocolDescriptor,
): DescriptorValidationResult {
  const issues: DescriptorValidationIssue[] = []
  if (desc.schemaVersion !== DESCRIPTOR_SCHEMA_VERSION) {
    issues.push(issue('schema-version', 'schemaVersion', `expected ${DESCRIPTOR_SCHEMA_VERSION}`))
  }
  if (!desc.id.trim()) {
    issues.push(issue('empty-id', 'id', 'id required'))
  }
  if (desc.framing.magic.length === 0) {
    issues.push(issue('magic-mismatch-header', 'framing.magic', 'magic required'))
  }
  if (desc.framing.magic.length > desc.framing.headerLength) {
    issues.push(
      issue(
        'magic-mismatch-header',
        'framing',
        'magic longer than headerLength',
      ),
    )
  }
  if (desc.variants.length === 0) {
    issues.push(issue('empty-variants', 'variants', 'at least one variant required'))
  }

  for (let i = 0; i < desc.variants.length; i++) {
    validateVariant(desc.variants[i]!, desc.framing.headerLength, `variants[${i}]`, issues)
  }
  validateFieldCoverage(
    desc.unknownVariant.headerFields,
    desc.framing.headerLength,
    'unknownVariant',
    issues,
  )

  // Reject preserve on free-form ascii fields without reason (already covered) —
  // additionally reject preserve on name containing "password"/"secret"/"psk".
  for (const variant of desc.variants) {
    for (const f of variant.fields) {
      if (
        f.disposition.kind === 'preserve'
        && /password|secret|psk|token|auth/i.test(f.name)
      ) {
        issues.push(
          issue(
            'preserve-without-reason',
            f.name,
            'sensitive-looking field name cannot use preserve',
          ),
        )
      }
    }
  }

  return issues.length === 0 ? { ok: true } : { ok: false, issues }
}

/** Type-level helper — IdentityCategory used by map dispositions must stay assignable. */
export type MappedCategory = IdentityCategory
