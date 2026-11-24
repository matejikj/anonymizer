/**
 * T56 — synthetic compiled schema tables (not S1AP/NGAP).
 * Proves second-schema onboarding without central dispatch / renderer changes.
 */

import type { AperSchemaModule } from './schemaTypes.ts'
import { S1AP_SCHEMA_MODULE } from './s1apSchema.ts'
import { NGAP_SCHEMA_MODULE } from './ngapSchema.ts'

/** Toy module A: procedure-like SEQUENCE with optional identity + enum status. */
export const TOY_MODULE_A: AperSchemaModule = {
  id: 'toy.aper.module-a',
  revision: 't56-1',
  root: {
    kind: 'sequence',
    extensible: false,
    fields: [
      {
        name: 'procedureCode',
        type: { kind: 'integer', lower: 0, upper: 255 },
        role: 'preserve',
      },
      {
        name: 'ueId',
        type: { kind: 'integer', lower: 0, upper: 15 },
        optional: true,
        role: 'map',
        mappingCategory: 'opaque-id',
      },
      {
        name: 'status',
        type: {
          kind: 'enumerated',
          names: ['ok', 'reject', 'ignore'],
        },
        role: 'preserve',
      },
    ],
  },
}

/** Toy module B: CHOICE + fixed OCTET STRING (second schema, same codec). */
export const TOY_MODULE_B: AperSchemaModule = {
  id: 'toy.aper.module-b',
  revision: 't56-1',
  root: {
    kind: 'choice',
    extensible: false,
    alts: [
      {
        name: 'id',
        type: { kind: 'integer', lower: 0, upper: 7 },
        role: 'map',
        mappingCategory: 'opaque-id',
      },
      {
        name: 'token',
        type: { kind: 'octet-string', sizeLower: 4, sizeUpper: 4 },
        role: 'mask',
      },
    ],
  },
}

/** Registry of compiled modules — T57/T58 append here; codec API unchanged. */
export const APER_SCHEMA_REGISTRY: ReadonlyMap<string, AperSchemaModule> = new Map([
  [TOY_MODULE_A.id, TOY_MODULE_A],
  [TOY_MODULE_B.id, TOY_MODULE_B],
  [S1AP_SCHEMA_MODULE.id, S1AP_SCHEMA_MODULE],
  [NGAP_SCHEMA_MODULE.id, NGAP_SCHEMA_MODULE],
])

export function getAperSchema(id: string): AperSchemaModule | undefined {
  return APER_SCHEMA_REGISTRY.get(id)
}
