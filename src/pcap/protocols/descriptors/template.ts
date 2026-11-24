/**
 * T31 — copy-paste template for a new proprietary descriptor (fill every TODO).
 * Never load descriptors from user uploads; only modules in this directory ship.
 */

import type { WireProtocolDescriptor } from './types.ts'
import { DESCRIPTOR_SCHEMA_VERSION } from './types.ts'

/**
 * Skeleton matching the validator’s coverage rules. Replace magic, ports, fields,
 * and variants before registering in `registry.ts`.
 */
export const DESCRIPTOR_TEMPLATE: WireProtocolDescriptor = {
  schemaVersion: DESCRIPTOR_SCHEMA_VERSION,
  id: 'vendor-protocol-template',
  title: 'TODO: vendor / dialect title',
  profileVersion: '0.0.0-template',
  specRefs: [
    'docs/PROPRIETARY_PROTOCOL_ONBOARDING.md',
    // TODO: pin RFC / vendor PDF revision + licence note
  ],
  transport: {
    udpPorts: [0], // TODO: confirmed ports only — never wide ephemeral ranges
  },
  framing: {
    kind: 'fixed-magic',
    endian: 'be',
    magic: [0x00, 0x00, 0x00, 0x00], // TODO
    headerLength: 8, // TODO: must equal covered field span
  },
  variants: [
    {
      when: { fieldOffset: 4, fieldLength: 1, equals: 1 },
      fields: [
        {
          name: 'magic',
          offset: 0,
          length: 4,
          disposition: { kind: 'preserve', reason: 'TODO: framing magic' },
        },
        {
          name: 'msgType',
          offset: 4,
          length: 1,
          disposition: { kind: 'preserve', reason: 'TODO: discriminator' },
        },
        {
          name: 'subscriberId',
          offset: 5,
          length: 3,
          disposition: { kind: 'map', category: 'radioId', format: 'u24' },
        },
      ],
      trailing: { kind: 'mask' },
    },
  ],
  unknownVariant: {
    headerFields: [
      {
        name: 'magic',
        offset: 0,
        length: 4,
        disposition: { kind: 'preserve', reason: 'framing magic' },
      },
      {
        name: 'msgType',
        offset: 4,
        length: 1,
        disposition: { kind: 'preserve', reason: 'discriminator' },
      },
      {
        name: 'rest',
        offset: 5,
        length: 3,
        disposition: { kind: 'mask' },
      },
    ],
    trailing: { kind: 'mask' },
  },
}
