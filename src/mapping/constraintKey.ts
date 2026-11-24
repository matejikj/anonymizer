import type { WireRepresentationConstraint } from './types';

export function constraintKey(c: WireRepresentationConstraint): string {
  switch (c.kind) {
    case 'ipv4-wire':
    case 'ipv6-wire':
    case 'mac-wire':
    case 'vlan-wire':
    case 'timestamp-wire':
      return c.kind;
    case 'hostname-ascii':
      return `hostname:${c.labelCount}:${c.maxLabelLength}`;
    case 'port-wire':
      return `port:${c.protocol}`;
    case 'radio-id-wire':
      return `radio:${c.bitWidth}`;
    case 'ssrc-wire':
      return c.kind;
    case 'text-ascii':
      return `text:${c.byteLength}`;
  }
}
