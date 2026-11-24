/**
 * Protocol module interface, decode context and decoded node types.
 */

export interface DecodeContext {
  /** Remaining recursion budget (decremented for tunnels) */
  readonly depthBudget: number;
  /** Offset from start of packet data for absolute byte ranges */
  readonly baseOffset: number;
  /** Link type or EtherType hint from parent layer */
  readonly hint: number;
}

export interface ByteRange {
  readonly start: number;
  readonly end: number;
}

export interface DecodedField {
  readonly name: string;
  readonly range: ByteRange;
  readonly value: string | number | bigint | Uint8Array;
  readonly display?: string;
}

export interface DecodedNode {
  readonly protocolId: string;
  readonly range: ByteRange;
  readonly fields: readonly DecodedField[];
  readonly children: readonly DecodedNode[];
  readonly issues: readonly string[];
}

export interface EntityCollector {
  addIpv4(addr: Uint8Array, packetNumber: number): void;
  addIpv6(addr: Uint8Array, packetNumber: number): void;
  addMac(addr: Uint8Array, packetNumber: number): void;
  addHostname(name: string, packetNumber: number): void;
  addPort(port: number, protocol: 'tcp' | 'udp' | 'sctp', packetNumber: number): void;
  addVlan(id: number, packetNumber: number): void;
}

export interface ProtocolModule {
  readonly id: string;
  probe(data: Uint8Array, ctx: DecodeContext): boolean;
  decode(data: Uint8Array, ctx: DecodeContext): DecodedNode;
  collect(node: DecodedNode, out: EntityCollector, packetNumber: number): void;
}

export const MAX_DECODE_DEPTH = 4;

/** Well-known EtherTypes */
export const ETHERTYPE_IPV4 = 0x0800;
export const ETHERTYPE_IPV6 = 0x86dd;
export const ETHERTYPE_ARP = 0x0806;
export const ETHERTYPE_VLAN = 0x8100;
export const ETHERTYPE_QINQ = 0x88a8;

/** IP protocol numbers */
export const IPPROTO_TCP = 6;
export const IPPROTO_UDP = 17;
export const IPPROTO_SCTP = 132;
export const IPPROTO_ICMP = 1;
export const IPPROTO_ICMPV6 = 58;
export const IPPROTO_IPV4 = 4;
export const IPPROTO_IPV6 = 41;
export const IPPROTO_GRE = 47;

/** IPv6 extension header next-header values */
export const IPV6_EXT_HOP = 0;
export const IPV6_EXT_ROUTING = 43;
export const IPV6_EXT_FRAGMENT = 44;
export const IPV6_EXT_DEST = 60;
export const IPV6_EXT_AUTH = 51;
export const IPV6_EXT_NONE = 59;

/** PCAP link types */
export const LINKTYPE_NULL = 0;
export const LINKTYPE_ETHERNET = 1;
export const LINKTYPE_PPP = 9;
export const LINKTYPE_PPP_HDLC = 50;
export const LINKTYPE_C_HDLC = 104;
export const LINKTYPE_LOOP = 108;
export const LINKTYPE_RAW_IPV4 = 228;
export const LINKTYPE_RAW_IPV6 = 229;
export const LINKTYPE_LINUX_SLL = 113;
export const LINKTYPE_LINUX_SLL2 = 276;
export const LINKTYPE_NFLOG = 239;
/** T40 — IEEE 802.11 (+ radiotap / Bluetooth / BLE). */
export const LINKTYPE_IEEE802_11 = 105;
export const LINKTYPE_IEEE802_11_RADIO = 127;
export const LINKTYPE_PPI = 192;
export const LINKTYPE_BLUETOOTH_HCI_H4 = 201;
export const LINKTYPE_BLUETOOTH_LE_LL = 251;
export const LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254;
export const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256;
