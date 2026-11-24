/**
 * Registers all protocol modules. Call once before decoding.
 */

import { registerLinkModule, registerEtherTypeModule, registerIpProtoModule, registerUdpPortModule } from './registry';
import {
  LINKTYPE_ETHERNET, LINKTYPE_RAW_IPV4, LINKTYPE_RAW_IPV6, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
  LINKTYPE_NULL, LINKTYPE_LOOP,
  ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP,
  IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV4, IPPROTO_IPV6, IPPROTO_GRE,
} from './types';
import { ethernetModule } from './link/ethernet';
import { sllModule, sll2Module } from './link/sll';
import { rawIpv4Module, rawIpv6Module } from './link/rawip';
import { nullLinkModule, loopLinkModule } from './link/nullLoop';
import { arpModule } from './network/arp';
import { ipv4Module } from './network/ipv4';
import { ipv6Module } from './network/ipv6';
import { ipInIpModule, ipv6InIpModule, greModule } from './network/tunnel';
import { vxlanModule, VXLAN_UDP_PORT } from './network/vxlan';
import { tcpModule } from './transport/tcp';
import { udpModule } from './transport/udp';
import { sctpModule } from './transport/sctp';
import { icmpv4Module, icmpv6Module } from './transport/icmp';

let initialized = false;

export function initProtocols(): void {
  if (initialized) return;
  initialized = true;

  // Link types
  registerLinkModule(LINKTYPE_ETHERNET, ethernetModule);
  registerLinkModule(LINKTYPE_LINUX_SLL, sllModule);
  registerLinkModule(LINKTYPE_LINUX_SLL2, sll2Module);
  registerLinkModule(LINKTYPE_RAW_IPV4, rawIpv4Module);
  registerLinkModule(LINKTYPE_RAW_IPV6, rawIpv6Module);
  registerLinkModule(LINKTYPE_NULL, nullLinkModule);
  registerLinkModule(LINKTYPE_LOOP, loopLinkModule);

  // EtherTypes → network modules
  registerEtherTypeModule(ETHERTYPE_IPV4, ipv4Module);
  registerEtherTypeModule(ETHERTYPE_IPV6, ipv6Module);
  registerEtherTypeModule(ETHERTYPE_ARP, arpModule);

  // IP protocols → transport modules
  registerIpProtoModule(IPPROTO_TCP, tcpModule);
  registerIpProtoModule(IPPROTO_UDP, udpModule);
  registerIpProtoModule(IPPROTO_SCTP, sctpModule);
  registerIpProtoModule(IPPROTO_ICMP, icmpv4Module);
  registerIpProtoModule(IPPROTO_ICMPV6, icmpv6Module);

  // IP protocols → tunnel modules (IP-in-IP, IPv6-in-IP, GRE)
  registerIpProtoModule(IPPROTO_IPV4, ipInIpModule);
  registerIpProtoModule(IPPROTO_IPV6, ipv6InIpModule);
  registerIpProtoModule(IPPROTO_GRE, greModule);

  // UDP destination port → application-layer tunnels
  registerUdpPortModule(VXLAN_UDP_PORT, vxlanModule);
}
