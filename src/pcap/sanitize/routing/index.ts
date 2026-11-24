/**
 * T38 — routing and first-hop redundancy sanitizers.
 */

export { IPPROTO_OSPF, sanitizeOspf } from './ospf.ts'
export { IPPROTO_EIGRP, sanitizeEigrp } from './eigrp.ts'
export { IPPROTO_PIM, sanitizePim } from './pim.ts'
export { IPPROTO_IGMP, sanitizeIgmp } from './igmp.ts'
export { RIP_UDP_PORTS, sanitizeRip } from './rip.ts'
export { BFD_UDP_PORTS, sanitizeBfd } from './bfd.ts'
export { HSRP_UDP_PORT, GLBP_UDP_PORT, sanitizeHsrpGlbp } from './hsrp.ts'
export { BGP_TCP_PORT, sanitizeBgp } from './bgp.ts'
export { sanitizeIsis } from './isis.ts'
export { LDP_PORT, sanitizeLdp } from './ldp.ts'
export { sanitizeTcpAuthOptions } from './tcpAuthOptions.ts'
