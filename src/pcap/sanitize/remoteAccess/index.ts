/**
 * T39 — remote access and out-of-band management sanitizers.
 */

export {
  RDP_TCP_PORT,
  RDP_UDP_PORT,
  isRdpPortHint,
  looksLikeRdp,
  sanitizeRdp,
} from './rdp.ts'
export {
  VNC_PORT_MIN,
  VNC_PORT_MAX,
  isVncPortHint,
  looksLikeVnc,
  sanitizeVnc,
} from './vnc.ts'
export {
  X11_PORT_MIN,
  X11_PORT_MAX,
  isX11PortHint,
  looksLikeX11Setup,
  sanitizeX11,
} from './x11.ts'
export {
  IPMI_UDP_PORT,
  isIpmiPortHint,
  looksLikeRmcp,
  sanitizeIpmi,
} from './ipmi.ts'
export {
  CITRIX_ICA_PORT,
  CITRIX_CGP_PORT,
  isCitrixPortHint,
  sanitizeCitrix,
} from './citrix.ts'
export {
  AMT_PORTS,
  isAmtPortHint,
  sanitizeAmtHttp,
} from './amt.ts'
