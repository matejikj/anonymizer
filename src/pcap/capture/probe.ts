/**
 * Quick format probe: identifies PCAP vs PCAPNG from the first bytes.
 */

import { CaptureFormat, PCAP_MAGIC_MICRO_LE, PCAP_MAGIC_MICRO_BE, PCAP_MAGIC_NANO_LE, PCAP_MAGIC_NANO_BE } from '../domain/types';

const BT_SHB = 0x0a0d0d0a;

export type ProbeResult =
  | { format: typeof CaptureFormat.ClassicPcap }
  | { format: typeof CaptureFormat.Pcapng }
  | { format: null; reason: string };

export function probeFormat(first8Bytes: ArrayBuffer): ProbeResult {
  if (first8Bytes.byteLength < 4) {
    return { format: null, reason: 'File too small' };
  }

  const view = new DataView(first8Bytes);
  const magic = view.getUint32(0, true);

  if (
    magic === PCAP_MAGIC_MICRO_LE ||
    magic === PCAP_MAGIC_MICRO_BE ||
    magic === PCAP_MAGIC_NANO_LE ||
    magic === PCAP_MAGIC_NANO_BE
  ) {
    return { format: CaptureFormat.ClassicPcap };
  }

  // PCAPNG SHB block type
  if (magic === BT_SHB) {
    return { format: CaptureFormat.Pcapng };
  }

  // Check BE SHB
  const magicBe = view.getUint32(0, false);
  if (magicBe === BT_SHB) {
    return { format: CaptureFormat.Pcapng };
  }

  return { format: null, reason: `Unknown magic: 0x${magic.toString(16)}` };
}
