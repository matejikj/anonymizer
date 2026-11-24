import { describe, it, expect } from 'vitest';
import { readPcapng } from '../../../src/pcap/capture/pcapngReader';
import { writePcapng } from '../../../src/pcap/capture/pcapngWriter';
import { validatePcapng } from '../../../src/pcap/capture/validator';
import { Endian, TimestampResolution } from '../../../src/pcap/domain/types';
import type { PacketEnvelope } from '../../../src/pcap/domain/types';

/**
 * Build a PCAPNG with metadata blocks (NRB, DSB, ISB) containing canary strings.
 * After round-trip through writer, none of the canary content should appear in output.
 */
function buildPcapngWithMetadata(): ArrayBuffer {
  const blocks: Uint8Array[] = [];

  // SHB
  const shb = new ArrayBuffer(28);
  const shbV = new DataView(shb);
  shbV.setUint32(0, 0x0a0d0d0a, true);
  shbV.setUint32(4, 28, true);
  shbV.setUint32(8, 0x1a2b3c4d, true);
  shbV.setUint16(12, 1, true);
  shbV.setUint16(14, 0, true);
  shbV.setBigInt64(16, -1n, true);
  shbV.setUint32(24, 28, true);
  blocks.push(new Uint8Array(shb));

  // IDB (minimal, 20 bytes)
  const idb = new ArrayBuffer(20);
  const idbV = new DataView(idb);
  idbV.setUint32(0, 0x00000001, true);
  idbV.setUint32(4, 20, true);
  idbV.setUint16(8, 1, true); // Ethernet
  idbV.setUint32(12, 262144, true);
  idbV.setUint32(16, 20, true);
  blocks.push(new Uint8Array(idb));

  // NRB with canary "SECRET_HOST.internal"
  const canary1 = new TextEncoder().encode('SECRET_HOST.internal');
  const nrbBodyLen = canary1.length;
  const nrbPadded = (nrbBodyLen + 3) & ~3;
  const nrbTotalLen = 12 + nrbPadded;
  const nrb = new ArrayBuffer(nrbTotalLen);
  const nrbV = new DataView(nrb);
  nrbV.setUint32(0, 0x00000004, true); // NRB
  nrbV.setUint32(4, nrbTotalLen, true);
  new Uint8Array(nrb, 8, canary1.length).set(canary1);
  nrbV.setUint32(nrbTotalLen - 4, nrbTotalLen, true);
  blocks.push(new Uint8Array(nrb));

  // DSB with canary "TLS_MASTER_SECRET_KEY_12345"
  const canary2 = new TextEncoder().encode('TLS_MASTER_SECRET_KEY_12345');
  const dsbBodyLen = canary2.length;
  const dsbPadded = (dsbBodyLen + 3) & ~3;
  const dsbTotalLen = 12 + dsbPadded;
  const dsb = new ArrayBuffer(dsbTotalLen);
  const dsbV = new DataView(dsb);
  dsbV.setUint32(0, 0x0000000a, true); // DSB
  dsbV.setUint32(4, dsbTotalLen, true);
  new Uint8Array(dsb, 8, canary2.length).set(canary2);
  dsbV.setUint32(dsbTotalLen - 4, dsbTotalLen, true);
  blocks.push(new Uint8Array(dsb));

  // ISB with canary "interface_stats_user_jakub"
  const canary3 = new TextEncoder().encode('interface_stats_user_jakub');
  const isbBodyLen = canary3.length;
  const isbPadded = (isbBodyLen + 3) & ~3;
  const isbTotalLen = 12 + isbPadded;
  const isb = new ArrayBuffer(isbTotalLen);
  const isbV = new DataView(isb);
  isbV.setUint32(0, 0x00000005, true); // ISB
  isbV.setUint32(4, isbTotalLen, true);
  new Uint8Array(isb, 8, canary3.length).set(canary3);
  isbV.setUint32(isbTotalLen - 4, isbTotalLen, true);
  blocks.push(new Uint8Array(isb));

  // One EPB
  const pktData = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
  const paddedData = 4;
  const epbLen = 32 + paddedData;
  const epb = new ArrayBuffer(epbLen);
  const epbV = new DataView(epb);
  epbV.setUint32(0, 0x00000006, true);
  epbV.setUint32(4, epbLen, true);
  epbV.setUint32(8, 0, true); // iface
  epbV.setUint32(12, 0, true); // ts high
  epbV.setUint32(16, 12345, true); // ts low
  epbV.setUint32(20, 4, true); // cap
  epbV.setUint32(24, 4, true); // orig
  new Uint8Array(epb, 28, 4).set(pktData);
  epbV.setUint32(epbLen - 4, epbLen, true);
  blocks.push(new Uint8Array(epb));

  // Concat
  let total = 0;
  for (const b of blocks) total += b.length;
  const result = new Uint8Array(total);
  let off = 0;
  for (const b of blocks) { result.set(b, off); off += b.length; }
  return result.buffer;
}

describe('Metadata canary stripping', () => {
  it('NRB, DSB, ISB content is not in output after round-trip', () => {
    const input = buildPcapngWithMetadata();

    // Parse
    const parsed = readPcapng(input);
    expect(parsed.droppedMetadataBlocks).toBe(3); // NRB + DSB + ISB
    expect(parsed.packets.length).toBe(1);

    // Write back (only structural: SHB + IDB + packets)
    const written = writePcapng({
      sections: parsed.sections,
      interfaces: parsed.interfaces,
      packets: parsed.packets,
    });

    // Validate structural correctness
    const validation = validatePcapng(written);
    expect(validation.valid).toBe(true);
    expect(validation.packetCount).toBe(1);

    // Search for canary strings in raw output bytes
    const outputBytes = new Uint8Array(written);
    const outputStr = new TextDecoder().decode(outputBytes);

    expect(outputStr).not.toContain('SECRET_HOST.internal');
    expect(outputStr).not.toContain('TLS_MASTER_SECRET_KEY_12345');
    expect(outputStr).not.toContain('interface_stats_user_jakub');
  });

  it('custom/unknown blocks are not copied to output', () => {
    const blocks: Uint8Array[] = [];

    // SHB
    const shb = new ArrayBuffer(28);
    const shbV = new DataView(shb);
    shbV.setUint32(0, 0x0a0d0d0a, true);
    shbV.setUint32(4, 28, true);
    shbV.setUint32(8, 0x1a2b3c4d, true);
    shbV.setUint16(12, 1, true); shbV.setUint16(14, 0, true);
    shbV.setBigInt64(16, -1n, true);
    shbV.setUint32(24, 28, true);
    blocks.push(new Uint8Array(shb));

    // IDB
    const idb = new ArrayBuffer(20);
    const idbV = new DataView(idb);
    idbV.setUint32(0, 0x00000001, true);
    idbV.setUint32(4, 20, true);
    idbV.setUint16(8, 1, true);
    idbV.setUint32(12, 262144, true);
    idbV.setUint32(16, 20, true);
    blocks.push(new Uint8Array(idb));

    // Custom block (type 0x00000BAD) with canary
    const canary = new TextEncoder().encode('CUSTOM_SECRET_DATA_XYZ');
    const cbPadded = (canary.length + 3) & ~3;
    const cbTotalLen = 12 + cbPadded;
    const cb = new ArrayBuffer(cbTotalLen);
    const cbV = new DataView(cb);
    cbV.setUint32(0, 0x00000bad, true);
    cbV.setUint32(4, cbTotalLen, true);
    new Uint8Array(cb, 8, canary.length).set(canary);
    cbV.setUint32(cbTotalLen - 4, cbTotalLen, true);
    blocks.push(new Uint8Array(cb));

    // EPB
    const epbLen = 32 + 4;
    const epb = new ArrayBuffer(epbLen);
    const epbV = new DataView(epb);
    epbV.setUint32(0, 0x00000006, true);
    epbV.setUint32(4, epbLen, true);
    epbV.setUint32(8, 0, true);
    epbV.setUint32(20, 4, true);
    epbV.setUint32(24, 4, true);
    new Uint8Array(epb, 28, 4).set(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]));
    epbV.setUint32(epbLen - 4, epbLen, true);
    blocks.push(new Uint8Array(epb));

    let total = 0;
    for (const b of blocks) total += b.length;
    const input = new Uint8Array(total);
    let off = 0;
    for (const b of blocks) { input.set(b, off); off += b.length; }

    const parsed = readPcapng(input.buffer);
    const written = writePcapng({ sections: parsed.sections, interfaces: parsed.interfaces, packets: parsed.packets });

    const outputStr = new TextDecoder().decode(new Uint8Array(written));
    expect(outputStr).not.toContain('CUSTOM_SECRET_DATA_XYZ');
  });
});
