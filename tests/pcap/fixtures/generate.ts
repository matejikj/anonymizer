/**
 * Synthetic PCAP fixture generator.
 * Creates test captures of various sizes without any real sensitive data.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const LINK_TYPE_ETHERNET = 1;

function writeU32LE(buf: Buffer, offset: number, val: number): void {
  buf.writeUInt32LE(val >>> 0, offset);
}

function writeU16LE(buf: Buffer, offset: number, val: number): void {
  buf.writeUInt16LE(val & 0xffff, offset);
}

/** Generate a classic PCAP with synthetic Ethernet/IPv4/UDP packets */
export function generateClassicPcap(packetCount: number, avgPayloadSize: number): Buffer {
  const globalHeader = Buffer.alloc(24);
  writeU32LE(globalHeader, 0, 0xa1b2c3d4); // magic micro LE
  writeU16LE(globalHeader, 4, 2); // version major
  writeU16LE(globalHeader, 6, 4); // version minor
  writeU32LE(globalHeader, 8, 0); // thiszone
  writeU32LE(globalHeader, 12, 0); // sigfigs
  writeU32LE(globalHeader, 16, 262144); // snaplen
  writeU32LE(globalHeader, 20, LINK_TYPE_ETHERNET); // link type

  const packets: Buffer[] = [];
  let tsSec = 1700000000; // arbitrary epoch
  let tsFrac = 0;

  for (let i = 0; i < packetCount; i++) {
    const payloadSize = avgPayloadSize + (i % 100) - 50;
    const packetSize = 14 + 20 + 8 + Math.max(payloadSize, 1); // eth + ip + udp + payload
    const packet = Buffer.alloc(packetSize);

    // Ethernet header (14 bytes)
    packet[0] = 0x00; packet[1] = 0x1a; packet[2] = 0x2b;
    packet[3] = 0x3c; packet[4] = 0x4d; packet[5] = (i & 0xff);
    packet[6] = 0x00; packet[7] = 0xaa; packet[8] = 0xbb;
    packet[9] = 0xcc; packet[10] = 0xdd; packet[11] = (i >> 8) & 0xff;
    packet.writeUInt16BE(0x0800, 12); // IPv4

    // IPv4 header (20 bytes)
    const ipOff = 14;
    packet[ipOff] = 0x45; // version + IHL
    packet[ipOff + 1] = 0x00; // DSCP
    packet.writeUInt16BE(packetSize - 14, ipOff + 2); // total length
    packet.writeUInt16BE(i & 0xffff, ipOff + 4); // identification
    packet.writeUInt16BE(0x4000, ipOff + 6); // flags DF
    packet[ipOff + 8] = 64; // TTL
    packet[ipOff + 9] = 17; // UDP
    // checksum left at 0 for fixture
    packet[ipOff + 12] = 10; packet[ipOff + 13] = 0;
    packet[ipOff + 14] = (i >> 8) & 0xff; packet[ipOff + 15] = i & 0xff;
    packet[ipOff + 16] = 192; packet[ipOff + 17] = 168;
    packet[ipOff + 18] = (i >> 8) & 0xff; packet[ipOff + 19] = i & 0xff;

    // UDP header (8 bytes)
    const udpOff = ipOff + 20;
    packet.writeUInt16BE(10000 + (i % 50000), udpOff); // src port
    packet.writeUInt16BE(5060, udpOff + 2); // dst port
    packet.writeUInt16BE(packetSize - 14 - 20, udpOff + 4); // length
    // checksum 0

    // payload: repeating bytes
    for (let j = udpOff + 8; j < packetSize; j++) {
      packet[j] = (i + j) & 0xff;
    }

    // Record header
    const recordHeader = Buffer.alloc(16);
    writeU32LE(recordHeader, 0, tsSec);
    writeU32LE(recordHeader, 4, tsFrac);
    writeU32LE(recordHeader, 8, packetSize); // incl_len
    writeU32LE(recordHeader, 12, packetSize); // orig_len

    packets.push(recordHeader, packet);

    tsFrac += 1000;
    if (tsFrac >= 1000000) {
      tsFrac = 0;
      tsSec++;
    }
  }

  return Buffer.concat([globalHeader, ...packets]);
}

/** Generate a PCAPNG file with SHB, IDB and EPBs */
export function generatePcapng(packetCount: number, avgPayloadSize: number): Buffer {
  const blocks: Buffer[] = [];

  // Section Header Block
  const shb = Buffer.alloc(28);
  writeU32LE(shb, 0, 0x0a0d0d0a); // block type
  writeU32LE(shb, 4, 28); // total length
  writeU32LE(shb, 8, 0x1a2b3c4d); // BOM
  writeU16LE(shb, 12, 1); // version major
  writeU16LE(shb, 14, 0); // version minor
  // section length = -1 (unspecified)
  shb.writeBigInt64LE(-1n, 16);
  writeU32LE(shb, 24, 28); // trailing total length
  blocks.push(shb);

  // Interface Description Block
  const idb = Buffer.alloc(20);
  writeU32LE(idb, 0, 0x00000001); // block type
  writeU32LE(idb, 4, 20); // total length
  writeU16LE(idb, 8, LINK_TYPE_ETHERNET); // link type
  writeU16LE(idb, 10, 0); // reserved
  writeU32LE(idb, 12, 262144); // snaplen
  writeU32LE(idb, 16, 20); // trailing total length
  blocks.push(idb);

  // Enhanced Packet Blocks
  let tsCounter = 0n;
  for (let i = 0; i < packetCount; i++) {
    const payloadSize = avgPayloadSize + (i % 100) - 50;
    const packetSize = 14 + 20 + 8 + Math.max(payloadSize, 1);
    const paddedPacketSize = (packetSize + 3) & ~3;
    const epbLen = 32 + paddedPacketSize + 4; // type+len+iface+ts+caplen+origlen + data + trailing

    const epb = Buffer.alloc(epbLen);
    writeU32LE(epb, 0, 0x00000006); // EPB
    writeU32LE(epb, 4, epbLen);
    writeU32LE(epb, 8, 0); // interface ID
    writeU32LE(epb, 12, Number((tsCounter >> 32n) & 0xffffffffn)); // ts high
    writeU32LE(epb, 16, Number(tsCounter & 0xffffffffn)); // ts low
    writeU32LE(epb, 20, packetSize); // captured length
    writeU32LE(epb, 24, packetSize); // original length

    // Packet data (simplified Ethernet/IP/UDP)
    const dataOff = 28;
    epb[dataOff] = 0x00; epb[dataOff+1] = 0x1a; epb[dataOff+2] = 0x2b;
    epb[dataOff+3] = 0x3c; epb[dataOff+4] = 0x4d; epb[dataOff+5] = i & 0xff;
    epb.writeUInt16BE(0x0800, dataOff + 12);
    epb[dataOff + 14] = 0x45;
    epb[dataOff + 14 + 9] = 17; // UDP

    writeU32LE(epb, epbLen - 4, epbLen); // trailing length
    blocks.push(epb);

    tsCounter += 1000n;
  }

  return Buffer.concat(blocks);
}

// CLI entry point
if (process.argv[1]?.endsWith('generate.ts')) {
  const outDir = join(import.meta.dirname ?? '.', 'generated');
  mkdirSync(outDir, { recursive: true });

  const profiles = [
    { name: 'small-100', packets: 100, payload: 200 },
    { name: 'common-100k', packets: 100_000, payload: 300 },
    { name: 'max-1M', packets: 1_000_000, payload: 100 },
    { name: 'large-250MB', packets: 500_000, payload: 450 },
  ];

  for (const p of profiles) {
    console.log(`Generating ${p.name} (${p.packets} packets, ~${p.payload}B avg payload)...`);
    const pcap = generateClassicPcap(p.packets, p.payload);
    writeFileSync(join(outDir, `${p.name}.pcap`), pcap);
    console.log(`  → ${p.name}.pcap: ${(pcap.byteLength / 1024 / 1024).toFixed(1)} MiB`);

    if (p.packets <= 100_000) {
      const pcapng = generatePcapng(p.packets, p.payload);
      writeFileSync(join(outDir, `${p.name}.pcapng`), pcapng);
      console.log(`  → ${p.name}.pcapng: ${(pcapng.byteLength / 1024 / 1024).toFixed(1)} MiB`);
    }
  }

  console.log('Done.');
}
