/**
 * Anonymized PCAP export filenames (ARCHITECTURE §25).
 */

export function anonymizedPcapFileName(sourceName: string, format: 'pcap' | 'pcapng'): string {
  let base = sourceName.replace(/[/\\]+/g, '_').trim()
  // T05: inflated inputs keep logical name without .gz for export.
  if (base.toLowerCase().endsWith('.gz')) {
    base = base.slice(0, -3)
  }
  const ext = format === 'pcapng' ? '.pcapng' : '.pcap'
  if (base.toLowerCase().endsWith('.pcapng')) {
    return `${base.slice(0, -7)}.anonymized.pcapng`
  }
  if (base.toLowerCase().endsWith('.pcap')) {
    return `${base.slice(0, -5)}.anonymized.pcap`
  }
  return `${base}.anonymized${ext}`
}
