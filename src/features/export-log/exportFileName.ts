/**
 * Export download filenames (ARCHITECTURE §3.5).
 */

export function anonymizedDownloadName(fileName: string | null, now = new Date()): string {
  if (fileName && fileName.trim()) {
    const base = fileName.replace(/[/\\]+/g, '_').trim()
    if (base.toLowerCase().endsWith('.log')) {
      return `${base.slice(0, -4)}.anonymized.log`
    }
    if (base.toLowerCase().endsWith('.txt')) {
      return `${base.slice(0, -4)}.anonymized.log`
    }
    return `${base}.anonymized.log`
  }
  const y = now.getFullYear()
  const m = String(now.getMonth() + 1).padStart(2, '0')
  const d = String(now.getDate()).padStart(2, '0')
  const hh = String(now.getHours()).padStart(2, '0')
  const mm = String(now.getMinutes()).padStart(2, '0')
  const ss = String(now.getSeconds()).padStart(2, '0')
  return `rnd-log-anonymizer-anonymized-${y}${m}${d}-${hh}${mm}${ss}.log`
}
