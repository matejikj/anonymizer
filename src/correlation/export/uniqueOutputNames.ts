/**
 * Allocate unique output file names for a correlation export (no silent overwrite).
 */

export function allocateUniqueOutputNames(
  items: readonly { readonly sourceId: string; readonly outputFileName: string }[],
): ReadonlyMap<string, string> {
  const used = new Set<string>()
  const out = new Map<string, string>()
  for (const item of items) {
    let name = item.outputFileName
    if (!used.has(name)) {
      used.add(name)
      out.set(item.sourceId, name)
      continue
    }
    const dot = name.lastIndexOf('.')
    const base = dot > 0 ? name.slice(0, dot) : name
    const ext = dot > 0 ? name.slice(dot) : ''
    let n = 2
    while (used.has(`${base}-${n}${ext}`)) n += 1
    name = `${base}-${n}${ext}`
    used.add(name)
    out.set(item.sourceId, name)
  }
  return out
}
