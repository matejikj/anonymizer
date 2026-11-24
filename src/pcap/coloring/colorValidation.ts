/**
 * sRGB color validation and WCAG AA contrast helpers for coloring rules.
 */

import type { PcapColorPair } from './types'

const SRGB_HEX = /^#([0-9a-f]{6}|[0-9a-f]{3})$/i

export function isValidSrgbColor(value: string): boolean {
  if (!SRGB_HEX.test(value.trim())) return false
  return true
}

export function normalizeSrgbColor(value: string): string | null {
  const trimmed = value.trim()
  if (!SRGB_HEX.test(trimmed)) return null
  if (trimmed.length === 4) {
    const [, r, g, b] = trimmed
    return `#${r}${r}${g}${g}${b}${b}`.toLowerCase()
  }
  return trimmed.toLowerCase()
}

function channelToLinear(c: number): number {
  const s = c / 255
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
}

export function relativeLuminance(hex: string): number {
  const norm = normalizeSrgbColor(hex)
  if (!norm) return 0
  const r = parseInt(norm.slice(1, 3), 16)
  const g = parseInt(norm.slice(3, 5), 16)
  const b = parseInt(norm.slice(5, 7), 16)
  return 0.2126 * channelToLinear(r) + 0.7152 * channelToLinear(g) + 0.0722 * channelToLinear(b)
}

export function contrastRatio(foreground: string, background: string): number {
  const l1 = relativeLuminance(foreground)
  const l2 = relativeLuminance(background)
  const lighter = Math.max(l1, l2)
  const darker = Math.min(l1, l2)
  return (lighter + 0.05) / (darker + 0.05)
}

export function meetsWcagAa(foreground: string, background: string, minRatio = 4.5): boolean {
  return contrastRatio(foreground, background) >= minRatio
}

export function validateColorPair(pair: PcapColorPair): string | null {
  if (!isValidSrgbColor(pair.foreground)) return 'invalid-foreground'
  if (!isValidSrgbColor(pair.background)) return 'invalid-background'
  if (!meetsWcagAa(pair.foreground, pair.background)) return 'low-contrast'
  return null
}

/** Adjust foreground toward black/white until WCAG AA is met. */
export function correctForegroundForContrast(
  foreground: string,
  background: string,
  minRatio = 4.5,
): string {
  const bg = normalizeSrgbColor(background)
  const fg = normalizeSrgbColor(foreground)
  if (!bg || !fg) return foreground
  if (meetsWcagAa(fg, bg, minRatio)) return fg

  const bgLum = relativeLuminance(bg)
  const target = bgLum > 0.5 ? '#000000' : '#ffffff'
  if (meetsWcagAa(target, bg, minRatio)) return target

  let best = target
  let bestRatio = contrastRatio(target, bg)
  for (let step = 0; step <= 255; step += 8) {
    const candidate = bgLum > 0.5 ? shadeHex(fg, step) : tintHex(fg, step)
    const ratio = contrastRatio(candidate, bg)
    if (ratio >= minRatio) return candidate
    if (ratio > bestRatio) {
      best = candidate
      bestRatio = ratio
    }
  }
  return best
}

function shadeHex(hex: string, amount: number): string {
  const norm = normalizeSrgbColor(hex)!
  const r = Math.max(0, parseInt(norm.slice(1, 3), 16) - amount)
  const g = Math.max(0, parseInt(norm.slice(3, 5), 16) - amount)
  const b = Math.max(0, parseInt(norm.slice(5, 7), 16) - amount)
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`
}

function tintHex(hex: string, amount: number): string {
  const norm = normalizeSrgbColor(hex)!
  const r = Math.min(255, parseInt(norm.slice(1, 3), 16) + amount)
  const g = Math.min(255, parseInt(norm.slice(3, 5), 16) + amount)
  const b = Math.min(255, parseInt(norm.slice(5, 7), 16) + amount)
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`
}

function toHex(n: number): string {
  return n.toString(16).padStart(2, '0')
}

export function sanitizeColorPair(pair: PcapColorPair): PcapColorPair {
  const foreground = normalizeSrgbColor(pair.foreground) ?? '#111111'
  const background = normalizeSrgbColor(pair.background) ?? '#f5f5f5'
  return {
    foreground: correctForegroundForContrast(foreground, background),
    background,
  }
}
