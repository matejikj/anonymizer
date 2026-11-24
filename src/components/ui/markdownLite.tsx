/**
 * Minimal Markdown → React renderer for the bundled "Jak anonymizujeme?" doc
 * (in-app Czech anonymization docs). Not a general-purpose Markdown engine —
 * it only understands the subset that document actually uses: headings (#/##/###),
 * paragraphs, unordered/ordered lists (with wrapped continuation lines), one GFM
 * pipe table, and inline code spans, bold, and italic emphasis. Content is our
 * own bundled source (never user input), so this builds React children
 * directly — no HTML string ever passes through `dangerouslySetInnerHTML`.
 */
import type { ReactNode } from 'react'

const COVER_DIV_RE = /^<div class="cover">\s*$/
const PAGE_BREAK_DIV_RE = /^<div style="page-break-before:\s*always"><\/div>\s*$/
const CLOSE_DIV_RE = /^<\/div>\s*$/

/** Strip the PDF-only cover wrapper + its two heading lines, and pagination divs. */
function preprocess(raw: string): string[] {
  const lines = raw.replace(/\r\n/g, '\n').split('\n')
  const out: string[] = []
  let inCover = false
  for (const line of lines) {
    if (COVER_DIV_RE.test(line)) {
      inCover = true
      continue
    }
    if (inCover) {
      if (CLOSE_DIV_RE.test(line)) inCover = false
      continue
    }
    if (PAGE_BREAK_DIV_RE.test(line)) continue
    out.push(line)
  }
  return out
}

function splitIntoChunks(lines: readonly string[]): string[][] {
  const chunks: string[][] = []
  let current: string[] = []
  for (const line of lines) {
    if (line.trim().length === 0) {
      if (current.length > 0) chunks.push(current)
      current = []
    } else {
      current.push(line)
    }
  }
  if (current.length > 0) chunks.push(current)
  return chunks
}

/** Inline `code`, **bold**, *italic* — applied to already-joined block text. */
function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const tokenRe = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g
  const parts = text.split(tokenRe).filter((p) => p.length > 0)
  return parts.map((part, i) => {
    const key = `${keyPrefix}-${i}`
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={key}>{part.slice(1, -1)}</code>
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={key}>{part.slice(2, -2)}</strong>
    }
    if (part.startsWith('*') && part.endsWith('*')) {
      return <em key={key}>{part.slice(1, -1)}</em>
    }
    return <span key={key}>{part}</span>
  })
}

function joinContinuation(lines: readonly string[]): string {
  return lines.map((l) => l.trim()).join(' ')
}

function parseTable(lines: readonly string[], key: string): ReactNode {
  const rows = lines
    .filter((l) => !/^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l))
    .map((l) => {
      const trimmed = l.trim().replace(/^\|/, '').replace(/\|$/, '')
      return trimmed.split('|').map((cell) => cell.trim())
    })
  const [header, ...body] = rows
  if (!header) return null
  return (
    <table key={key}>
      <thead>
        <tr>
          {header.map((cell, i) => (
            <th key={i}>{renderInline(cell, `${key}-h${i}`)}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {body.map((row, ri) => (
          <tr key={ri}>
            {row.map((cell, ci) => (
              <td key={ci}>{renderInline(cell, `${key}-r${ri}c${ci}`)}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function parseList(lines: readonly string[], ordered: boolean, key: string): ReactNode {
  const markerRe = ordered ? /^\d+\.\s+/ : /^-\s+/
  const items: string[][] = []
  for (const line of lines) {
    if (markerRe.test(line)) {
      items.push([line.replace(markerRe, '')])
    } else if (items.length > 0) {
      items[items.length - 1]!.push(line)
    }
  }
  const Tag = ordered ? 'ol' : 'ul'
  return (
    <Tag key={key}>
      {items.map((itemLines, i) => (
        <li key={i}>{renderInline(joinContinuation(itemLines), `${key}-i${i}`)}</li>
      ))}
    </Tag>
  )
}

export function renderMarkdownLite(raw: string): ReactNode[] {
  const lines = preprocess(raw)
  const chunks = splitIntoChunks(lines)
  const nodes: ReactNode[] = []

  chunks.forEach((chunk, idx) => {
    const key = `b${idx}`
    const first = chunk[0]!

    const headingMatch = /^(#{1,3})\s+(.*)$/.exec(first)
    if (headingMatch && chunk.length === 1) {
      const level = headingMatch[1]!.length
      const text = headingMatch[2]!
      const inline = renderInline(text, key)
      if (level === 1) nodes.push(<h3 key={key}>{inline}</h3>)
      else if (level === 2) nodes.push(<h3 key={key}>{inline}</h3>)
      else nodes.push(<h4 key={key}>{inline}</h4>)
      return
    }

    if (first.trim().startsWith('|')) {
      const table = parseTable(chunk, key)
      if (table) nodes.push(table)
      return
    }

    if (/^-\s+/.test(first)) {
      nodes.push(parseList(chunk, false, key))
      return
    }

    if (/^\d+\.\s+/.test(first)) {
      nodes.push(parseList(chunk, true, key))
      return
    }

    nodes.push(<p key={key}>{renderInline(joinContinuation(chunk), key)}</p>)
  })

  return nodes
}
