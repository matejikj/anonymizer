/**
 * Bounded XML tokenizer with absolute source spans (latin1 code-unit = byte).
 * No DTD/entity expansion; structural errors → complete:false (caller fail-closed).
 */

export type XmlSpan = { readonly start: number; readonly end: number }

export type XmlAttr = {
  readonly rawName: string
  readonly localName: string
  readonly value: XmlSpan
}

export type XmlElement = {
  readonly kind: 'element'
  readonly rawName: string
  readonly localName: string
  readonly open: XmlSpan
  readonly close: XmlSpan | null
  readonly selfClosing: boolean
  readonly attrs: readonly XmlAttr[]
  readonly children: readonly XmlNode[]
}

export type XmlText = {
  readonly kind: 'text'
  readonly span: XmlSpan
}

export type XmlCdata = {
  readonly kind: 'cdata'
  /** Full `<![CDATA[…]]>` including markers. */
  readonly span: XmlSpan
  /** Inner character data only. */
  readonly content: XmlSpan
}

export type XmlMisc = {
  readonly kind: 'comment' | 'pi' | 'doctype'
  readonly span: XmlSpan
}

export type XmlNode = XmlElement | XmlText | XmlCdata | XmlMisc

export type BoundedXmlParse = {
  readonly roots: readonly XmlNode[]
  readonly complete: boolean
  readonly issues: readonly string[]
}

type MutableElement = {
  kind: 'element'
  rawName: string
  localName: string
  open: XmlSpan
  close: XmlSpan | null
  selfClosing: boolean
  attrs: XmlAttr[]
  children: XmlNode[]
}

const MAX_NODES = 8_192
const MAX_DEPTH = 64
const MAX_ATTRS = 64

export function localNameOf(raw: string): string {
  const i = raw.indexOf(':')
  return (i >= 0 ? raw.slice(i + 1) : raw).toLowerCase()
}

export function isXmlnsAttr(localName: string, rawName: string): boolean {
  const raw = rawName.toLowerCase()
  return localName === 'xmlns' || raw.startsWith('xmlns:')
}

export function spanText(text: string, span: XmlSpan): string {
  return text.slice(span.start, span.end)
}

export function isWhitespaceSpan(text: string, span: XmlSpan): boolean {
  for (let i = span.start; i < span.end; i++) {
    const c = text.charCodeAt(i)
    if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return false
  }
  return true
}

export function parseBoundedXml(text: string): BoundedXmlParse {
  const issues: string[] = []
  let nodeCount = 0
  let i = 0
  const n = text.length
  const roots: XmlNode[] = []
  const stack: MutableElement[] = []

  if (/<!DOCTYPE/i.test(text)) issues.push('xml-doctype')
  if (/<!ENTITY/i.test(text)) issues.push('xml-entity')

  const parentChildren = (): XmlNode[] =>
    stack.length > 0 ? stack[stack.length - 1]!.children : roots

  const bump = (): boolean => {
    nodeCount++
    return nodeCount <= MAX_NODES
  }

  const incomplete = (code: string): BoundedXmlParse => {
    issues.push(code)
    return { roots, complete: false, issues }
  }

  while (i < n) {
    if (text.charCodeAt(i) !== 0x3c /* < */) {
      const start = i
      while (i < n && text.charCodeAt(i) !== 0x3c) i++
      if (!bump()) return incomplete('xml-node-budget')
      parentChildren().push({ kind: 'text', span: { start, end: i } })
      continue
    }

    if (text.startsWith('<!--', i)) {
      const end = text.indexOf('-->', i + 4)
      if (end < 0) return incomplete('xml-unclosed-comment')
      if (!bump()) return incomplete('xml-node-budget')
      parentChildren().push({ kind: 'comment', span: { start: i, end: end + 3 } })
      i = end + 3
      continue
    }

    if (text.startsWith('<![CDATA[', i)) {
      const contentStart = i + 9
      const end = text.indexOf(']]>', contentStart)
      if (end < 0) return incomplete('xml-unclosed-cdata')
      if (!bump()) return incomplete('xml-node-budget')
      parentChildren().push({
        kind: 'cdata',
        span: { start: i, end: end + 3 },
        content: { start: contentStart, end },
      })
      i = end + 3
      continue
    }

    if (text.startsWith('<!', i)) {
      const start = i
      i += 2
      let depth = 0
      while (i < n) {
        const c = text.charCodeAt(i)
        if (c === 0x5b) depth++
        else if (c === 0x5d) depth = Math.max(0, depth - 1)
        else if (c === 0x3e && depth === 0) {
          i++
          break
        }
        i++
      }
      if (i > n || (i === n && text.charCodeAt(n - 1) !== 0x3e)) {
        return incomplete('xml-unclosed-decl')
      }
      if (!bump()) return incomplete('xml-node-budget')
      parentChildren().push({ kind: 'doctype', span: { start, end: i } })
      continue
    }

    if (text.startsWith('<?', i)) {
      const end = text.indexOf('?>', i + 2)
      if (end < 0) return incomplete('xml-unclosed-pi')
      if (!bump()) return incomplete('xml-node-budget')
      parentChildren().push({ kind: 'pi', span: { start: i, end: end + 2 } })
      i = end + 2
      continue
    }

    if (text.startsWith('</', i)) {
      const start = i
      i += 2
      const nameStart = i
      while (i < n && isNameChar(text.charCodeAt(i))) i++
      if (i === nameStart) return incomplete('xml-bad-end-tag')
      const rawName = text.slice(nameStart, i)
      while (i < n && isSpace(text.charCodeAt(i))) i++
      if (i >= n || text.charCodeAt(i) !== 0x3e) return incomplete('xml-bad-end-tag')
      i++
      const el = stack.pop()
      if (!el) return incomplete('xml-unmatched-end')
      if (el.localName !== localNameOf(rawName)) return incomplete('xml-tag-mismatch')
      el.close = { start, end: i }
      continue
    }

    // Start tag
    if (stack.length >= MAX_DEPTH) return incomplete('xml-depth-budget')
    const openStart = i
    i++
    const nameStart = i
    while (i < n && isNameChar(text.charCodeAt(i))) i++
    if (i === nameStart) return incomplete('xml-bad-start-tag')
    const rawName = text.slice(nameStart, i)
    const attrs: XmlAttr[] = []
    let selfClosing = false

    while (i < n) {
      while (i < n && isSpace(text.charCodeAt(i))) i++
      if (i >= n) return incomplete('xml-unclosed-start')
      if (text.charCodeAt(i) === 0x3e) {
        i++
        break
      }
      if (text.charCodeAt(i) === 0x2f && i + 1 < n && text.charCodeAt(i + 1) === 0x3e) {
        selfClosing = true
        i += 2
        break
      }
      if (attrs.length >= MAX_ATTRS) return incomplete('xml-attr-budget')
      const attrNameStart = i
      while (i < n && isNameChar(text.charCodeAt(i))) i++
      if (i === attrNameStart) return incomplete('xml-bad-attr')
      const attrRaw = text.slice(attrNameStart, i)
      while (i < n && isSpace(text.charCodeAt(i))) i++
      if (i >= n || text.charCodeAt(i) !== 0x3d) return incomplete('xml-bad-attr')
      i++
      while (i < n && isSpace(text.charCodeAt(i))) i++
      if (i >= n) return incomplete('xml-bad-attr')
      const quote = text.charCodeAt(i)
      if (quote !== 0x22 && quote !== 0x27) return incomplete('xml-bad-attr')
      i++
      const valueStart = i
      while (i < n && text.charCodeAt(i) !== quote) i++
      if (i >= n) return incomplete('xml-unclosed-attr')
      const valueEnd = i
      i++
      attrs.push({
        rawName: attrRaw,
        localName: localNameOf(attrRaw),
        value: { start: valueStart, end: valueEnd },
      })
    }

    if (!bump()) return incomplete('xml-node-budget')
    const el: MutableElement = {
      kind: 'element',
      rawName,
      localName: localNameOf(rawName),
      open: { start: openStart, end: i },
      close: null,
      selfClosing,
      attrs,
      children: [],
    }
    parentChildren().push(el)
    if (!selfClosing) stack.push(el)
  }

  if (stack.length > 0) return incomplete('xml-unclosed-element')

  // DOCTYPE/ENTITY are issues but parse of the forest can still be structurally complete;
  // callers treat those as XXE fail-closed separately.
  const structuralOk = !issues.some(
    (x) =>
      x !== 'xml-doctype'
      && x !== 'xml-entity',
  )
  return { roots, complete: structuralOk, issues }
}

function isSpace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d
}

function isNameChar(c: number): boolean {
  return (
    (c >= 0x41 && c <= 0x5a)
    || (c >= 0x61 && c <= 0x7a)
    || (c >= 0x30 && c <= 0x39)
    || c === 0x5f
    || c === 0x2d
    || c === 0x2e
    || c === 0x3a
  )
}
