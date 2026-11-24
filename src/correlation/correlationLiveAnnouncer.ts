/**
 * Throttled ARIA live announcements for correlation workspace (Stage 31).
 */

let lastAnnounceAt = 0
let pending: string | null = null
let timer: ReturnType<typeof setTimeout> | null = null
let liveText = ''

const THROTTLE_MS = 400

function flush(): void {
  timer = null
  if (pending == null) return
  liveText = pending
  pending = null
  lastAnnounceAt = Date.now()
  if (typeof document !== 'undefined') {
    const el = document.getElementById('corr-source-live')
    if (el) el.textContent = liveText
  }
}

export function announceCorrelationSource(message: string): void {
  const now = Date.now()
  pending = message
  if (now - lastAnnounceAt >= THROTTLE_MS) {
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
    flush()
    return
  }
  if (timer) return
  timer = setTimeout(flush, THROTTLE_MS - (now - lastAnnounceAt))
}

export function getCorrelationSourceLiveText(): string {
  return liveText
}

export function resetCorrelationLiveAnnouncerForTests(): void {
  lastAnnounceAt = 0
  pending = null
  liveText = ''
  if (timer) {
    clearTimeout(timer)
    timer = null
  }
}
