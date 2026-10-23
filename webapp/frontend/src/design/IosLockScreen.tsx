import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { AppIcon, Glyph } from './IosIcons'
import { dateText, timeText } from './iosDevice'
import { rubberBand } from './iosGestures'
import { NoteList, type Note } from './IosNotifications'
import { useIosModal } from './useIosModal'

/** How long the screen takes to slide away when unlocked (matches themes.css), and how long after locking keys are ignored. */
const UNLOCK_MS = 380
const ARM_MS = 250
const MODIFIERS = new Set(['Tab', 'Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'Escape'])

interface IosLockScreenProps {
  now: Date
  notes: Note[]
  busySince: number | null
  action: string
  /** Animation is at Wild, so the screen slides away rather than vanishing. */
  wild: boolean
  torch: boolean
  onTorch: () => void
  onCamera: () => void
  onUnlock: () => void
  onOpenNote: (n: Note) => void
}

/**
 * The lock screen: the date over a large rounded clock, a request still running as a Live Activity,
 * the notifications that came in, and the flashlight and camera buttons. Swipe up (or drag up with
 * the pointer) to open: it follows the finger, resists being pulled down, and opens past a quarter of
 * the way or on a flick. Any key, or the Open button, opens it too.
 */
export function IosLockScreen({ now, notes, busySince, action, wild, torch, onTorch, onCamera, onUnlock, onOpenNote }: IosLockScreenProps) {
  const ref = useRef<HTMLDivElement>(null)
  const drag = useRef<{ y: number; t: number } | null>(null)
  const [dy, setDy] = useState(0)
  const [leaving, setLeaving] = useState(false)
  // The Live Activity counts seconds; the clock above only minutes.
  const [tick, setTick] = useState(() => Date.now())
  useEffect(() => {
    if (busySince === null) return
    const id = window.setInterval(() => setTick(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [busySince])
  const pending = useRef<Note | null>(null)
  useIosModal(ref, () => {})

  const open = (note?: Note) => {
    if (leaving) return
    pending.current = note ?? null
    setLeaving(true)
    window.setTimeout(() => {
      onUnlock()
      if (pending.current) onOpenNote(pending.current)
    }, wild ? UNLOCK_MS : 0)
  }
  const openRef = useRef(open)
  useEffect(() => {
    openRef.current = open
  })

  // Any key opens it, but not the one that locked it, and not keys that only move focus.
  useEffect(() => {
    let armed = false
    const arm = window.setTimeout(() => {
      armed = true
    }, ARM_MS)
    const onKey = (e: KeyboardEvent) => {
      if (!armed || MODIFIERS.has(e.key)) return
      if ((e.key === 'Enter' || e.key === ' ') && (e.target as Element | null)?.closest?.('button')) return
      e.preventDefault()
      openRef.current()
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.clearTimeout(arm)
      window.removeEventListener('keydown', onKey)
    }
  }, [])

  const onDown = (e: ReactPointerEvent) => {
    if (e.button !== 0 || (e.target as Element).closest('button')) return
    e.currentTarget.setPointerCapture?.(e.pointerId)
    drag.current = { y: e.clientY, t: performance.now() }
  }
  const onMove = (e: ReactPointerEvent) => {
    if (!drag.current) return
    const d = e.clientY - drag.current.y
    setDy(d < 0 ? d : rubberBand(d, 80))
  }
  const onUp = (e: ReactPointerEvent) => {
    const d = drag.current
    drag.current = null
    if (!d) return
    const travel = e.clientY - d.y
    const velocity = travel / Math.max(1, performance.now() - d.t)
    setDy(0)
    if (travel < -window.innerHeight / 4 || velocity < -0.5) open()
  }

  const elapsed = busySince === null ? 0 : Math.max(0, Math.round((tick - busySince) / 1000))
  const progress = Math.min(1, -dy / (window.innerHeight / 4))
  return (
    <div
      ref={ref}
      className="ios-lock"
      role="dialog"
      aria-modal="true"
      aria-label="Lock Screen"
      tabIndex={-1}
      data-leaving={leaving || undefined}
      data-dragging={dy !== 0 || undefined}
      style={{ '--drag': `${dy}px`, '--progress': progress } as React.CSSProperties}
      onPointerDown={onDown}
      onPointerMove={onMove}
      onPointerUp={onUp}
      onPointerCancel={onUp}
    >
      <div className="ios-lock-top">
        <span className="ios-lock-glyph" aria-hidden="true"><Glyph name={leaving ? 'lock-open' : 'lock'} size={20} /></span>
        <span className="ios-lock-date">{dateText(now, true)}</span>
        <time className="ios-lock-time" dateTime={now.toISOString()}>{timeText(now)}</time>
      </div>
      <div className="ios-lock-middle">
        {busySince !== null && (
          <div className="ios-live ios-glass" role="status">
            <AppIcon app={action === 'verify' ? 'verify' : 'sign'} size={40} />
            <span className="ios-live-text">
              <b>{action === 'verify' ? 'Verifying signature' : 'Signing document'}</b>
              <span>{`${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, '0')}`} · in progress</span>
            </span>
            <span className="ios-spinner" aria-hidden="true" />
          </div>
        )}
        {notes.length > 0 && <NoteList notes={notes} now={now.getTime()} onOpen={n => open(n)} />}
      </div>
      <div className="ios-lock-bottom">
        <button type="button" className="ios-lock-button" aria-label="Flashlight" aria-pressed={torch} onClick={onTorch}>
          <Glyph name="flashlight" size={22} />
        </button>
        <button type="button" className="ios-lock-open" data-autofocus onClick={() => open()}>
          <span>Swipe up to open</span>
          <span className="ios-home-bar" aria-hidden="true" />
        </button>
        <button type="button" className="ios-lock-button" aria-label="Camera" onClick={onCamera}>
          <Glyph name="camera" size={22} />
        </button>
      </div>
    </div>
  )
}
