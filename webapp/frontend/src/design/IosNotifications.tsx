import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { AppIcon, APP_LOOKS, Glyph } from './IosIcons'
import { ago, dateText, timeText } from './iosDevice'
import type { AppId } from './iosPrefs'
import type { Outcome } from './signals'
import { useIosModal } from './useIosModal'

export interface Note {
  id: string
  app: AppId
  kind: Outcome | 'file'
  title: string
  body: string
  /** Epoch ms. */
  at: number
  /** What tapping it opens. */
  target?: 'result' | 'files'
}

/** How long a banner stays, unless the pointer or focus rests on it. */
export const BANNER_MS = 5000
/** Banners shown at once; older ones go straight to Notification Center. */
export const MAX_BANNERS = 3

interface NoteCardProps {
  note: Note
  now: number
  onOpen: (note: Note) => void
  /** The card's own close button; without it there is none. */
  onDismiss?: (id: string) => void
  /** How many more notifications from the same app sit behind this one. */
  behind?: number
}

/** One notification: app icon, app name, when, title and text. Tapping it opens what it is about. */
export function NoteCard({ note, now, onOpen, onDismiss, behind = 0 }: NoteCardProps) {
  return (
    <div className="ios-note ios-glass" data-kind={note.kind} data-behind={Math.min(2, behind) || undefined}>
      <button type="button" className="ios-note-open" onClick={() => onOpen(note)} aria-label={`${APP_LOOKS[note.app].label}: ${note.title}. ${note.body}`}>
        <AppIcon app={note.app} size={38} />
        <span className="ios-note-text">
          <span className="ios-note-head">
            <b>{note.title}</b>
            <time dateTime={new Date(note.at).toISOString()}>{ago(note.at, now)}</time>
          </span>
          <span className="ios-note-body">{note.body}</span>
          {behind > 0 && <span className="ios-note-more">{behind} more notification{behind > 1 ? 's' : ''}</span>}
        </span>
      </button>
      {onDismiss && (
        <button type="button" className="ios-note-close" aria-label="Clear notification" onClick={() => onDismiss(note.id)}>
          <Glyph name="xmark" size={12} />
        </button>
      )}
    </div>
  )
}

/** A banner: drops in from the top, goes away by itself, on its ✕, or when swiped up. */
function Banner({ note, onOpen, onDismiss }: { note: Note; onOpen: (n: Note) => void; onDismiss: (id: string) => void }) {
  const [held, setHeld] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const drag = useRef<number | null>(null)

  useEffect(() => {
    if (held) return
    const t = window.setTimeout(() => onDismiss(note.id), BANNER_MS)
    return () => window.clearTimeout(t)
  }, [held, note.id, onDismiss])

  const onDown = (e: ReactPointerEvent) => {
    drag.current = e.clientY
  }
  const onMove = (e: ReactPointerEvent) => {
    if (drag.current === null || !ref.current) return
    const dy = Math.min(0, e.clientY - drag.current)
    ref.current.style.translate = `0 ${dy}px`
  }
  const onUp = (e: ReactPointerEvent) => {
    if (drag.current === null || !ref.current) return
    const dy = e.clientY - drag.current
    drag.current = null
    ref.current.style.translate = ''
    if (dy < -30) onDismiss(note.id)
  }

  return (
    <div
      ref={ref}
      className="ios-banner"
      onPointerEnter={() => setHeld(true)}
      onPointerLeave={() => setHeld(false)}
      onFocus={() => setHeld(true)}
      onBlur={() => setHeld(false)}
      onPointerDown={onDown}
      onPointerMove={onMove}
      onPointerUp={onUp}
      onPointerCancel={onUp}
    >
      <NoteCard note={note} now={note.at} onOpen={onOpen} onDismiss={onDismiss} />
    </div>
  )
}

/** The banners at the top of the screen, newest first, announced politely as they arrive. */
export function IosBanners({ notes, onOpen, onDismiss }: { notes: Note[]; onOpen: (n: Note) => void; onDismiss: (id: string) => void }) {
  return (
    <div className="ios-banners" role="region" aria-label="Notifications" aria-live="polite">
      {notes.map(n => <Banner key={n.id} note={n} onOpen={onOpen} onDismiss={onDismiss} />)}
    </div>
  )
}

/** Groups notifications by app, newest group first, each newest first. */
function groupNotes(notes: readonly Note[]) {
  const groups = new Map<AppId, Note[]>()
  for (const n of [...notes].sort((a, b) => b.at - a.at)) groups.set(n.app, [...(groups.get(n.app) ?? []), n])
  return [...groups.entries()].map(([app, list]) => ({ app, list }))
}

interface NoteListProps {
  notes: Note[]
  now: number
  onOpen: (n: Note) => void
  onClear?: (ids: string[]) => void
}

/**
 * Notifications grouped by app: a stack shows its newest with the others peeking out below until it
 * is tapped open. Shared by Notification Center and the lock screen.
 */
export function NoteList({ notes, now, onOpen, onClear }: NoteListProps) {
  const [open, setOpen] = useState<Set<AppId>>(new Set())
  // The ✕ turns into "Clear" first, as on iOS; a second press clears the group.
  const [arming, setArming] = useState<AppId | null>(null)
  return (
    <ul className="ios-note-list">
      {groupNotes(notes).map(({ app, list }) => {
        const expanded = open.has(app) || list.length === 1
        return (
          <li key={app} className="ios-note-group" data-expanded={expanded || undefined}>
            {list.length > 1 && (
              <div className="ios-note-group-head">
                <span>{APP_LOOKS[app].label}</span>
                {expanded && <button type="button" onClick={() => setOpen(new Set([...open].filter(a => a !== app)))}>Show Less</button>}
                {onClear && (
                  <button
                    type="button"
                    className="ios-note-clear"
                    data-armed={arming === app || undefined}
                    aria-label={arming === app ? `Clear ${APP_LOOKS[app].label} notifications` : `Clear ${APP_LOOKS[app].label} notifications?`}
                    onClick={() => {
                      if (arming === app) {
                        onClear(list.map(n => n.id))
                        setArming(null)
                      } else setArming(app)
                    }}
                    onBlur={() => setArming(null)}
                  >
                    {arming === app ? 'Clear' : <Glyph name="xmark" size={11} />}
                  </button>
                )}
              </div>
            )}
            {(expanded ? list : list.slice(0, 1)).map(n => (
              <NoteCard
                key={n.id}
                note={n}
                now={now}
                behind={expanded ? 0 : list.length - 1}
                onOpen={expanded ? onOpen : () => setOpen(new Set([...open, app]))}
                onDismiss={onClear && list.length === 1 ? id => onClear([id]) : undefined}
              />
            ))}
          </li>
        )
      })}
    </ul>
  )
}

interface IosNotificationCenterProps {
  notes: Note[]
  now: Date
  onOpen: (n: Note) => void
  onClear: (ids: string[]) => void
  onClearAll: () => void
  onClose: () => void
}

/** Notification Center: pulled down from the top left, the time and date over every notification kept. */
export function IosNotificationCenter({ notes, now, onOpen, onClear, onClearAll, onClose }: IosNotificationCenterProps) {
  const ref = useRef<HTMLDivElement>(null)
  useIosModal(ref, onClose)
  return (
    <div className="ios-scrim ios-scrim--shade" onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className="ios-nc" role="dialog" aria-modal="true" aria-label="Notification Center" tabIndex={-1}>
        <div className="ios-nc-clock" aria-hidden="true">
          <span>{dateText(now, true)}</span>
          <b>{timeText(now)}</b>
        </div>
        <div className="ios-nc-head">
          <h2>Notification Center</h2>
          {notes.length > 0 && <button type="button" className="ios-pill-button" onClick={onClearAll}>Clear All</button>}
          <button type="button" className="ios-round-button" aria-label="Close" onClick={onClose}><Glyph name="xmark" size={14} /></button>
        </div>
        {notes.length
          ? <NoteList notes={notes} now={now.getTime()} onOpen={onOpen} onClear={onClear} />
          : <p className="ios-nc-empty">No Older Notifications</p>}
      </div>
    </div>
  )
}
