import { useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import { AppIcon } from './IosIcons'
import { rubberBand } from './iosGestures'
import type { AppId } from './iosPrefs'
import type { TabId } from './IosTabBar'
import { Thumbnail } from './Thumbnail'
import { useIosModal } from './useIosModal'

export interface SwitcherCard {
  id: TabId
  app: AppId
  title: string
  subtitle?: string
}

interface IosSwitcherProps {
  cards: SwitcherCard[]
  current: TabId
  onOpen: (id: TabId) => void
  /** Closes the card; false when it cannot be closed now (it shakes). */
  onCloseCard: (id: TabId) => boolean
  onClose: () => void
}

/** A card flicked up further than this (px) is closed. */
const CLOSE_PX = 120

/**
 * The App Switcher: every open part of the app as a card (its icon and name over a miniature of
 * it), the current one first. Tap a card to go there; flick it up, or press Delete, to close it.
 * Closing Sign / Verify starts the wizard over; while it is running a request it refuses with a shake.
 */
export function IosSwitcher({ cards, current, onOpen, onCloseCard, onClose }: IosSwitcherProps) {
  const ref = useRef<HTMLDivElement>(null)
  const [drag, setDrag] = useState<{ id: TabId; y: number; dy: number } | null>(null)
  const [refused, setRefused] = useState<TabId | null>(null)
  // A drag ends in a click on the card; that click must not open it.
  const dragged = useRef(false)
  useIosModal(ref, onClose)

  const close = (id: TabId) => {
    if (onCloseCard(id)) return
    setRefused(id)
    window.setTimeout(() => setRefused(null), 500)
  }

  const onDown = (e: ReactPointerEvent, id: TabId) => {
    if (e.button !== 0) return
    e.currentTarget.setPointerCapture?.(e.pointerId)
    setDrag({ id, y: e.clientY, dy: 0 })
  }
  const onMove = (e: ReactPointerEvent) => {
    if (!drag) return
    const dy = e.clientY - drag.y
    setDrag({ ...drag, dy: dy < 0 ? dy : rubberBand(dy, 40) })
  }
  const onUp = () => {
    const d = drag
    setDrag(null)
    dragged.current = !!d && Math.abs(d.dy) > 6
    if (d && d.dy < -CLOSE_PX) close(d.id)
  }
  const onKey = (e: ReactKeyboardEvent, id: TabId) => {
    if (e.key !== 'Delete' && e.key !== 'Backspace') return
    e.preventDefault()
    close(id)
  }

  const ordered = [...cards].sort((a, b) => (a.id === current ? -1 : b.id === current ? 1 : 0))
  return (
    <div ref={ref} className="ios-switcher" role="dialog" aria-modal="true" aria-label="App Switcher" tabIndex={-1} onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <ul className="ios-switcher-cards" onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}>
        {ordered.map(card => {
          const dy = drag?.id === card.id ? drag.dy : 0
          return (
            <li
              key={card.id}
              className="ios-switcher-card"
              data-refused={refused === card.id || undefined}
              data-dragging={dy !== 0 || undefined}
              style={{ '--drag': `${dy}px`, '--fade': Math.max(0.2, 1 + dy / 400) } as React.CSSProperties}
            >
              <span className="ios-switcher-head" aria-hidden="true">
                <AppIcon app={card.app} size={28} />
                <b>{card.title}</b>
              </span>
              <button
                type="button"
                className="ios-switcher-shot"
                aria-label={`${card.title}${card.subtitle ? `, ${card.subtitle}` : ''}. Delete closes it.`}
                onPointerDown={e => onDown(e, card.id)}
                onClick={() => {
                  if (dragged.current) dragged.current = false
                  else onOpen(card.id)
                }}
                onKeyDown={e => onKey(e, card.id)}
              >
                <Thumbnail layout="focus" theme="ios" />
                {card.subtitle && <span className="ios-switcher-sub">{card.subtitle}</span>}
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
