import { useId, useLayoutEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { Glyph, type GlyphName } from './IosIcons'
import type { Point } from './iosGestures'
import { useIosModal } from './useIosModal'

export interface AlertAction {
  label: string
  /** 'default' is the preferred action (bold), 'cancel' runs on Escape, 'destructive' is red. */
  style?: 'default' | 'cancel' | 'destructive'
  run?: () => void
}

export interface AlertSpec {
  title: string
  message?: string
  glyph?: GlyphName
  actions: AlertAction[]
}

/**
 * An iOS alert: a small glass card in the middle of a dimmed screen, title and message centred, its
 * buttons side by side when there are two and stacked otherwise. Escape is the cancel button, or the
 * only one.
 */
export function IosAlert({ alert, onDone }: { alert: AlertSpec; onDone: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const messageId = useId()
  const choose = (a: AlertAction | undefined) => {
    onDone()
    a?.run?.()
  }
  const cancel = alert.actions.find(a => a.style === 'cancel') ?? (alert.actions.length === 1 ? alert.actions[0] : undefined)
  useIosModal(ref, () => choose(cancel))
  const preferred = alert.actions.find(a => a.style === 'default') ?? alert.actions[alert.actions.length - 1]

  return (
    <div className="ios-scrim ios-scrim--alert">
      <div
        ref={ref}
        className="ios-alert ios-glass"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={alert.message ? messageId : undefined}
        tabIndex={-1}
      >
        <div className="ios-alert-text">
          {alert.glyph && <span className="ios-alert-glyph"><Glyph name={alert.glyph} size={34} /></span>}
          <h2 id={titleId}>{alert.title}</h2>
          {alert.message && <p id={messageId}>{alert.message}</p>}
        </div>
        <div className={`ios-alert-actions${alert.actions.length === 2 ? ' ios-alert-actions--row' : ''}`}>
          {alert.actions.map(a => (
            <button
              key={a.label}
              type="button"
              className="ios-alert-button"
              data-style={a.style ?? 'plain'}
              data-autofocus={a === preferred ? '' : undefined}
              onClick={() => choose(a)}
            >
              {a.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

export type Hud =
  | { kind: 'silent'; on: boolean }
  | { kind: 'volume'; level: number }
  | { kind: 'brightness'; level: number }
  | { kind: 'text'; text: string; error?: boolean }

/** The small pill iOS shows for the ring / silent switch and the volume buttons, or a short message. */
export function IosHud({ hud }: { hud: Hud }) {
  if (hud.kind === 'text') {
    return (
      <div className="ios-hud ios-glass" role="status" data-error={hud.error || undefined}>
        <Glyph name={hud.error ? 'warn' : 'info'} size={16} />
        <span>{hud.text}</span>
      </div>
    )
  }
  if (hud.kind === 'silent') {
    return (
      <div className="ios-hud ios-glass" role="status" data-silent={hud.on}>
        <Glyph name={hud.on ? 'bell-slash' : 'bell'} size={18} />
        <span>Silent Mode</span>
        <b>{hud.on ? 'On' : 'Off'}</b>
      </div>
    )
  }
  const pct = Math.round(hud.level * 100)
  return (
    <div className="ios-hud ios-hud--level ios-glass" role="status" aria-label={`${hud.kind === 'volume' ? 'Volume' : 'Brightness'} ${pct}%`}>
      <Glyph name={hud.kind === 'volume' ? (hud.level ? 'speaker' : 'speaker-slash') : 'sun'} size={18} />
      <span className="ios-hud-bar"><i style={{ width: `${pct}%` }} /></span>
    </div>
  )
}

export interface MenuItem {
  label: string
  glyph?: GlyphName
  destructive?: boolean
  disabled?: boolean
  /** A choice that is the current one, ticked on the left (sort orders, views). */
  checked?: boolean
  run: () => void
}

/**
 * A context menu, as a long press or a right-click opens it: the screen behind blurs, and a glass
 * menu of actions (their symbols on the right) opens beside the point, kept on screen.
 */
export function IosMenu({ at, title, items, onClose }: { at: Point; title?: string; items: MenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState<{ left: number; top: number; origin: string }>({ left: at.x, top: at.y, origin: 'top left' })
  useIosModal(ref, onClose)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const { width, height } = el.getBoundingClientRect()
    const right = at.x + width + 12 > window.innerWidth
    const below = at.y + height + 12 <= window.innerHeight
    setPos({
      left: Math.max(8, right ? at.x - width : at.x),
      top: Math.max(8, below ? at.y : at.y - height),
      origin: `${below ? 'top' : 'bottom'} ${right ? 'right' : 'left'}`,
    })
  }, [at.x, at.y])

  const onKey = (e: ReactKeyboardEvent) => {
    const buttons = [...(ref.current?.querySelectorAll<HTMLButtonElement>('button:not([disabled])') ?? [])]
    const i = buttons.indexOf(document.activeElement as HTMLButtonElement)
    const go = (n: number) => buttons[(n + buttons.length) % buttons.length]?.focus()
    if (e.key === 'ArrowDown') go(i + 1)
    else if (e.key === 'ArrowUp') go(i - 1)
    else if (e.key === 'Home') go(0)
    else if (e.key === 'End') go(buttons.length - 1)
    else return
    e.preventDefault()
  }

  return (
    <div className="ios-scrim ios-scrim--menu" onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <div
        ref={ref}
        className="ios-menu ios-glass"
        role="menu"
        aria-label={title ?? 'Actions'}
        style={{ left: pos.left, top: pos.top, transformOrigin: pos.origin }}
        onKeyDown={onKey}
      >
        {title && <div className="ios-menu-title" aria-hidden="true">{title}</div>}
        {items.map(item => (
          <button
            key={item.label}
            type="button"
            role={item.checked === undefined ? 'menuitem' : 'menuitemradio'}
            aria-checked={item.checked}
            className="ios-menu-item"
            data-destructive={item.destructive || undefined}
            disabled={item.disabled}
            onClick={() => {
              onClose()
              item.run()
            }}
          >
            {item.checked !== undefined && <span className="ios-menu-check">{item.checked && '✓'}</span>}
            <span>{item.label}</span>
            {item.glyph && <Glyph name={item.glyph} size={18} />}
          </button>
        ))}
      </div>
    </div>
  )
}
