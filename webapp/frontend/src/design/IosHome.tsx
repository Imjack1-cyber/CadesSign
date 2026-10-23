import { useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import type { StoredFile } from './generatedFiles'
import type { MenuItem } from './IosAlert'
import { DockIcon } from './IosDock'
import { AppIcon, APP_LOOKS, Glyph } from './IosIcons'
import { ago, dateText, timeText } from './iosDevice'
import type { Point } from './iosGestures'
import type { Note } from './IosNotifications'
import { type AppId, setIosPrefs, useIosPrefs } from './iosPrefs'
import { SIGNING_TIPS } from './tips'
import { useIosModal } from './useIosModal'

const DOCK: readonly AppId[] = ['sign', 'analytics', 'files', 'settings']

interface IosHomeProps {
  now: Date
  recent: StoredFile[]
  last: Note | null
  badges: Partial<Record<AppId, number>>
  onLaunch: (app: AppId, from: DOMRect) => void
  onMenu: (app: AppId, at: Point, extra: MenuItem[]) => void
  onFile: (f: StoredFile) => void
  onSearch: () => void
  onClose: () => void
}

/** Moves `app` to `to` in the order. */
const moved = (order: readonly AppId[], app: AppId, to: number) => {
  const rest = order.filter(a => a !== app)
  rest.splice(Math.max(0, Math.min(rest.length, to)), 0, app)
  return rest
}

/**
 * The Home Screen: widgets (the date and time, recent files, the last result, a tip), the apps with
 * their names, the Search pill and the dock, over the full wallpaper. Holding an app offers "Edit
 * Home Screen": the apps jiggle and can be dragged into another order, or moved with Alt and the
 * arrow keys, until Done. The order is kept. Escape (or opening an app) goes back.
 */
export function IosHome({ now, recent, last, badges, onLaunch, onMenu, onFile, onSearch, onClose }: IosHomeProps) {
  const ref = useRef<HTMLDivElement>(null)
  const prefs = useIosPrefs()
  const [jiggle, setJiggle] = useState(false)
  const [dragging, setDragging] = useState<AppId | null>(null)
  // A tip of the day: the same all day, the next one tomorrow.
  const tip = SIGNING_TIPS[Math.floor(now.getTime() / 86_400_000) % SIGNING_TIPS.length]
  useIosModal(ref, () => (jiggle ? setJiggle(false) : onClose()))

  const order = prefs.home
  const edit: MenuItem = { label: 'Edit Home Screen', glyph: 'grid', run: () => setJiggle(true) }

  const onKey = (e: ReactKeyboardEvent, app: AppId) => {
    if (!e.altKey || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) return
    e.preventDefault()
    const i = order.indexOf(app)
    const step = e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 1
    setJiggle(true)
    setIosPrefs({ home: moved(order, app, i + step) })
  }

  // While jiggling, an app follows the pointer through the grid: hovering another app takes its place.
  const onDown = (e: ReactPointerEvent, app: AppId) => {
    if (!jiggle || e.button !== 0) return
    e.currentTarget.setPointerCapture?.(e.pointerId)
    setDragging(app)
  }
  const onMove = (e: ReactPointerEvent) => {
    if (!dragging) return
    const over = document.elementFromPoint(e.clientX, e.clientY)?.closest<HTMLElement>('.ios-home-grid [data-ios-app]')
    const target = over?.dataset.iosApp as AppId | undefined
    if (target && target !== dragging) setIosPrefs({ home: moved(order, dragging, order.indexOf(target)) })
  }

  return (
    <div ref={ref} className="ios-home" role="dialog" aria-modal="true" aria-label="Home Screen" tabIndex={-1} data-jiggle={jiggle || undefined}>
      {jiggle && <button type="button" className="ios-pill-button ios-home-done" data-autofocus onClick={() => setJiggle(false)}>Done</button>}
      <div className="ios-widgets">
        <div className="ios-widget ios-widget--clock ios-glass" aria-label={`${dateText(now, true)}, ${timeText(now)}`} role="group">
          <span className="ios-widget-day">{now.toLocaleDateString([], { weekday: 'long' })}</span>
          <b className="ios-widget-date">{now.getDate()}</b>
          <span className="ios-widget-time">{timeText(now)}</span>
        </div>
        <div className="ios-widget ios-glass" role="group" aria-label="Recent Files">
          <span className="ios-widget-head"><Glyph name="folder" size={14} /> Recent Files</span>
          {recent.length ? (
            <ul className="ios-widget-list">
              {recent.slice(0, 3).map(f => (
                <li key={f.id}><button type="button" onClick={() => onFile(f)}><Glyph name={f.folder === 'reports' ? 'doc-text' : f.folder === 'keystores' ? 'key' : 'seal'} size={14} />{f.name}</button></li>
              ))}
            </ul>
          ) : <span className="ios-widget-empty">Files you make show up here.</span>}
        </div>
        <div className="ios-widget ios-glass" role="group" aria-label="Last Result" data-kind={last?.kind}>
          <span className="ios-widget-head"><Glyph name="check-circle" size={14} /> Last Result</span>
          {last ? (
            <>
              <b className="ios-widget-title">{last.title}</b>
              <span className="ios-widget-body">{last.body}</span>
              <span className="ios-widget-when">{ago(last.at, now.getTime())}</span>
            </>
          ) : <span className="ios-widget-empty">Nothing signed or verified yet.</span>}
        </div>
        <div className="ios-widget ios-widget--tip ios-glass" role="group" aria-label="Tip">
          <span className="ios-widget-head"><Glyph name="info" size={14} /> Tip</span>
          <span className="ios-widget-body">{tip}</span>
        </div>
      </div>
      <ul className="ios-home-grid" aria-label="Apps" onPointerMove={onMove} onPointerUp={() => setDragging(null)} onPointerCancel={() => setDragging(null)}>
        {order.map((app, i) => (
          <li key={app} style={{ '--i': i } as React.CSSProperties} data-dragging={dragging === app || undefined}>
            <span className="ios-home-app" onPointerDown={e => onDown(e, app)} onKeyDown={e => onKey(e, app)}>
              {jiggle ? (
                <button type="button" className="ios-dock-icon" data-ios-app={app} aria-label={`${APP_LOOKS[app].label}, position ${i + 1} of ${order.length}. Alt and arrow keys move it.`}>
                  <AppIcon app={app} size={60} badge={badges[app]} />
                </button>
              ) : (
                <DockIcon app={app} size={60} badge={badges[app]} onLaunch={onLaunch} onMenu={(a, at) => onMenu(a, at, [edit])} />
              )}
              <span className="ios-home-label" aria-hidden="true">{APP_LOOKS[app].label}</span>
            </span>
          </li>
        ))}
      </ul>
      <span className="ios-page-dots" aria-hidden="true"><i /></span>
      <button type="button" className="ios-home-search ios-glass" onClick={onSearch}><Glyph name="search" size={14} /> Search</button>
      <nav className="ios-dock ios-glass ios-home-dock" aria-label="Dock">
        {DOCK.map(app => <DockIcon key={app} app={app} size={56} badge={badges[app]} onLaunch={onLaunch} onMenu={(a, at) => onMenu(a, at, [edit])} />)}
      </nav>
    </div>
  )
}
