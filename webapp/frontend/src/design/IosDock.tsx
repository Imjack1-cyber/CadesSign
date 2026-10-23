import { useEffect, useState } from 'react'
import type { StoredFile } from './generatedFiles'
import { AppIcon, APP_LOOKS, FileThumb } from './IosIcons'
import { type Point, useLongPress } from './iosGestures'
import type { AppId } from './iosPrefs'

const DOCK_APPS: readonly AppId[] = ['sign', 'analytics', 'files', 'settings']
/** How near the bottom edge (px) the pointer brings a hidden dock back, and how far up it may go before it hides again. */
const REVEAL_PX = 8
const KEEP_PX = 150

interface DockIconProps {
  app: AppId
  badge?: number
  size: number
  onLaunch: (app: AppId, from: DOMRect) => void
  onMenu: (app: AppId, at: Point) => void
}

/** An app in the dock or on the Home Screen: press to open, hold (or right-click) for its quick actions. */
export function DockIcon({ app, badge, size, onLaunch, onMenu }: DockIconProps) {
  const { handlers, fired } = useLongPress(at => onMenu(app, at))
  const label = APP_LOOKS[app].label
  return (
    <button
      type="button"
      className="ios-dock-icon"
      data-ios-app={app}
      aria-label={badge ? `${label}, ${badge} new` : label}
      title={label}
      {...handlers}
      onClick={e => {
        if (fired()) return
        onLaunch(app, e.currentTarget.getBoundingClientRect())
      }}
    >
      <AppIcon app={app} size={size} badge={badge} />
    </button>
  )
}

interface IosDockProps {
  badges: Partial<Record<AppId, number>>
  recents: StoredFile[]
  autoHide: boolean
  onLaunch: (app: AppId, from: DOMRect) => void
  onMenu: (app: AppId, at: Point) => void
  onFile: (file: StoredFile) => void
}

/**
 * The iPadOS dock: a floating glass shelf of apps and, past a divider, the files made most recently.
 * With auto-hide on it slides away and comes back when the pointer reaches the bottom edge or
 * keyboard focus moves into it.
 */
export function IosDock({ badges, recents, autoHide, onLaunch, onMenu, onFile }: IosDockProps) {
  const [revealed, setRevealed] = useState(false)
  const shown = !autoHide || revealed

  useEffect(() => {
    if (!autoHide) return
    const onMove = (e: PointerEvent) => {
      if (e.pointerType !== 'mouse') return
      if (e.clientY >= window.innerHeight - REVEAL_PX) setRevealed(true)
      else if (e.clientY < window.innerHeight - KEEP_PX) setRevealed(false)
    }
    window.addEventListener('pointermove', onMove, { passive: true })
    return () => window.removeEventListener('pointermove', onMove)
  }, [autoHide])

  return (
    <div className="ios-dock-wrap" data-hidden={!shown || undefined}>
      <nav className="ios-dock ios-glass" aria-label="Dock">
        {DOCK_APPS.map(app => <DockIcon key={app} app={app} size={52} badge={badges[app]} onLaunch={onLaunch} onMenu={onMenu} />)}
        {recents.length > 0 && <span className="ios-dock-divider" aria-hidden="true" />}
        {recents.map(f => (
          <button key={f.id} type="button" className="ios-dock-icon ios-dock-file" aria-label={`Recent file: ${f.name}`} title={f.name} onClick={() => onFile(f)}>
            <FileThumb name={f.name} size={52} />
          </button>
        ))}
      </nav>
    </div>
  )
}
