import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import type { View } from '../components/layout/AppShell'
import { Glyph, type GlyphName } from './IosIcons'

export type TabId = View | 'files' | 'settings'

interface IosTabBarProps {
  phone: boolean
  /** The tab shown: a view, or (on phones) Files or Settings. */
  current: TabId
  onSelect: (tab: TabId) => void
  onSearch: () => void
  filesBadge: number
}

const PAD_TABS: ReadonlyArray<{ id: TabId; label: string; glyph: GlyphName }> = [
  { id: 'wizard', label: 'Sign / Verify', glyph: 'pen' },
  { id: 'dashboard', label: 'Analytics', glyph: 'chart' },
  { id: 'about', label: 'About', glyph: 'info' },
]

const PHONE_TABS: ReadonlyArray<{ id: TabId; label: string; glyph: GlyphName }> = [
  { id: 'wizard', label: 'Sign', glyph: 'pen' },
  { id: 'dashboard', label: 'Analytics', glyph: 'chart' },
  { id: 'files', label: 'Files', glyph: 'folder' },
  { id: 'settings', label: 'Settings', glyph: 'gear' },
]

/** A drag of the lens shorter than this (px) is a tap. */
const SLOP = 6

/**
 * The Liquid Glass tab bar: a floating capsule at the top of the iPad screen, or at the bottom of a
 * phone's beside a round Search button. A clear glass lens sits on the chosen tab and slides to the
 * next one; it can also be dragged across the bar and let go on a tab. On a phone the bar shrinks
 * to the chosen tab while the page scrolls down and comes back when it scrolls up. Arrow keys move
 * between the tabs.
 */
export function IosTabBar({ phone, current, onSelect, onSearch, filesBadge }: IosTabBarProps) {
  const tabs = phone ? PHONE_TABS : PAD_TABS
  const barRef = useRef<HTMLDivElement>(null)
  const [lens, setLens] = useState<{ left: number; width: number } | null>(null)
  const [drag, setDrag] = useState<{ x: number; start: number; left: number; moved: boolean } | null>(null)
  const [minimized, setMinimized] = useState(false)

  const measure = useCallback(() => {
    const el = barRef.current?.querySelector<HTMLElement>('[aria-current=page]')
    setLens(el ? { left: el.offsetLeft, width: el.offsetWidth } : null)
  }, [])
  useLayoutEffect(measure, [measure, current, phone, minimized])
  useEffect(() => {
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [measure])

  // On a phone the bar gets out of the way of what is being read.
  useEffect(() => {
    if (!phone) return
    let lastY: number | null = null
    const onWheel = (e: WheelEvent) => {
      if (Math.abs(e.deltaY) > 4) setMinimized(e.deltaY > 0)
    }
    const onTouch = (e: TouchEvent) => {
      const y = e.touches[0]?.clientY
      if (y === undefined) return
      if (lastY !== null && Math.abs(y - lastY) > 12) {
        setMinimized(y < lastY)
        lastY = y
      } else if (lastY === null) lastY = y
    }
    const onEnd = () => {
      lastY = null
    }
    window.addEventListener('wheel', onWheel, { passive: true })
    window.addEventListener('touchmove', onTouch, { passive: true })
    window.addEventListener('touchend', onEnd, { passive: true })
    return () => {
      window.removeEventListener('wheel', onWheel)
      window.removeEventListener('touchmove', onTouch)
      window.removeEventListener('touchend', onEnd)
    }
  }, [phone])

  const select = (id: TabId) => {
    setMinimized(false)
    if (id !== current) onSelect(id)
  }

  const onDown = (e: ReactPointerEvent<HTMLButtonElement>, id: TabId) => {
    if (id !== current || !lens || e.button !== 0) return
    e.currentTarget.setPointerCapture?.(e.pointerId)
    setDrag({ x: e.clientX, start: e.clientX, left: lens.left, moved: false })
  }
  const onMove = (e: ReactPointerEvent) => {
    if (!drag || !lens || !barRef.current) return
    const moved = drag.moved || Math.abs(e.clientX - drag.start) > SLOP
    const max = barRef.current.clientWidth - lens.width
    setDrag({ ...drag, x: e.clientX, moved })
    if (moved) setLens({ ...lens, left: Math.max(0, Math.min(max, drag.left + e.clientX - drag.start)) })
  }
  const onUp = () => {
    const d = drag
    setDrag(null)
    if (!d?.moved || !lens || !barRef.current) return
    // Let go: the tab under the lens's middle is chosen, and the lens settles on it.
    const middle = lens.left + lens.width / 2
    const buttons = [...barRef.current.querySelectorAll<HTMLElement>('.ios-tab')]
    const nearest = buttons.reduce((a, b) => (Math.abs(b.offsetLeft + b.offsetWidth / 2 - middle) < Math.abs(a.offsetLeft + a.offsetWidth / 2 - middle) ? b : a))
    const id = nearest.dataset.tab as TabId
    if (id === current) measure()
    else select(id)
  }

  const onKey = (e: ReactKeyboardEvent) => {
    const buttons = [...(barRef.current?.querySelectorAll<HTMLButtonElement>('.ios-tab') ?? [])]
    const i = buttons.indexOf(document.activeElement as HTMLButtonElement)
    const go = (n: number) => buttons[(n + buttons.length) % buttons.length]?.focus()
    if (e.key === 'ArrowRight') go(i + 1)
    else if (e.key === 'ArrowLeft') go(i - 1)
    else if (e.key === 'Home') go(0)
    else if (e.key === 'End') go(buttons.length - 1)
    else return
    e.preventDefault()
  }

  return (
    <nav className="ios-tabbar" data-phone={phone || undefined} data-min={(phone && minimized) || undefined} aria-label="Tab bar">
      <div ref={barRef} className="ios-tabbar-capsule ios-glass" onKeyDown={onKey} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}>
        {lens && <span className="ios-tabbar-lens" data-dragging={drag?.moved || undefined} style={{ left: lens.left, width: lens.width }} aria-hidden="true" />}
        {tabs.map(t => (
          <button
            key={t.id}
            type="button"
            className="ios-tab"
            data-tab={t.id}
            data-ios-app={t.id === 'files' ? 'files' : undefined}
            aria-current={t.id === current ? 'page' : undefined}
            aria-label={t.id === 'files' && filesBadge ? `${t.label}, ${filesBadge} new` : t.label}
            onPointerDown={e => onDown(e, t.id)}
            onClick={() => {
              if (!drag?.moved) select(t.id)
            }}
          >
            <Glyph name={t.glyph} size={phone ? 22 : 17} />
            <span className="ios-tab-label">{t.label}</span>
            {t.id === 'files' && filesBadge > 0 && <span className="ios-badge" aria-hidden="true">{filesBadge}</span>}
          </button>
        ))}
      </div>
      <button type="button" className="ios-tabbar-search ios-glass" aria-label="Search" aria-keyshortcuts="Control+Space Meta+Space" onClick={onSearch}>
        <Glyph name="search" size={phone ? 22 : 17} />
      </button>
    </nav>
  )
}
