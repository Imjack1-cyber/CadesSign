import { useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react'
import { clampMove } from './win95Windows'

interface Win95FrameProps {
  title: string
  icon?: ReactNode
  /** Where the frame first opens, in viewport px. */
  initial: { x: number; y: number }
  minimized?: boolean
  onMinimize: () => void
  onClose: () => void
  className?: string
  children: ReactNode
  /** A label for the window as a whole; the title by default. */
  ariaLabel?: string
  /** The frontmost of the desktop's windows; the others sit behind it with gray title bars. */
  active?: boolean
  onActivate?: () => void
}

/**
 * A window of the Windows 95 desktop's own (Explorer and friends), as opposed to the app's cards that
 * win95Windows.ts turns into windows: it floats over the page, moves by its title bar with the same
 * dotted outline, maximizes on the button or a double-click, and minimizes into the taskbar.
 */
export function Win95Frame(props: Win95FrameProps) {
  const { title, icon, initial, minimized, onMinimize, onClose, className, children, ariaLabel, active = true, onActivate } = props
  const [pos, setPos] = useState(initial)
  const [maximized, setMaximized] = useState(false)
  const drag = useRef<{ x: number; y: number; rect: DOMRect; outline: HTMLDivElement | null } | null>(null)

  const onDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (maximized || e.button !== 0 || (e.target as Element).closest('button')) return
    e.preventDefault()
    e.currentTarget.setPointerCapture?.(e.pointerId)
    drag.current = { x: e.clientX, y: e.clientY, rect: e.currentTarget.parentElement!.getBoundingClientRect(), outline: null }
  }
  const onMove = (e: ReactPointerEvent) => {
    const d = drag.current
    if (!d) return
    const dx = e.clientX - d.x
    const dy = e.clientY - d.y
    if (!d.outline) {
      if (Math.abs(dx) < 3 && Math.abs(dy) < 3) return
      d.outline = document.createElement('div')
      d.outline.className = 'w95-drag-outline'
      Object.assign(d.outline.style, { width: `${d.rect.width}px`, height: `${d.rect.height}px` })
      document.body.append(d.outline)
    }
    Object.assign(d.outline.style, { left: `${d.rect.left + dx}px`, top: `${d.rect.top + dy}px` })
  }
  const onUp = (e: ReactPointerEvent) => {
    const d = drag.current
    drag.current = null
    if (!d?.outline) return
    d.outline.remove()
    const move = clampMove(d.rect, e.clientX - d.x, e.clientY - d.y, window.innerWidth, window.innerHeight)
    setPos((p: { x: number; y: number }) => ({ x: p.x + move.dx, y: p.y + move.dy }))
  }

  return (
    <section
      className={`w95-frame${maximized ? ' w95-frame--max' : ''}${active ? ' w95-frame--active' : ''}${className ? ` ${className}` : ''}`}
      style={{ left: pos.x, top: pos.y }}
      hidden={minimized}
      aria-label={ariaLabel ?? title}
      onPointerDownCapture={onActivate}
      onFocusCapture={onActivate}
    >
      <div
        className="w95-titlebar"
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerCancel={onUp}
        onDoubleClick={e => { if (!(e.target as Element).closest('button')) setMaximized((m: boolean) => !m) }}
      >
        {icon && <span className="w95-titlebar-icon" aria-hidden="true">{icon}</span>}
        <span className="w95-titlebar-text">{title}</span>
        <span className="w95-titlebar-buttons">
          <button type="button" data-w95-action="minimize" aria-label={`Minimize ${title}`} title="Minimize" onClick={onMinimize} />
          <button
            type="button"
            data-w95-action="maximize"
            data-restore={maximized}
            aria-label={`${maximized ? 'Restore' : 'Maximize'} ${title}`}
            title={maximized ? 'Restore' : 'Maximize'}
            onClick={() => setMaximized((m: boolean) => !m)}
          />
          <button type="button" data-w95-action="close" aria-label={`Close ${title}`} title="Close" onClick={onClose} />
        </span>
      </div>
      {children}
    </section>
  )
}
