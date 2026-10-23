import { useRef, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react'
import { rubberBand, shouldDismiss } from './iosGestures'
import { useIosModal } from './useIosModal'

interface IosSheetProps {
  label: string
  onClose: () => void
  /**
   * 'sheet' slides up over a dimmed screen (a form sheet on iPad, a bottom sheet with a grabber on
   * phones) and is modal; 'page' is a phone tab's page, covering the content but not the tab bar.
   */
  presentation: 'sheet' | 'page'
  className?: string
  children: ReactNode
}

/**
 * A sheet or a tab page of the iPadOS theme's own apps (Files, Settings). A sheet can be pulled down
 * by its grabber: it follows the finger, resists being pulled up, and closes when dragged a third of
 * the way or flicked.
 */
export function IosSheet({ label, onClose, presentation, className, children }: IosSheetProps) {
  const ref = useRef<HTMLElement>(null)
  const drag = useRef<{ y: number; t: number } | null>(null)
  useIosModal(ref, onClose, presentation === 'sheet')

  const onDown = (e: ReactPointerEvent) => {
    if (e.button !== 0) return
    e.currentTarget.setPointerCapture?.(e.pointerId)
    drag.current = { y: e.clientY, t: performance.now() }
    ref.current?.classList.add('ios-dragging')
  }
  const onMove = (e: ReactPointerEvent) => {
    if (!drag.current || !ref.current) return
    const dy = e.clientY - drag.current.y
    ref.current.style.translate = `0 ${dy >= 0 ? dy : -rubberBand(-dy, 60)}px`
  }
  const onUp = (e: ReactPointerEvent) => {
    const d = drag.current
    const el = ref.current
    drag.current = null
    if (!d || !el) return
    el.classList.remove('ios-dragging')
    const dy = e.clientY - d.y
    el.style.translate = ''
    if (shouldDismiss(dy, dy / Math.max(1, performance.now() - d.t), el.getBoundingClientRect().height)) onClose()
  }

  if (presentation === 'page') {
    return (
      <section ref={ref} className={`ios-page${className ? ` ${className}` : ''}`} aria-label={label} tabIndex={-1}>
        {children}
      </section>
    )
  }
  return (
    <div className="ios-scrim ios-scrim--sheet" onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <section
        ref={ref}
        className={`ios-sheet ios-glass${className ? ` ${className}` : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
      >
        <div className="ios-grabber" onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp} aria-hidden="true">
          <i />
        </div>
        {children}
      </section>
    </div>
  )
}
