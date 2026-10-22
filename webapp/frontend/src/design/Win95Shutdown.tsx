import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { emitChrome } from './signals'
import { SHUTDOWN_TIMES } from './win95Timing'

type Choice = 'shutdown' | 'restart' | 'leave'
type Phase = 'dialog' | 'shutting' | 'safe' | 'post' | 'splash'

const CHOICES: ReadonlyArray<{ id: Choice; label: string }> = [
  { id: 'shutdown', label: 'Shut down the computer?' },
  { id: 'restart', label: 'Restart the computer?' },
  { id: 'leave', label: 'Leave the Windows 95 theme?' },
]


interface Win95ShutdownProps {
  /** The dialog was cancelled, or the computer started again. */
  onClose: () => void
  /** The user chose to leave the theme. */
  onLeave: () => void
}

/**
 * Shutting down Windows 95, start to finish: the dimmed screen with the Shut Down Windows dialog,
 * "Please wait while your computer shuts down", then the orange "It's now safe to turn off your
 * computer" that waits for a key or click to power on again (POST text, the splash with its moving
 * bar, the start-up sound). Restart skips the safe screen; the third choice leaves the theme.
 */
export function Win95Shutdown({ onClose, onLeave }: Win95ShutdownProps) {
  const [phase, setPhase] = useState<Phase>('dialog')
  const [choice, setChoice] = useState<Choice>('shutdown')
  const dialogRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (phase === 'dialog') dialogRef.current?.querySelector<HTMLInputElement>('input:checked')?.focus()
  }, [phase])

  // The timed screens move on by themselves; the safe screen and the start-up screens also on any
  // key or click. Listening starts a moment late, so the press that got here does not skip ahead.
  useEffect(() => {
    if (phase === 'dialog') return
    const next = () => {
      if (phase === 'shutting') {
        if (choice === 'leave') onLeave()
        else setPhase(choice === 'shutdown' ? 'safe' : 'post')
      } else if (phase === 'safe') setPhase('post')
      else if (phase === 'post') setPhase('splash')
      else {
        emitChrome('startup')
        // Replays the taskbar and page entrance animations (themes.css).
        const root = document.documentElement
        root.classList.add('app-boot')
        window.setTimeout(() => root.classList.remove('app-boot'), 1200)
        onClose()
      }
    }
    const timer = phase === 'safe' ? 0 : window.setTimeout(next, SHUTDOWN_TIMES[phase])
    const skip = phase === 'shutting' ? null : next
    const arm = window.setTimeout(() => {
      if (!skip) return
      window.addEventListener('keydown', skip)
      window.addEventListener('pointerdown', skip)
    }, 300)
    return () => {
      window.clearTimeout(timer)
      window.clearTimeout(arm)
      if (skip) {
        window.removeEventListener('keydown', skip)
        window.removeEventListener('pointerdown', skip)
      }
    }
  }, [phase, choice, onClose, onLeave])

  const confirm = () => {
    emitChrome('shutdown')
    setPhase('shutting')
  }

  // A modal dialog: Escape answers No, Enter answers Yes, and Tab stays inside.
  const onDialogKey = (e: ReactKeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'Enter' && (e.target as HTMLElement).tagName === 'INPUT') {
      e.preventDefault()
      confirm()
    } else if (e.key === 'Tab') {
      const stops = [...dialogRef.current!.querySelectorAll<HTMLElement>('input:checked, button')]
      const at = stops.indexOf(document.activeElement as HTMLElement)
      const to = e.shiftKey ? (at <= 0 ? stops.length - 1 : at - 1) : (at + 1) % stops.length
      e.preventDefault()
      stops[to]?.focus()
    }
  }

  switch (phase) {
    case 'dialog':
      return (
        <div className="w95-shutdown-dim">
          <div
            ref={dialogRef}
            className="w95-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="w95-shutdown-title"
            onKeyDown={onDialogKey}
          >
            <div className="w95-dialog-title" id="w95-shutdown-title">Shut Down Windows</div>
            <div className="w95-dialog-body">
              <span className="w95-dialog-icon" aria-hidden="true" />
              <fieldset>
                <legend>Are you sure you want to:</legend>
                {CHOICES.map(c => (
                  <label key={c.id}>
                    <input type="radio" name="w95-shutdown" checked={choice === c.id} onChange={() => setChoice(c.id)} />
                    {c.label}
                  </label>
                ))}
              </fieldset>
            </div>
            <div className="w95-dialog-buttons">
              <button type="button" className="w95-button" onClick={confirm}>Yes</button>
              <button type="button" className="w95-button" onClick={onClose}>No</button>
            </div>
          </div>
        </div>
      )
    case 'shutting':
      return (
        <div className="w95-screen w95-screen--sky" role="status">
          <span className="w95-logo" aria-hidden="true"><b>CAdES</b>95</span>
          <span className="w95-screen-text">Please wait while your computer shuts down.</span>
        </div>
      )
    case 'safe':
      return (
        <div className="w95-screen w95-screen--safe" role="status">
          <span className="w95-safe-text">It&rsquo;s now safe to turn off<br />your computer.</span>
          <span className="w95-screen-hint">Press any key or click to turn it back on.</span>
        </div>
      )
    case 'post':
      return (
        <div className="w95-screen w95-screen--post" role="status">
          <span>Starting CAdES 95...</span>
        </div>
      )
    case 'splash':
      return (
        <div className="w95-screen w95-screen--sky w95-screen--splash" role="status" aria-label="Starting CAdES 95">
          <span className="w95-logo" aria-hidden="true"><b>CAdES</b>95</span>
          <span className="w95-splash-bar" aria-hidden="true" />
        </div>
      )
  }
}
