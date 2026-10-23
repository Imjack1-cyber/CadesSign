import { useRef } from 'react'
import { useIosModal } from './useIosModal'

/** Apple keyboards name their keys with symbols; everyone else's with words. */
const MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)
const KEY = MAC ? { mod: '⌘', alt: '⌥', shift: '⇧', esc: 'esc' } : { mod: 'Ctrl', alt: 'Alt', shift: 'Shift', esc: 'Esc' }

const SHORTCUTS: ReadonlyArray<{ keys: string[]; label: string }> = [
  { keys: [KEY.mod, 'Space'], label: 'Spotlight' },
  { keys: [KEY.mod, 'K'], label: 'Spotlight' },
  { keys: [KEY.alt, KEY.shift, 'H'], label: 'Home Screen' },
  { keys: [KEY.alt, KEY.shift, 'S'], label: 'App Switcher' },
  { keys: [KEY.alt, KEY.shift, 'C'], label: 'Control Center' },
  { keys: [KEY.alt, KEY.shift, 'N'], label: 'Notification Center' },
  { keys: [KEY.alt, KEY.shift, 'L'], label: 'Lock Screen' },
  { keys: [KEY.esc], label: 'Close' },
]

function List() {
  return (
    <dl className="ios-shortcuts-list">
      {SHORTCUTS.map(s => (
        <div key={s.keys.join('+')}>
          <dt>{s.label}</dt>
          <dd>{s.keys.map(k => <kbd key={k}>{k}</kbd>)}</dd>
        </div>
      ))}
    </dl>
  )
}

/**
 * The keyboard shortcuts, as iPadOS shows them while ⌘ is held down. Opened from Settings it stays
 * until closed; shown by holding the key it goes away when the key is let go (and stays out of the
 * way of screen readers, which have Settings for it).
 */
export function IosShortcuts({ held, onClose }: { held: boolean; onClose: () => void }) {
  if (held) {
    return (
      <div className="ios-shortcuts ios-glass" aria-hidden="true">
        <h2>CAdES B-LT</h2>
        <List />
      </div>
    )
  }
  return <ShortcutsDialog onClose={onClose} />
}

function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  useIosModal(ref, onClose)
  return (
    <div className="ios-scrim ios-scrim--alert" onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className="ios-shortcuts ios-glass" role="dialog" aria-modal="true" aria-label="Keyboard Shortcuts" tabIndex={-1}>
        <h2>Keyboard Shortcuts</h2>
        <List />
        <button type="button" className="ios-pill-button" onClick={onClose}>Done</button>
      </div>
    </div>
  )
}
