import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'
import type { View } from '../components/layout/AppShell'
import { emitChrome } from './signals'
import { useDesign } from './useDesign'
import { DocumentsIcon } from './Win95Icons'

/** A button on the taskbar for a window: minimized ones stand out, open ones look pressed. */
export interface Task {
  id: string
  label: string
  open: boolean
  onClick: () => void
}

interface Win95TaskbarProps {
  view: View
  onViewChange: (view: View) => void
  onOpenAppearance: () => void
  onOpenAbout: () => void
  onOpenDocuments: () => void
  tasks: Task[]
  assistantHidden: boolean
  onToggleAssistant: () => void
  onShutdown: () => void
}

type ItemId = 'wizard' | 'dashboard' | 'documents' | 'settings' | 'help' | 'assistant' | 'shutdown'

/** Start menu entries; `key` is the underlined access key, as in 95's menus. */
const ITEMS: ReadonlyArray<{ id: ItemId; label: string; key: string; icon: ReactNode; separator?: boolean }> = [
  {
    id: 'wizard', label: 'Sign / Verify', key: 'v',
    icon: <><path d="M4 2h10l5 5v15H4z" fill="#fff" stroke="#000" /><path d="M14 2v5h5" fill="#c0c0c0" stroke="#000" /><path d="M7 17q3-4 5 0t5-2" fill="none" stroke="#000080" strokeWidth="1.5" /></>,
  },
  {
    id: 'dashboard', label: 'Analytics', key: 'a',
    icon: <><path d="M3 21h18" stroke="#000" /><path d="M5 12h3v9H5zM10.5 7h3v14h-3zM16 14h3v7h-3z" fill="#008080" stroke="#000" /></>,
  },
  {
    id: 'documents', label: 'Documents', key: 'd',
    icon: <g transform="scale(0.75)"><DocumentsIcon /></g>,
  },
  {
    id: 'settings', label: 'Settings', key: 's',
    icon: <><rect x="3" y="4" width="18" height="13" fill="#c0c0c0" stroke="#000" /><rect x="5" y="6" width="14" height="9" fill="#008080" /><path d="M8 20h8M12 17v3" stroke="#000" strokeWidth="1.5" /></>,
  },
  {
    id: 'help', label: 'Help', key: 'h',
    icon: <><path d="M4 3h13v18H4z" fill="#000080" stroke="#000" /><path d="M17 3l3 2v16l-3 0" fill="#808080" stroke="#000" /><path d="M8.5 9a2 2 0 1 1 3 1.7c-.8.5-1 1-1 2M10.5 15.5v1" fill="none" stroke="#ff0" strokeWidth="1.5" /></>,
  },
  {
    id: 'assistant', label: 'Paperclip', key: 'p',
    icon: <path d="M9 15V6a3.5 3.5 0 0 1 7 0v12a3 3 0 0 1-6 0V8a2 2 0 0 1 4 0v8" fill="none" stroke="#555" strokeWidth="1.6" />,
  },
  {
    id: 'shutdown', label: 'Shut Down…', key: 'u', separator: true,
    icon: <><rect x="3" y="5" width="18" height="12" fill="#c0c0c0" stroke="#000" /><rect x="5" y="7" width="14" height="8" fill="#000" /><path d="M7 20h10" stroke="#000" strokeWidth="2" /></>,
  },
]

const VIEW_LABEL: Record<View, string> = { wizard: 'Sign / Verify', dashboard: 'Analytics', about: 'About' }

/** The label with its access key underlined. */
function Label({ text, accessKey }: { text: string; accessKey: string }) {
  const i = text.toLowerCase().indexOf(accessKey)
  if (i < 0) return <>{text}</>
  return <>{text.slice(0, i)}<u>{text[i]}</u>{text.slice(i + 1)}</>
}

const clockText = (d: Date) => d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })

/**
 * The Windows 95 theme's taskbar, which really works: Start opens a menu that navigates the app
 * (also on Ctrl+Esc, as in 95), each window has a button here, the tray speaker turns theme sound on
 * and off, and Shut Down starts the shutdown sequence. Win95Shell owns the windows and what they do;
 * the engine only hears about the menu to play its sound.
 */
export function Win95Taskbar(props: Win95TaskbarProps) {
  const { view, onViewChange, onOpenAppearance, onOpenAbout, onOpenDocuments, tasks, assistantHidden, onToggleAssistant, onShutdown } = props
  const { effects, soundPick, setSound } = useDesign()
  const [open, setOpen] = useState(false)
  const [now, setNow] = useState(() => new Date())
  const startRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([])

  const close = useCallback((refocus: boolean) => {
    setOpen(false)
    emitChrome('start-close')
    if (refocus) startRef.current?.focus()
  }, [])

  const toggle = useCallback(() => {
    emitChrome(open ? 'start-close' : 'start-open')
    setOpen(!open)
  }, [open])

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 30_000)
    return () => window.clearInterval(id)
  }, [])

  // Ctrl+Esc opens Start from anywhere, as the Windows key's stand-in always did.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && e.ctrlKey) {
        e.preventDefault()
        toggle()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [toggle])

  useEffect(() => {
    if (!open) return
    itemRefs.current[0]?.focus()
    const onDown = (e: PointerEvent) => {
      const path = e.composedPath()
      if (menuRef.current && !path.includes(menuRef.current) && startRef.current && !path.includes(startRef.current)) close(false)
    }
    document.addEventListener('pointerdown', onDown)
    return () => document.removeEventListener('pointerdown', onDown)
  }, [open, close])

  const activate = (id: ItemId) => {
    setOpen(false)
    if (id !== 'shutdown') emitChrome('start-close')
    switch (id) {
      case 'wizard':
      case 'dashboard':
        onViewChange(id)
        break
      case 'documents':
        onOpenDocuments()
        break
      case 'settings':
        onOpenAppearance()
        break
      case 'help':
        onOpenAbout()
        break
      case 'assistant':
        onToggleAssistant()
        break
      case 'shutdown':
        emitChrome('start-close')
        onShutdown()
        break
    }
  }

  const onMenuKey = (e: ReactKeyboardEvent) => {
    const items = itemRefs.current.filter((el: HTMLButtonElement | null): el is HTMLButtonElement => el !== null)
    const at = items.indexOf(document.activeElement as HTMLButtonElement)
    const focus = (i: number) => items[(i + items.length) % items.length]?.focus()
    switch (e.key) {
      case 'ArrowDown': focus(at + 1); break
      case 'ArrowUp': focus(at - 1); break
      case 'Home': focus(0); break
      case 'End': focus(items.length - 1); break
      case 'Escape':
        if (e.ctrlKey) return
        close(true)
        break
      case 'Tab':
        close(false)
        return
      default: {
        const item = ITEMS.find(it => it.key === e.key.toLowerCase())
        if (!item || e.ctrlKey || e.altKey || e.metaKey) return
        activate(item.id)
      }
    }
    e.preventDefault()
  }

  const soundOn = soundPick === 'on'

  return (
    <>
      <div className="w95-taskbar" role="toolbar" aria-label="Taskbar">
        <button
          ref={startRef}
          type="button"
          className="w95-start"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-controls="w95-start-menu"
          aria-keyshortcuts="Control+Escape"
          onClick={toggle}
        >
          <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="" width="16" height="16" />
          Start
        </button>
        <span className="w95-tasks">
          <span className="w95-task" aria-current="page">{VIEW_LABEL[view]}</span>
          {tasks.map(t => (
            <button
              key={t.id}
              type="button"
              className="w95-task w95-task--window"
              data-w95-task={t.id}
              aria-pressed={t.open}
              aria-label={t.open ? `Minimize ${t.label}` : `Restore ${t.label}`}
              title={t.label}
              onClick={t.onClick}
            >
              {t.label}
            </button>
          ))}
        </span>
        <span className="w95-tray">
          <button
            type="button"
            className="w95-speaker"
            aria-label="Sound"
            aria-pressed={soundOn}
            title={effects === 'off' ? 'Sound needs animation turned on' : soundOn ? 'Mute' : 'Unmute'}
            disabled={effects === 'off'}
            onClick={() => setSound(soundOn ? 'off' : 'on')}
          >
            <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
              <path d="M2 6h3l4-3v10l-4-3H2z" fill="#ff0" stroke="#000" />
              {soundOn
                ? <path d="M11 5q2 3 0 6M13 3q4 5 0 10" fill="none" stroke="#000" />
                : <path d="M11 5l4 6M15 5l-4 6" stroke="#c00" strokeWidth="1.5" />}
            </svg>
          </button>
          <time className="w95-clock" dateTime={now.toISOString()} title={now.toLocaleDateString([], { dateStyle: 'full' })}>
            {clockText(now)}
          </time>
        </span>
      </div>

      {open && (
        <div ref={menuRef} id="w95-start-menu" className="w95-menu" role="menu" aria-label="Start" onKeyDown={onMenuKey}>
          <span className="w95-menu-banner" aria-hidden="true"><b>CAdES</b>95</span>
          <span className="w95-menu-items">
            {ITEMS.map((item, i) => (
              <span key={item.id} role="none">
                {item.separator && <span className="w95-menu-separator" role="separator" />}
                <button
                  ref={el => { itemRefs.current[i] = el }}
                  type="button"
                  role="menuitem"
                  tabIndex={-1}
                  aria-keyshortcuts={item.key.toUpperCase()}
                  onClick={() => activate(item.id)}
                >
                  <svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">{item.icon}</svg>
                  <span>
                    <Label text={item.id === 'assistant' ? `${assistantHidden ? 'Show' : 'Hide'} ${item.label}` : item.label} accessKey={item.key} />
                  </span>
                </button>
              </span>
            ))}
          </span>
        </div>
      )}
    </>
  )
}
