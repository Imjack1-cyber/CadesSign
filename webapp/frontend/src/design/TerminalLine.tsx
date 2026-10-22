import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import {
  APP_SIGNAL_EVENT, type AppSignal, type FileSlot, type Outcome, type WizardCommand,
  emitChrome, emitCommand, emitCommandResult,
} from './signals'
import { type TerminalContext, type TerminalReply, type TerminalView, complete, interpret, scrollStatus } from './terminalCommands'
import { useDesign } from './useDesign'

/** How long a reply stays on the line before the status (READY, INSERT, ...) comes back, in ms. */
const SHOW_MS = 4000
const SHOW_ERROR_MS = 6000
const SHOW_OUTCOME_MS = 8000
/** The scroll position stays briefly after the wheel stops. */
const SHOW_SCROLL_MS = 1500
const HISTORY_MAX = 50
/** The collapse to a line and a dot before the screen goes dark; matches app-crt-off in themes.css. */
const POWER_OFF_MS = 700
const REBOOT_DARK_MS = 1200
/** Keys are ignored this long after the screen goes dark, so the Enter that ran `shutdown` cannot wake it. */
const WAKE_ARM_MS = 250
/** The element a wheel event scrolls: the innermost scrollable one along its path, IX's insides included. */
function scrollerOf(path: readonly EventTarget[]): Element {
  for (const node of path) {
    if (!(node instanceof Element)) continue
    const { overflowY } = window.getComputedStyle(node)
    if ((overflowY === 'auto' || overflowY === 'scroll') && node.scrollHeight > node.clientHeight + 1) return node
  }
  return document.scrollingElement ?? document.documentElement
}

/** The boot log replays from this session flag (ThemeEffects.tsx). */
const BOOTED_KEY = 'cades-terminal-booted'

type Tone = 'info' | 'ok' | 'warn' | 'error'
interface Message {
  text: string
  tone: Tone
}

const OUTCOME: Record<Outcome, { tag: string; tone: Tone }> = {
  success: { tag: '[  OK  ]', tone: 'ok' },
  warning: { tag: '[ WARN ]', tone: 'warn' },
  error: { tag: '[ FAIL ]', tone: 'error' },
  info: { tag: '[ INFO ]', tone: 'info' },
}

interface TerminalLineProps {
  onViewChange: (view: TerminalView) => void
  /** About is an overlay of the side menu rather than a page. */
  onOpenAbout: () => void
}

/**
 * The Retro Terminal's status line, as a working command line: type a command and press Enter (see
 * terminalCommands.ts). The reply takes the place of the status for a few seconds; results of the
 * wizard are printed there too. Backtick focuses it from anywhere outside a text field, Escape leaves
 * it, arrow keys walk the history and Tab completes. `shutdown` switches the tube off until a key.
 */
export function TerminalLine({ onViewChange, onOpenAbout }: TerminalLineProps) {
  const { setTheme, setSound, setEffects } = useDesign()
  const inputRef = useRef<HTMLInputElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const pickSlot = useRef<FileSlot>('inputDocument')
  const [value, setValue] = useState('')
  const [message, setMessage] = useState<Message | null>(null)
  const [password, setPassword] = useState<TerminalReply['password']>()
  const history = useRef<string[]>([])
  const historyAt = useRef(0)
  const pending = useRef<WizardCommand | null>(null)
  const [power, setPower] = useState<'on' | 'off' | 'rebooting'>('on')
  const offRef = useRef<HTMLDivElement>(null)

  const timer = useRef(0)
  const show = useCallback((text: string, tone: Tone = 'info', ms = SHOW_MS) => {
    setMessage(text ? { text, tone } : null)
    window.clearTimeout(timer.current)
    if (text) timer.current = window.setTimeout(() => setMessage(null), ms)
  }, [])
  useEffect(() => () => window.clearTimeout(timer.current), [])

  const answer = useCallback((reply: { text: string; error?: boolean }) => {
    show(reply.text, reply.error ? 'error' : 'info', reply.error ? SHOW_ERROR_MS : SHOW_MS)
    emitCommandResult(!reply.error)
  }, [show])

  // Wizard results, and commands waiting for the wizard to be opened.
  useEffect(() => {
    const onSignal = (e: Event) => {
      const d = (e as CustomEvent<AppSignal>).detail
      if (d.type === 'outcome' && d.title) {
        const { tag, tone } = OUTCOME[d.kind]
        show(`${tag} ${d.title}${d.message ? ` — ${d.message}` : ''}`, tone, SHOW_OUTCOME_MS)
      } else if (d.type === 'step' && pending.current) {
        // The wizard emits its first step before it listens for commands, so send after this dispatch.
        const cmd = pending.current
        pending.current = null
        window.setTimeout(() => {
          const reply = emitCommand(cmd)
          if (reply) answer(reply)
        })
      }
    }
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    return () => window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
  }, [show, answer])

  // Scrolling shows where the view stands, like the pager in `less`. Read a frame later, once it moved.
  useEffect(() => {
    let frame = 0
    const onWheel = (e: WheelEvent) => {
      const scroller = scrollerOf(e.composedPath())
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        const at = scrollStatus(scroller.scrollTop, scroller.scrollHeight, scroller.clientHeight)
        if (at) show(at, 'info', SHOW_SCROLL_MS)
      })
    }
    window.addEventListener('wheel', onWheel, { passive: true })
    return () => {
      cancelAnimationFrame(frame)
      window.removeEventListener('wheel', onWheel)
    }
  }, [show])

  // Backtick focuses the line from anywhere but another text field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '`' || e.ctrlKey || e.metaKey || e.altKey) return
      const target = e.composedPath()[0]
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable)) return
      e.preventDefault()
      inputRef.current?.focus()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const powerOn = useCallback(() => {
    try {
      window.sessionStorage.removeItem(BOOTED_KEY)
    } catch {
      // Storage blocked: the boot log replays anyway, ThemeEffects counts the start-ups.
    }
    document.documentElement.classList.remove('app-poweroff')
    setPower('on')
    emitChrome('startup')
    window.setTimeout(() => inputRef.current?.focus(), 0)
  }, [])

  const powerOff = useCallback((mode: 'shutdown' | 'reboot') => {
    inputRef.current?.blur()
    document.documentElement.classList.add('app-poweroff')
    emitChrome('shutdown')
    window.setTimeout(() => setPower(mode === 'reboot' ? 'rebooting' : 'off'), POWER_OFF_MS)
  }, [])

  // While off, any key or click powers on again; listening starts a moment late, so the Enter that
  // ran `shutdown` does not switch it straight back on. A reboot comes back by itself.
  useEffect(() => {
    if (power === 'on') return
    if (power === 'rebooting') {
      const t = window.setTimeout(powerOn, REBOOT_DARK_MS)
      return () => window.clearTimeout(t)
    }
    offRef.current?.focus()
    const wake = (e: Event) => {
      e.preventDefault()
      powerOn()
    }
    const arm = window.setTimeout(() => {
      window.addEventListener('keydown', wake, { once: true })
      window.addEventListener('pointerdown', wake, { once: true })
    }, WAKE_ARM_MS)
    return () => {
      window.clearTimeout(arm)
      window.removeEventListener('keydown', wake)
      window.removeEventListener('pointerdown', wake)
    }
  }, [power, powerOn])
  // Leaving the theme while off must not leave the page collapsed.
  useEffect(() => () => document.documentElement.classList.remove('app-poweroff'), [])

  const ctx: TerminalContext = {
    wizard: emitCommand,
    navigate: view => (view === 'about' ? onOpenAbout() : onViewChange(view)),
    // Inside the Enter key press, so the browser lets the chooser open.
    pickFile: (slot, accept) => {
      const input = fileRef.current
      if (!input) return
      pickSlot.current = slot
      input.accept = accept
      input.value = ''
      input.click()
    },
    setTheme,
    setSound: on => setSound(on ? 'on' : 'off'),
    setEffects,
    power: powerOff,
  }

  const onFile = () => {
    const file = fileRef.current?.files?.[0]
    if (!file) return
    const cmd: WizardCommand = { type: 'file', slot: pickSlot.current, file }
    const reply = emitCommand(cmd)
    if (reply) answer(reply)
    else {
      pending.current = cmd
      onViewChange('wizard')
    }
  }

  const submit = () => {
    const line = value
    setValue('')
    if (password) {
      // Never echoed, never kept.
      setPassword(undefined)
      const reply = emitCommand({ type: 'set', key: password, value: line })
      answer(reply ?? { text: 'open sign / verify first (cd sign)', error: true })
      return
    }
    if (line.trim() && history.current[history.current.length - 1] !== line) {
      history.current = [...history.current, line].slice(-HISTORY_MAX)
    }
    historyAt.current = history.current.length
    const reply = interpret(line, ctx)
    if (reply.retry) pending.current = reply.retry
    if (reply.password) setPassword(reply.password)
    if (reply.clear) {
      show('')
      return
    }
    answer(reply)
  }

  const onKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'Enter':
        e.preventDefault()
        submit()
        break
      case 'Escape':
        if (password) {
          setPassword(undefined)
          setValue('')
          show('password cancelled')
        }
        inputRef.current?.blur()
        break
      case 'Tab': {
        if (password || !value.trim()) return
        e.preventDefault()
        const done = complete(value)
        setValue(done.line)
        if (done.matches.length > 1) show(done.matches.join('  '))
        break
      }
      case 'ArrowUp':
      case 'ArrowDown': {
        if (password) return
        e.preventDefault()
        const list = history.current
        const at = Math.max(0, Math.min(list.length, historyAt.current + (e.key === 'ArrowUp' ? -1 : 1)))
        historyAt.current = at
        setValue(list[at] ?? '')
        break
      }
    }
  }

  return (
    <>
      <div className="tty">
        <label className="tty-prompt" htmlFor="tty-input">{password ? 'password:' : 'operator@cades-lt:~$'}</label>
        <input
          ref={inputRef}
          id="tty-input"
          className="tty-input"
          type={password ? 'password' : 'text'}
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={onKeyDown}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          aria-describedby="tty-mode"
          title="Type a command; help lists them. Backtick focuses this line."
        />
        <span id="tty-mode" className="tty-mode" role="status" data-tone={message?.tone} title={message?.text}>
          {message?.text}
        </span>
        <input ref={fileRef} type="file" hidden onChange={onFile} tabIndex={-1} aria-hidden="true" />
      </div>
      {power !== 'on' && (
        <div
          ref={offRef}
          className="tty-off"
          role="dialog"
          aria-modal="true"
          aria-label="Terminal switched off"
          tabIndex={-1}
        >
          {power === 'off' && <p><span className="tty-off-cursor">_</span> Press any key to power on</p>}
        </div>
      )}
    </>
  )
}
