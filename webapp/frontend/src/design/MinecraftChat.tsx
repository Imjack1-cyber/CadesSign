import { type KeyboardEvent as ReactKeyboardEvent, useCallback, useEffect, useRef, useState } from 'react'
import { type ChatActions, minecraftCommand } from './minecraftCommands'
import { unlock } from './minecraftState'
import { type CommandReply, type FileSlot, emitCommand, emitCommandResult } from './signals'
import { type TerminalContext, type TerminalReply, type TerminalView, interpret } from './terminalCommands'
import { useDesign } from './useDesign'
import { useWizardCommand } from './useWizardCommand'

/** How long a line stays in the log once the chat is closed. */
export const CHAT_LINE_MS = 8000
const LOG_MAX = 50
const HISTORY_MAX = 30

type Tone = 'say' | 'info' | 'error'

interface Line {
  id: number
  text: string
  tone: Tone
  at: number
}

interface MinecraftChatProps extends ChatActions {
  onViewChange: (view: TerminalView) => void
  onOpenAbout: () => void
  /** Another screen of the HUD is open: the chat keys stay off. */
  disabled?: boolean
}

/**
 * The Minecraft theme's chat: T or / outside a text field opens a line at the bottom left; Enter runs
 * it, Escape closes it, the arrow keys walk the history. Replies stay in a log that fades a few
 * seconds after the chat is closed, as in the game.
 */
export function MinecraftChat({ onViewChange, onOpenAbout, disabled, ...actions }: MinecraftChatProps) {
  const { setTheme, setSound, setEffects } = useDesign()
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')
  const [log, setLog] = useState<Line[]>([])
  const [now, setNow] = useState(() => Date.now())
  const inputRef = useRef<HTMLInputElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const pickSlot = useRef<FileSlot>('inputDocument')
  const history = useRef<string[]>([])
  const historyAt = useRef(0)
  const nextId = useRef(0)

  const say = useCallback((text: string, tone: Tone) => {
    if (!text) return
    setLog((l: Line[]) => [...l, { id: nextId.current++, text, tone, at: Date.now() }].slice(-LOG_MAX))
    setNow(Date.now())
  }, [])

  const answer = useCallback((reply: CommandReply) => {
    say(reply.text, reply.error ? 'error' : 'info')
    emitCommandResult(!reply.error)
  }, [say])

  const wizard = useWizardCommand(() => onViewChange('wizard'), answer)

  // T or / opens the chat from anywhere outside a text field.
  useEffect(() => {
    if (disabled) return
    const onKey = (e: KeyboardEvent) => {
      if (open || e.ctrlKey || e.metaKey || e.altKey) return
      if (e.key !== 't' && e.key !== 'T' && e.key !== '/') return
      const target = e.composedPath()[0]
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable)) return
      e.preventDefault()
      setValue(e.key === '/' ? '/' : '')
      setOpen(true)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, disabled])

  useEffect(() => {
    if (open) inputRef.current?.focus()
  }, [open])

  // Lines fade a few seconds after they were said; a tick re-renders while any is still showing.
  useEffect(() => {
    if (open || !log.some((l: Line) => now - l.at < CHAT_LINE_MS)) return
    const t = window.setTimeout(() => setNow(Date.now()), 1000)
    return () => window.clearTimeout(t)
  }, [open, log, now])

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
    power: () => say('There is no power button in this world', 'error'),
  }

  const onFile = () => {
    const file = fileRef.current?.files?.[0]
    if (file) wizard.send({ type: 'file', slot: pickSlot.current, file })
  }

  const close = () => {
    setOpen(false)
    setValue('')
    setNow(Date.now())
  }

  const submit = () => {
    const line = value.trim()
    close()
    if (!line || line === '/') return
    history.current = [...history.current.filter((h: string) => h !== line), line].slice(-HISTORY_MAX)
    historyAt.current = history.current.length
    if (!line.startsWith('/')) {
      // Plain text is said aloud.
      say(`<Steve> ${line}`, 'say')
      return
    }
    say(line, 'say')
    unlock('chatty')
    const mine = minecraftCommand(line, actions)
    if (mine) {
      answer(mine)
      return
    }
    const reply: TerminalReply = interpret(line.slice(1), ctx)
    if (reply.retry) wizard.later(reply.retry)
    if (reply.password) {
      say('Passwords are set in the wizard, not in the chat', 'error')
      return
    }
    if (!reply.clear) answer(reply)
  }

  const onKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'Enter':
        e.preventDefault()
        submit()
        return
      case 'Escape':
        e.preventDefault()
        e.stopPropagation()
        close()
        return
      case 'ArrowUp':
      case 'ArrowDown': {
        e.preventDefault()
        const h = history.current
        if (!h.length) return
        historyAt.current = Math.max(0, Math.min(h.length, historyAt.current + (e.key === 'ArrowUp' ? -1 : 1)))
        setValue(h[historyAt.current] ?? '')
      }
    }
  }

  const shown = open ? log.slice(-10) : log.filter((l: Line) => now - l.at < CHAT_LINE_MS).slice(-6)

  return (
    <div className="mc-chat" data-open={open || undefined}>
      <ol className="mc-chat-log" aria-live="polite" aria-label="Chat messages">
        {shown.map((l: Line) => (
          <li key={l.id} data-tone={l.tone} style={open ? undefined : { '--age': (now - l.at) / CHAT_LINE_MS } as React.CSSProperties}>
            {l.text}
          </li>
        ))}
      </ol>
      {open && (
        <input
          ref={inputRef}
          className="mc-chat-input"
          aria-label="Chat"
          value={value}
          spellCheck={false}
          autoComplete="off"
          onChange={e => setValue(e.target.value)}
          onKeyDown={onKeyDown}
          onBlur={() => window.setTimeout(close, 0)}
        />
      )}
      <input ref={fileRef} type="file" hidden onChange={onFile} tabIndex={-1} aria-hidden="true" />
    </div>
  )
}
