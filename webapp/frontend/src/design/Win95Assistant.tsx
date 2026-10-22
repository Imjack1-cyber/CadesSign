import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { APP_SIGNAL_EVENT, type AppSignal, emitChrome, GENERATED_EVENT } from './signals'
import { useDesign } from './useDesign'

interface Choice {
  label: string
  run: () => void
}

interface Message {
  text: string
  choices?: Choice[]
}

type Mood = 'idle' | 'talk' | 'think' | 'cheer' | 'oops'

interface Win95AssistantProps {
  onHide: () => void
  onOpenDocuments: () => void
}

const LEVELS =
  'B-B is the signature alone. B-T adds a timestamp from a trusted authority, proving when you signed. ' +
  'B-LT also packs in the certificates and the revocation answers (OCSP or CRL) needed to check it years later. ' +
  'B-LTA adds archive timestamps on top, renewed before the cryptography gets weak.'

const TIPS = [
  'A detached signature lives in its own .p7s file; keep the original next to it. Enveloping puts the document inside the signature.',
  'B-LT signatures stay checkable after the certificate expires, because the proof of validity travels with them.',
  'OCSP asks a server whether a certificate was revoked; a CRL is the whole list of revoked certificates.',
  'Your keystore holds your private key. Keep it somewhere safe, and keep its password somewhere else.',
  'Drag any window by its title bar. Drop it on the taskbar to minimize it.',
  'Press Ctrl+Esc to open the Start menu, just like in 1995.',
  'Everything you sign or verify is filed in My Documents, on the desktop.',
  'Closed a window by mistake? Double-click the Recycle Bin to get it back.',
  'A timestamp proves the signature existed at that moment, even if your certificate is revoked later.',
]

const STEP_TIPS: Record<string, string> = {
  '1': "Hi, I'm Paperclip! Do you want to sign a document or check a signature? Pick one, then press Next.",
  '2sign': "It looks like you're signing a document. Would you like help? Choose the file, and your keystore if you have one.",
  '2verify': "It looks like you're checking a signature. Give me the .p7s file, plus the original if the signature is detached.",
  '3': 'Decisions, decisions. B-LT is a good default: the signature can still be checked long after today.',
  '4': "Everything look right? Press the button and I'll get to work.",
}

/** How long a message without choices stays up, and the least time between unprompted tips. */
const SAY_MS = 9000
const IDLE_TIP_MS = 45_000

/**
 * Paperclip, the Windows 95 theme's assistant: an animated paperclip on the desktop whose eyes follow
 * the pointer. It comments on the wizard's steps, requests and results, files saved to My Documents,
 * windows going to the Recycle Bin and frantic typing; offers to show error details; and when left
 * alone (at the Wild level) shares a tip now and then. Click it for its menu, drag it anywhere, and
 * hide it there or bring it back from the Start menu. Speech is announced politely.
 */
export function Win95Assistant({ onHide, onOpenDocuments }: Win95AssistantProps) {
  const { effects } = useDesign()
  const wild = effects === 'wild'
  const [message, setMessage] = useState<Message | null>(null)
  const [mood, setMood] = useState<Mood>('idle')
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)
  const [eyes, setEyes] = useState({ x: 0, y: 0 })
  const rootRef = useRef<HTMLDivElement>(null)
  const lastSaid = useRef(0)
  const timer = useRef(0)
  const tipsLeft = useRef<string[]>([])
  const once = useRef(new Set<string>())
  const busy = useRef(false)
  const busyTimer = useRef(0)
  const lastStep = useRef('')
  const action = useRef('')
  /** A file was saved during a request; mentioned when the request ends, unless a result said so. */
  const savedFile = useRef(false)
  const drag = useRef<{ x: number; y: number; left: number; top: number; moved: boolean } | null>(null)

  const say = useCallback((text: string, nextMood: Mood = 'talk', choices?: Choice[]) => {
    window.clearTimeout(timer.current)
    setMessage({ text, choices })
    setMood(nextMood)
    lastSaid.current = Date.now()
    emitChrome('assistant')
    if (!choices) {
      timer.current = window.setTimeout(() => {
        setMessage(null)
        setMood('idle')
      }, SAY_MS)
    }
  }, [])

  const close = useCallback(() => {
    window.clearTimeout(timer.current)
    setMessage(null)
    setMood('idle')
  }, [])

  /** Says something once per session only. */
  const sayOnce = useCallback((key: string, text: string, nextMood?: Mood, choices?: Choice[]) => {
    if (once.current.has(key)) return
    once.current.add(key)
    say(text, nextMood, choices)
  }, [say])

  const tip = useCallback(() => {
    if (!tipsLeft.current.length) tipsLeft.current = [...TIPS].sort(() => Math.random() - 0.5)
    say(tipsLeft.current.pop()!, 'talk')
  }, [say])

  const showDetails = useCallback(() => {
    const details = document.querySelector<HTMLDetailsElement>('.technical-details')
    if (details) {
      details.open = true
      details.scrollIntoView({ behavior: 'smooth', block: 'center' })
      say('There you go. The technical details are open below the result.', 'talk')
    } else say('There are no extra details this time; the message above is all the server said.', 'talk')
  }, [say])

  // The app's own news: wizard steps, requests, results and the theme's chrome.
  useEffect(() => {
    const onSignal = (e: Event) => {
      const d = (e as CustomEvent<AppSignal>).detail
      if (d.type === 'step') {
        action.current = d.action
        const key = d.step === 2 ? `2${d.action}` : String(d.step)
        if (key === lastStep.current) return
        lastStep.current = key
        if (STEP_TIPS[key]) say(STEP_TIPS[key], 'talk')
      } else if (d.type === 'busy') {
        busy.current = d.on
        window.clearTimeout(busyTimer.current)
        if (d.on) {
          // Only for requests that take a moment.
          busyTimer.current = window.setTimeout(
            () => say("Working on it... If there's a timestamp to fetch, I have to dial out to the authority. Hold on!", 'think'),
            800,
          )
          return
        }
        setMood((m: Mood) => (m === 'think' ? 'idle' : m))
        if (savedFile.current) {
          savedFile.current = false
          if (Date.now() - lastSaid.current > 300) sayFiled()
        }
      } else if (d.type === 'outcome') {
        const signed = action.current === 'sign'
        if (d.kind === 'success') {
          say(signed ? 'Congratulations, your document is signed! I filed a copy in My Documents.' : 'Good news: the signature checks out!', 'cheer',
            signed ? [{ label: 'Open My Documents', run: () => { close(); onOpenDocuments() } }, { label: 'Thanks!', run: close }] : undefined)
        } else if (d.kind === 'warning') {
          say("Hmm. It worked, but not everything checked out. Have a look at the details below; they say what's missing.", 'think')
        } else if (d.kind === 'error') {
          say("Oops! That didn't work. Would you like to see the technical details?", 'oops', [
            { label: 'Show me the details', run: showDetails },
            { label: 'No thanks', run: close },
          ])
        } else say("Done. Here's what the server had to say.", 'talk')
      } else if (d.type === 'chrome') {
        if (d.event === 'close') sayOnce('close', 'Closed windows wait in the Recycle Bin. Double-click it to get them back.')
        else if (d.event === 'minimize') sayOnce('minimize', 'Minimized windows wait on the taskbar. Click one to bring it back.')
      }
    }
    const sayFiled = () => say('I put a copy in My Documents, in case you need it again.', 'talk', [
      { label: 'Open My Documents', run: () => { close(); onOpenDocuments() } },
      { label: 'OK', run: close },
    ])
    const onGenerated = () => {
      if (busy.current) savedFile.current = true
      else sayFiled()
    }
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    window.addEventListener(GENERATED_EVENT, onGenerated)
    return () => {
      window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
      window.removeEventListener(GENERATED_EVENT, onGenerated)
    }
  }, [say, sayOnce, close, onOpenDocuments, showDetails])

  // Typing, the classic opening line; typing frantically, a concerned one.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const field = e.composedPath()[0]
      if (e.key.length !== 1 || e.ctrlKey || e.metaKey) return
      if (!(field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) || rootRef.current?.contains(field)) return
      sayOnce('letter', "It looks like you're writing a letter. Would you like help?", 'talk', [
        { label: 'Get help with writing the letter', run: () => say("Just kidding, it's a form field. You're doing great.", 'cheer') },
        { label: 'Just type the letter without help', run: close },
      ])
    }
    const root = document.documentElement
    const observer = new MutationObserver(() => {
      if (root.classList.contains('app-lag')) {
        say("Whoa, slow down! I can't keep up. It looks like you're in a hurry. Would you like help?", 'oops', [
          { label: 'Yes, slow me down', run: () => say('Deep breath. The app will catch up in a second.', 'talk') },
          { label: 'No', run: close },
        ])
      }
    })
    observer.observe(root, { attributes: true, attributeFilter: ['class'] })
    window.addEventListener('keydown', onKey, true)
    return () => {
      observer.disconnect()
      window.removeEventListener('keydown', onKey, true)
    }
  }, [say, sayOnce, close])

  // Left alone at the Wild level, it shares a tip now and then.
  useEffect(() => {
    if (!wild) return
    const id = window.setInterval(() => {
      if (busy.current || document.hidden || Date.now() - lastSaid.current < IDLE_TIP_MS) return
      tip()
    }, 5000)
    return () => window.clearInterval(id)
  }, [wild, tip])

  // Its eyes follow the pointer, at the Wild level only.
  useEffect(() => {
    if (!wild) return
    let frame = 0
    const onMove = (e: PointerEvent) => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        const r = rootRef.current?.querySelector('.w95-clip')?.getBoundingClientRect()
        if (!r) return
        const dx = e.clientX - (r.left + r.width / 2)
        const dy = e.clientY - (r.top + r.height * 0.3)
        const d = Math.hypot(dx, dy) || 1
        setEyes({ x: (dx / d) * Math.min(2.2, d / 40), y: (dy / d) * Math.min(2.2, d / 40) })
      })
    }
    window.addEventListener('pointermove', onMove, { passive: true })
    return () => {
      cancelAnimationFrame(frame)
      window.removeEventListener('pointermove', onMove)
    }
  }, [wild])

  useEffect(() => () => {
    window.clearTimeout(timer.current)
    window.clearTimeout(busyTimer.current)
  }, [])

  // Without Wild motion the eyes look straight ahead.
  const look = wild ? eyes : { x: 0, y: 0 }

  const menu = () => say('What would you like to do?', 'talk', [
    { label: 'Explain the signature levels', run: () => say(LEVELS, 'talk') },
    { label: 'Open My Documents', run: () => { close(); onOpenDocuments() } },
    { label: 'Tell me a tip', run: tip },
    { label: 'Hide Paperclip', run: onHide },
  ])

  const onDown = (e: ReactPointerEvent<HTMLButtonElement>) => {
    if (e.button !== 0) return
    const r = rootRef.current!.getBoundingClientRect()
    e.currentTarget.setPointerCapture?.(e.pointerId)
    drag.current = { x: e.clientX, y: e.clientY, left: r.left, top: r.top, moved: false }
  }
  const onMove = (e: ReactPointerEvent) => {
    const d = drag.current
    if (!d) return
    const dx = e.clientX - d.x
    const dy = e.clientY - d.y
    if (!d.moved && Math.hypot(dx, dy) < 4) return
    d.moved = true
    setPos({
      x: Math.min(Math.max(0, d.left + dx), window.innerWidth - 60),
      y: Math.min(Math.max(0, d.top + dy), window.innerHeight - 100),
    })
  }
  const onUp = () => {
    const d = drag.current
    drag.current = null
    if (d && !d.moved) {
      if (message?.choices && message.text === 'What would you like to do?') close()
      else menu()
    }
  }

  return (
    <div
      ref={rootRef}
      className={`w95-assistant w95-assistant--${mood}`}
      style={pos ? { left: pos.x, top: pos.y, right: 'auto', bottom: 'auto' } : undefined}
    >
      <div className="w95-balloon" role="status" aria-live="polite" hidden={!message}>
        {message && (
          <>
            <button type="button" className="w95-balloon-close" aria-label="Close balloon" onClick={close} />
            <p>{message.text}</p>
            {message.choices && (
              <ul>
                {message.choices.map(c => (
                  <li key={c.label}>
                    <button type="button" onClick={c.run}>{c.label}</button>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
      <button
        type="button"
        className="w95-clip"
        aria-label="Paperclip, your assistant"
        aria-haspopup="true"
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerCancel={() => { drag.current = null }}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            menu()
          }
        }}
      >
        <svg viewBox="0 0 80 112" width="80" height="112" aria-hidden="true">
          <g className="clip-paper">
            <path d="M6 90l64-6 4 22-64 6z" fill="#fff8c8" stroke="#8a7a40" />
            <path d="M14 96l50-5M15 101l50-5M16 106l40-4" stroke="#c8b870" />
          </g>
          <g className="clip-body">
            <path className="clip-wire" d="M24 62V24a14 14 0 0 1 28 0v62a12 12 0 0 1-24 0V32a8 8 0 0 1 16 0v46" />
            <path className="clip-shine" d="M24 62V24a14 14 0 0 1 28 0v62a12 12 0 0 1-24 0V32a8 8 0 0 1 16 0v46" />
            <g className="clip-brows">
              <path d="M22 26q6-5 12-1" />
              <path d="M42 25q6-4 12 1" />
            </g>
            <g className="clip-eyes">
              <ellipse cx="29" cy="34" rx="7" ry="8" fill="#fff" stroke="#333" />
              <ellipse cx="48" cy="34" rx="7" ry="8" fill="#fff" stroke="#333" />
              <circle cx={30 + look.x} cy={35 + look.y} r="3" fill="#111" />
              <circle cx={47 + look.x} cy={35 + look.y} r="3" fill="#111" />
              <circle cx={31 + look.x} cy={34 + look.y} r="1" fill="#fff" />
              <circle cx={48 + look.x} cy={34 + look.y} r="1" fill="#fff" />
            </g>
          </g>
        </svg>
      </button>
    </div>
  )
}
