import { useCallback, useEffect, useRef, useState } from 'react'
import { useGeneratedFiles } from './generatedFiles'
import { MinecraftChat } from './MinecraftChat'
import { MinecraftGame } from './MinecraftGame'
import { DeathScreen, MinecraftAdvancements, MinecraftChest, type Operation, PlayerList } from './MinecraftScreens'
import {
  ADVANCEMENTS, type AdvancementId, type GameId, type GameMode, MC_STATE_EVENT, type McChange, XP_FOR, addXp, readGameMode,
  readRecords, readXp, unlock, xpToNext,
} from './minecraftState'
import { APP_SIGNAL_EVENT, type AppSignal, GENERATED_EVENT, emitChrome, emitCommand } from './signals'
import type { TerminalView } from './terminalCommands'

/** Typed on the page outside any text field, this word opens the minigames. */
export const EASTER_EGG = 'creeper'
export const MAX_HEARTS = 10
/** How long an advancement stays up, and a lost heart shakes. */
export const TOAST_MS = 4000
const HURT_MS = 600
/** The level that earns "Getting an Upgrade". */
const UPGRADE_LEVEL = 5

/** A creeper's face, for the browser tab while the theme is on. */
const FAVICON = `data:image/svg+xml,${encodeURIComponent(
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 8 8' shape-rendering='crispEdges'><path fill='#5aa53a' d='M0 0h8v8H0z'/>" +
  "<path fill='#3f8a2a' d='M0 0h1v1H0zM5 0h1v1H5zM7 3h1v1H7zM2 7h1v1H2z'/><path fill='#111' d='M1 2h2v2H1zM5 2h2v2H5zM3 4h2v1H3zM2 5h4v2H2z'/>" +
  "<path fill='#5aa53a' d='M3 6h2v1H3z'/></svg>",
)}`

interface Toast {
  n: number
  heading: string
  title: string
}

/** True when a key press went to a text field (or anything typed into). */
const typing = (e: KeyboardEvent) => {
  const target = e.composedPath()[0]
  return target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement ||
    (target instanceof HTMLElement && target.isContentEditable)
}

interface MinecraftHudProps {
  onViewChange: (view: TerminalView) => void
  onOpenAbout: () => void
}

/**
 * The Minecraft theme's HUD along the bottom: hearts, the XP bar and the level. Results earn XP
 * (levelling up as in the game); a failure costs a heart, the next success heals one, and in survival
 * mode a failure shows the death screen. Advancements pop up as toasts. While a request runs the XP bar
 * fills and empties (themes.css, under .app-mine). Beside the bar: the minigames, the chest of
 * generated files and the advancements. Keys outside text fields: 1-5 jump along the wizard's steps
 * like a hotbar, T or / opens the chat, held Tab shows this session's operations, and typing
 * "creeper" opens the minigames.
 */
export function MinecraftHud({ onViewChange, onOpenAbout }: MinecraftHudProps) {
  const [xp, setXp] = useState(readXp)
  const [hearts, setHearts] = useState(MAX_HEARTS)
  const [hurt, setHurt] = useState(0)
  const [mode, setMode] = useState<GameMode>(readGameMode)
  const [toasts, setToasts] = useState<Toast[]>([])
  const [playing, setPlaying] = useState<GameId | true | false>(false)
  const [chest, setChest] = useState(false)
  const [advancements, setAdvancements] = useState(false)
  const [death, setDeath] = useState<{ title?: string; message?: string } | null>(null)
  const [players, setPlayers] = useState(false)
  const [records, setRecords] = useState(readRecords)
  const [operations, setOperations] = useState<Operation[]>([])
  const step = useRef(1)
  const lastBusy = useRef<{ action?: string; level?: string }>({})
  const toastN = useRef(0)
  const opener = useRef<HTMLButtonElement>(null)
  // Remembers what the app generates while the theme is on, for the chest.
  const store = useGeneratedFiles()

  const toast = useCallback((heading: string, title: string) => {
    setToasts((ts: Toast[]) => [...ts, { n: ++toastN.current, heading, title }])
  }, [])

  // Results: XP, hearts, advancements, the death screen.
  useEffect(() => {
    const onSignal = (e: Event) => {
      const d = (e as CustomEvent<AppSignal>).detail
      if (d.type === 'busy' && d.on) lastBusy.current = { action: d.action, level: d.level }
      if (d.type === 'step') step.current = d.step
      if (d.type !== 'outcome') return
      setOperations((ops: Operation[]) => [...ops, { kind: d.kind, title: d.title || d.kind, action: d.action, at: Date.now() }])
      addXp(XP_FOR[d.kind])
      if (d.kind === 'success') {
        setHearts((n: number) => Math.min(MAX_HEARTS, n + 1))
        toast('Advancement Made!', d.title || 'Done')
        if (d.action === 'sign') unlock('stone-age')
        if (d.action === 'verify') unlock('iron-pick')
        if (d.action === 'sign' && lastBusy.current.level === 'LTA') unlock('diamonds')
      } else if (d.kind === 'error' && readGameMode() === 'survival') {
        setHearts((n: number) => Math.max(0, n - 1))
        setHurt((n: number) => n + 1)
        unlock('ouch')
        setDeath({ title: d.title, message: d.message })
      }
    }
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    return () => window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
  }, [toast])

  // XP, advancements and the game mode, from wherever they changed (here, the chat, the minigames).
  useEffect(() => {
    const onChange = (e: Event) => {
      const d = (e as CustomEvent<McChange>).detail
      if (d.kind === 'xp') {
        const now = readXp()
        setXp(now)
        if (now.level >= UPGRADE_LEVEL) unlock('upgrade')
      } else if (d.kind === 'advancement') {
        toast('Advancement Made!', ADVANCEMENTS.find(a => a.id === (d.id as AdvancementId))?.title ?? d.id)
      } else if (d.kind === 'gamemode') setMode(d.mode)
    }
    const onGenerated = () => unlock('treasure')
    window.addEventListener(MC_STATE_EVENT, onChange)
    window.addEventListener(GENERATED_EVENT, onGenerated)
    return () => {
      window.removeEventListener(MC_STATE_EVENT, onChange)
      window.removeEventListener(GENERATED_EVENT, onGenerated)
    }
  }, [toast])

  // One toast at a time.
  useEffect(() => {
    if (!toasts.length) return
    const t = window.setTimeout(() => setToasts((ts: Toast[]) => ts.slice(1)), TOAST_MS)
    return () => window.clearTimeout(t)
  }, [toasts])

  // A lost heart shakes for a moment.
  useEffect(() => {
    if (!hurt) return
    const t = window.setTimeout(() => setHurt(0), HURT_MS)
    return () => window.clearTimeout(t)
  }, [hurt])

  // The creeper face in the browser tab, the page's own icon back afterwards.
  useEffect(() => {
    const link = document.querySelector<HTMLLinkElement>('link[rel~="icon"]') ?? Object.assign(document.createElement('link'), { rel: 'icon' })
    const before = link.getAttribute('href')
    if (!link.isConnected) document.head.append(link)
    link.href = FAVICON
    return () => {
      if (before) link.setAttribute('href', before)
      else link.remove()
    }
  }, [])

  const screenOpen = playing !== false || chest || advancements || death !== null

  // Keys outside text fields: the hotbar 1-5, held Tab, and the "creeper" easter egg.
  useEffect(() => {
    if (screenOpen) return
    let typed = ''
    const down = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || typing(e)) return
      if (e.key === 'Tab') {
        // Only shown; Tab still moves focus.
        setPlayers(true)
        return
      }
      if (/^[1-5]$/.test(e.key)) {
        gotoStep(Number(e.key), step.current)
        return
      }
      if (e.key.length !== 1) return
      typed = (typed + e.key.toLowerCase()).slice(-EASTER_EGG.length)
      if (typed === EASTER_EGG) {
        typed = ''
        setPlaying(true)
      }
    }
    const up = (e: KeyboardEvent) => {
      if (e.key === 'Tab') setPlayers(false)
    }
    const blur = () => setPlayers(false)
    window.addEventListener('keydown', down)
    window.addEventListener('keyup', up)
    window.addEventListener('blur', blur)
    return () => {
      window.removeEventListener('keydown', down)
      window.removeEventListener('keyup', up)
      window.removeEventListener('blur', blur)
    }
  }, [screenOpen])

  // The chest and advancements open over the app, like the game's own screens.
  useEffect(() => {
    if (!chest && !advancements) return
    emitChrome('sheet-open')
    return () => emitChrome('sheet-close')
  }, [chest, advancements])

  const closeGame = useCallback(() => {
    setPlaying(false)
    setRecords(readRecords())
    window.setTimeout(() => opener.current?.focus(), 0)
  }, [])

  const need = xpToNext(xp.level)
  const best = [['mining', 'Mining Run'], ['runner', 'Creeper Run'], ['crafting', 'Crafting']]
    .map(([id, label]) => `${label}: ${records[id as GameId] ?? '-'}`).join(' · ')

  return (
    <>
      <div className="mc-hud" role="group" aria-label="Status" data-mode={mode}>
        {mode === 'creative' ? (
          <span className="mc-creative">Creative Mode</span>
        ) : (
          <span className="mc-hearts" aria-label={`Hearts ${hearts}`} data-hurt={hurt ? true : undefined}>
            {Array.from({ length: MAX_HEARTS }, (_, i) => <i key={i} data-full={i < hearts || undefined} />)}
          </span>
        )}
        <span className="mc-level" key={xp.level} aria-label={`Level ${xp.level}`}>{xp.level}</span>
        <span className="mc-xpbar" aria-label={`Experience ${xp.points} of ${need}`} role="img">
          <i style={{ width: `${(xp.points / need) * 100}%` }} />
        </span>
        <span className="mc-hud-buttons">
          <button type="button" className="mc-play" onClick={() => setAdvancements(true)} aria-haspopup="dialog" title="Advancements">
            <span aria-hidden="true">★</span><span className="mc-sr">Advancements</span>
          </button>
          <button type="button" className="mc-play" onClick={() => setChest(true)} aria-haspopup="dialog" title="Chest: the files you made">
            Chest
          </button>
          <button
            ref={opener}
            type="button"
            className="mc-play"
            onClick={() => setPlaying(true)}
            aria-haspopup="dialog"
            title={`Play the minigames (or type "${EASTER_EGG}"). Best: ${best}`}
          >
            Play
          </button>
        </span>
      </div>
      <div className="mc-toast-slot" role="status">
        {toasts[0] && (
          <div className="mc-toast" key={toasts[0].n}>
            <span className="mc-toast-icon" aria-hidden="true" />
            <span>
              <b>{toasts[0].heading}</b>
              <span>{toasts[0].title}</span>
            </span>
          </div>
        )}
      </div>
      <MinecraftChat
        onViewChange={onViewChange}
        onOpenAbout={onOpenAbout}
        disabled={screenOpen}
        openGame={g => setPlaying(g ?? true)}
        openChest={() => setChest(true)}
        openAdvancements={() => setAdvancements(true)}
      />
      {players && <PlayerList operations={operations} />}
      {chest && <MinecraftChest store={store} onClose={() => setChest(false)} />}
      {advancements && <MinecraftAdvancements onClose={() => setAdvancements(false)} />}
      {death && (
        <DeathScreen
          title={death.title}
          message={death.message}
          score={xp.level}
          onClose={() => setDeath(null)}
          onRespawn={() => {
            setDeath(null)
            emitCommand({ type: 'run' })
          }}
          onTitle={() => {
            setDeath(null)
            emitCommand({ type: 'reset' })
          }}
        />
      )}
      {playing !== false && <MinecraftGame onClose={closeGame} initial={playing === true ? undefined : playing} />}
    </>
  )
}

/**
 * The hotbar keys: a done step is clicked on the step rail (the wizard lets only those be revisited),
 * the next one is Next; others stay where they are.
 */
function gotoStep(n: number, current: number) {
  if (n === current + 1) {
    emitCommand({ type: 'next' })
    return
  }
  if (n >= current) return
  const el = document.querySelectorAll<HTMLElement>('.wizard-steps ix-workflow-step')[n - 1]
  const target = el?.shadowRoot?.querySelector<HTMLElement>('[role=button]') ?? el
  target?.click()
}
