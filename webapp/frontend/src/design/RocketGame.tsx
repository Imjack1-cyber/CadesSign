import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { type Bit, burstBits, drawBits, spawnBit, stepBits } from './effects/bits'
import { BLUE, ORANGE, drawBall, drawCar } from './effects/rocket'
import { type Sound, createSound } from './effects/sound'
import {
  ARENA_H, ARENA_W, BALL_R, CAR_HH, CAR_HL, DIFFICULTIES, type Difficulty, GOAL_D, GOAL_H, type Input, type Match,
  STEP, type Team, axes, botInput, createMatch, createMind, isSupersonic, speedOf, stepMatch, tick,
} from './rocketGame'
import { emitChrome } from './signals'
import { trapFocus } from './trapFocus'
import { useDesign } from './useDesign'

const RECORD_KEY = 'cades-rocket-record'
const CORNER_R = 140
const TEAM = ['Blue', 'Orange'] as const
const COLOR = [BLUE, ORANGE] as const
/** The narrowest stretch of arena the camera shows, in arena units; a phone held upright follows the play. */
const MIN_VIEW = 1000
/** Seconds between two boost roars while boost is held. */
const ROAR_S = 0.3

type Screen = 'menu' | 'playing' | 'paused' | 'over'
type Record_ = Partial<Record<Difficulty, { w: number; l: number }>>

function readRecord(): Record_ {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(RECORD_KEY) ?? '{}')
    return parsed && typeof parsed === 'object' ? (parsed as Record_) : {}
  } catch {
    return {}
  }
}

function saveRecord(record: Record_) {
  try {
    window.localStorage.setItem(RECORD_KEY, JSON.stringify(record))
  } catch {
    // Storage blocked: the record lasts as long as the page.
  }
}

const clockText = (m: Match) => {
  const s = Math.ceil(m.clock)
  return `${m.overtime ? '+' : ''}${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

/** What the HUD shows; only re-rendered when one of these changes. */
interface Hud {
  score: [number, number]
  clock: string
  overtime: boolean
  boost: number
  banner: string
  bannerTeam?: Team
}

const hudOf = (m: Match, banner: string, bannerTeam?: Team): Hud => ({
  score: [...m.score], clock: clockText(m), overtime: m.overtime, boost: Math.round(m.cars[0].boost), banner, bannerTeam,
})

const sameHud = (a: Hud, b: Hud) =>
  a.score[0] === b.score[0] && a.score[1] === b.score[1] && a.clock === b.clock && a.overtime === b.overtime &&
  a.boost === b.boost && a.banner === b.banner && a.bannerTeam === b.bannerTeam

/** The keys the game uses, and what they do. */
const KEYS: Record<string, 'left' | 'right' | 'jump' | 'boost'> = {
  ArrowLeft: 'left', a: 'left', A: 'left',
  ArrowRight: 'right', d: 'right', D: 'right',
  ArrowUp: 'jump', w: 'jump', W: 'jump', ' ': 'jump', k: 'jump', K: 'jump',
  Shift: 'boost', j: 'boost', J: 'boost',
}

interface RocketGameProps {
  onClose: () => void
}

/**
 * The Rocket League theme's minigame: a Sideswipe 1v1 against a bot (rocketGame.ts plays it). A
 * modal over the whole app: a start screen to pick the bot's level, the match on a canvas with the
 * score, clock and boost as plain text around it, a pause menu on Esc and a result screen with the
 * match stats. Behind the menus two bots play on their own. On touch screens on-screen buttons stand
 * in for the keys.
 */
export function RocketGame({ onClose }: RocketGameProps) {
  const { soundPick } = useDesign()
  const dialogRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [screen, setScreen] = useState<Screen>('menu')
  const [difficulty, setDifficulty] = useState<Difficulty>('pro')
  const [record, setRecord] = useState<Record_>(readRecord)
  const [hud, setHud] = useState<Hud | null>(null)
  const [announce, setAnnounce] = useState('')
  const [result, setResult] = useState<Match | null>(null)

  const match = useRef<Match | null>(null)
  /** Bots playing behind the menus. */
  const attract = useRef<Match>(createMatch('allstar'))
  const attractMinds = useRef([createMind(), createMind()])
  const screenRef = useRef(screen)
  useEffect(() => {
    screenRef.current = screen
  }, [screen])
  const keys = useRef(new Set<'left' | 'right' | 'jump' | 'boost'>())
  const touches = useRef(new Map<number, 'left' | 'right' | 'jump' | 'boost'>())
  const sound = useRef<Sound | null>(null)

  // Audio of its own, following the user's sound pick, and the stadium hushed behind the game.
  useEffect(() => {
    emitChrome('game-open')
    return () => emitChrome('game-close')
  }, [])
  useEffect(() => {
    if (soundPick !== 'on') return
    const s = createSound()
    sound.current = s
    s.crowd(true)
    return () => {
      s.dispose()
      sound.current = null
    }
  }, [soundPick])

  useEffect(() => {
    dialogRef.current?.focus()
  }, [])

  const start = useCallback(() => {
    match.current = createMatch(difficulty)
    keys.current.clear()
    setResult(null)
    setHud(hudOf(match.current, '3'))
    setAnnounce(`Kickoff against the ${DIFFICULTIES.find(d => d.id === difficulty)?.label} bot`)
    setScreen('playing')
    dialogRef.current?.focus()
  }, [difficulty])

  const end = useCallback((m: Match) => {
    const won = m.winner === 0
    setRecord((prev: Record_) => {
      const mine = prev[m.difficulty] ?? { w: 0, l: 0 }
      const next = { ...prev, [m.difficulty]: { w: mine.w + (won ? 1 : 0), l: mine.l + (won ? 0 : 1) } }
      saveRecord(next)
      return next
    })
    setResult(m)
    setAnnounce(`${won ? 'Victory' : 'Defeat'}, ${m.score[0]} to ${m.score[1]}`)
    setScreen('over')
  }, [])

  // Keyboard: the game keys while playing; Esc pauses, resumes or leaves the menus.
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopPropagation()
        const now = screenRef.current
        if (now === 'playing') setScreen('paused')
        else if (now === 'paused') setScreen('playing')
        else onClose()
        return
      }
      if (e.key === 'Tab') {
        trapFocus(e, dialogRef.current)
        return
      }
      const action = KEYS[e.key]
      if (!action || screenRef.current !== 'playing') return
      e.preventDefault()
      keys.current.add(action)
    }
    const up = (e: KeyboardEvent) => {
      const action = KEYS[e.key]
      if (action) keys.current.delete(action)
    }
    const blur = () => keys.current.clear()
    window.addEventListener('keydown', down, true)
    window.addEventListener('keyup', up, true)
    window.addEventListener('blur', blur)
    return () => {
      window.removeEventListener('keydown', down, true)
      window.removeEventListener('keyup', up, true)
      window.removeEventListener('blur', blur)
    }
  }, [onClose])

  // Switching tabs pauses the match.
  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden && screenRef.current === 'playing') setScreen('paused')
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => document.removeEventListener('visibilitychange', onVisibility)
  }, [])

  // The loop: steps the match (or the bots behind the menus), turns events into sound and sparks, draws.
  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    const bits: Bit[] = []
    let shake = 0
    let roar = 0
    let banner = ''
    let bannerTeam: Team | undefined
    let bannerT = 0
    let last = performance.now()
    let frame = 0
    let shown: Hud | null = null
    /** Where the camera looks, in arena x, when the screen is too narrow for the whole arena. */
    let camX = ARENA_W / 2

    const input = (): Input => {
      const held = new Set([...keys.current, ...touches.current.values()])
      const dir = (held.has('right') ? 1 : 0) - (held.has('left') ? 1 : 0)
      return { dir: dir as Input['dir'], jump: held.has('jump'), boost: held.has('boost') }
    }

    const react = (m: Match, live: boolean) => {
      const s = live ? sound.current : null
      const pan = (x: number) => Math.max(-1, Math.min(1, (x / ARENA_W) * 2 - 1)) * 0.8
      for (const e of m.events) {
        switch (e.type) {
          case 'countdown':
            banner = String(e.n)
            bannerTeam = undefined
            bannerT = 1
            s?.beep(440, 120)
            break
          case 'go':
            banner = 'GO!'
            bannerT = 0.7
            s?.beep(880, 380)
            break
          case 'hit':
            spawnBit(bits, { x: e.x, y: e.y, shape: 'ring', size: 10, grow: 300 * e.power + 80, life: 0.3, color: '#fff' })
            s?.ballhit(e.power, pan(e.x))
            break
          case 'goal': {
            const x = e.team === 0 ? ARENA_W - 20 : 20
            burstBits(bits, Math.random, x, e.y, 70, 1100, { shape: 'streak', size: 6, color: COLOR[e.team], gravity: 600 })
            burstBits(bits, Math.random, x, e.y, 40, 700, { shape: 'star', size: 8, color: '#ffe08a', gravity: 400 })
            spawnBit(bits, { x, y: e.y, shape: 'ring', size: 20, grow: 1400, life: 0.8, color: COLOR[e.team] })
            shake = 1
            banner = 'GOAL!'
            bannerTeam = e.team
            bannerT = 2.2
            if (live) setAnnounce(`${TEAM[e.team]} scores. ${m.score[0]} to ${m.score[1]}`)
            s?.horn()
            s?.cheer()
            break
          }
          case 'demo':
            burstBits(bits, Math.random, e.x, e.y, 30, 400, { size: 16, grow: 40, color: 'rgba(80,80,95,0.6)', life: 1.3 })
            burstBits(bits, Math.random, e.x, e.y, 30, 900, { shape: 'square', size: 9, color: '#ff5a2a', gravity: 1400 })
            spawnBit(bits, { x: e.x, y: e.y, shape: 'ring', size: 12, grow: 900, life: 0.5, color: '#ffd27a' })
            shake = Math.max(shake, 0.6)
            if (live) setAnnounce(`${TEAM[e.team]} demolished`)
            s?.demo(pan(e.x))
            break
          case 'jump':
          case 'flip':
            if (e.team === 0) s?.swish(pan(m.cars[0].x))
            break
          case 'land':
            if (e.team === 0) s?.haptic()
            break
          case 'overtime':
            banner = 'OVERTIME'
            bannerTeam = undefined
            bannerT = 2
            if (live) setAnnounce('Overtime: next goal wins')
            s?.horn()
            break
          case 'end':
            if (live) {
              if (e.winner === 0) {
                s?.cheer()
                s?.chime()
              } else s?.failure()
            }
            break
        }
      }
    }

    const draw = (m: Match, dt: number) => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const cw = canvas.clientWidth
      const ch = canvas.clientHeight
      if (canvas.width !== Math.round(cw * dpr) || canvas.height !== Math.round(ch * dpr)) {
        canvas.width = Math.round(cw * dpr)
        canvas.height = Math.round(ch * dpr)
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, cw, ch)
      const fullW = ARENA_W + GOAL_D * 2 + 40
      const fullH = ARENA_H + 40
      // The whole arena when it fits well; on a narrow screen, where it would leave most of the height
      // empty, at least MIN_VIEW wide, following the play.
      const fit = Math.min(cw / fullW, ch / fullH)
      const scale = fit * fullH < ch * 0.5 ? Math.max(fit, Math.min(ch / fullH, cw / MIN_VIEW)) : fit
      const view = cw / scale
      const focus = m.ball.live ? m.ball.x * 0.6 + (m.cars[0].demoT ? m.ball.x : m.cars[0].x) * 0.4 : camX
      camX += (focus - camX) * Math.min(1, dt * 4)
      const half = (fullW - view) / 2
      const lookAt = view >= fullW ? ARENA_W / 2 : Math.max(ARENA_W / 2 - half, Math.min(ARENA_W / 2 + half, camX))
      shake = Math.max(0, shake - dt * 2.5)
      const jx = shake ? (Math.random() - 0.5) * 24 * shake : 0
      const jy = shake ? (Math.random() - 0.5) * 24 * shake : 0
      ctx.translate(cw / 2 - lookAt * scale + jx, (ch - ARENA_H * scale) / 2 + jy)
      ctx.scale(scale, scale)
      drawArena(ctx)

      for (const car of m.cars) {
        if (car.demoT) continue
        const { xx, xy } = axes(car)
        const tailX = car.x - car.face * xx * CAR_HL
        const tailY = car.y - car.face * xy * CAR_HL
        if (car.boosting) {
          for (let i = 0; i < 3; i++) {
            spawnBit(bits, {
              x: tailX, y: tailY, vx: -car.face * xx * 500 + (Math.random() - 0.5) * 120, vy: -car.face * xy * 500 + (Math.random() - 0.5) * 120,
              size: 5 + Math.random() * 5, life: 0.25, color: ['#ffd23f', ORANGE, '#ff4d1a'][i],
            })
          }
        }
        if (isSupersonic(car)) {
          spawnBit(bits, { x: tailX, y: tailY, vx: -car.vx * 0.2, vy: -car.vy * 0.2, shape: 'streak', size: 4, life: 0.3, color: car.team ? '#ffd2a8' : '#cfe6ff' })
        }
        ctx.save()
        ctx.translate(car.x, car.y)
        ctx.rotate(car.a)
        drawCar(ctx, 0, CAR_HH + 4, car.face, COLOR[car.team], CAR_HL / 27)
        ctx.restore()
      }
      if (m.ball.live) drawBall(ctx, m.ball, ARENA_H, BALL_R)
      stepBits(bits, dt)
      drawBits(ctx, bits)
    }

    const loop = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      const live = screenRef.current === 'playing' || screenRef.current === 'paused' || screenRef.current === 'over'
      const m = live && match.current ? match.current : attract.current
      if (screenRef.current === 'playing' && match.current) {
        const me = match.current
        stepMatch(me, input(), dt)
        react(me, true)
        const car = me.cars[0]
        roar -= dt
        if (car.boosting && roar <= 0) {
          sound.current?.boost()
          roar = ROAR_S
        }
        sound.current?.engine(car.demoT ? 0 : Math.min(1, speedOf(car) / 1900) * 0.8 + 0.2)
        bannerT = Math.max(0, bannerT - dt)
        if (!bannerT) banner = ''
        const next = hudOf(me, banner, bannerTeam)
        if (!shown || !sameHud(shown, next)) {
          shown = next
          setHud(next)
        }
        if (me.phase === 'ended') end(me)
      } else if (!live || !match.current) {
        // The bots play on behind the menu, silently, and start over when their match ends.
        const a = attract.current
        a.events = []
        a.carry = Math.min(a.carry + dt, 0.25)
        while (a.carry >= STEP) {
          a.carry -= STEP
          tick(a, botInput(a, 0, STEP, attractMinds.current[0]), botInput(a, 1, STEP, attractMinds.current[1]))
        }
        react(a, false)
        if (a.phase === 'ended') attract.current = createMatch('allstar')
        sound.current?.engine(0)
      } else {
        sound.current?.engine(0)
      }
      draw(m, screenRef.current === 'paused' ? 0 : dt)
      frame = requestAnimationFrame(loop)
    }
    frame = requestAnimationFrame(loop)
    return () => {
      cancelAnimationFrame(frame)
      sound.current?.engine(0)
    }
  }, [end])

  const press = (action: 'left' | 'right' | 'jump' | 'boost') => ({
    onPointerDown: (e: ReactPointerEvent<HTMLButtonElement>) => {
      e.preventDefault()
      e.currentTarget.setPointerCapture?.(e.pointerId)
      touches.current.set(e.pointerId, action)
    },
    onPointerUp: (e: ReactPointerEvent) => touches.current.delete(e.pointerId),
    onPointerCancel: (e: ReactPointerEvent) => touches.current.delete(e.pointerId),
    onContextMenu: (e: React.MouseEvent) => e.preventDefault(),
  })

  const mine = record[difficulty]
  const won = result?.winner === 0

  return (
    <div
      ref={dialogRef}
      className="rl-game"
      role="dialog"
      aria-modal="true"
      aria-label="Sideswipe match"
      tabIndex={-1}
      data-screen={screen}
    >
      <canvas ref={canvasRef} className="rl-game-canvas" aria-hidden="true" />

      {screen !== 'menu' && hud && (
        <div className="rl-hud">
          <div className="rl-hud-score">
            <span className="rl-hud-team rl-hud-team--blue" aria-label={`Blue ${hud.score[0]}`}>{hud.score[0]}</span>
            <span className="rl-hud-clock" aria-label={`Clock ${hud.clock}`}>
              {hud.overtime && <i>OT</i>}
              {hud.clock}
            </span>
            <span className="rl-hud-team rl-hud-team--orange" aria-label={`Orange ${hud.score[1]}`}>{hud.score[1]}</span>
          </div>
          <div className="rl-hud-boost" style={{ '--boost': hud.boost } as React.CSSProperties} aria-label={`Boost ${hud.boost}`}>
            <b>{hud.boost}</b>
            <small>BOOST</small>
          </div>
          {hud.banner && (
            <div className="rl-hud-banner" data-team={hud.bannerTeam === undefined ? undefined : hud.bannerTeam ? 'orange' : 'blue'} aria-hidden="true">
              {hud.banner}
            </div>
          )}
        </div>
      )}
      <p className="rl-sr" aria-live="polite">{announce}</p>

      <button type="button" className="rl-game-close" aria-label="Close the match" onClick={onClose}>×</button>

      {screen === 'playing' && (
        <div className="rl-touch">
          <div className="rl-touch-group">
            <button type="button" aria-label="Left" {...press('left')}>◀</button>
            <button type="button" aria-label="Right" {...press('right')}>▶</button>
          </div>
          <div className="rl-touch-group">
            <button type="button" aria-label="Boost" className="rl-touch-boost" {...press('boost')}>BOOST</button>
            <button type="button" aria-label="Jump" className="rl-touch-jump" {...press('jump')}>JUMP</button>
          </div>
        </div>
      )}

      {screen === 'menu' && (
        <div className="rl-panel">
          <h2>Sideswipe</h2>
          <p>A two-minute 1v1. Blue is you: score in the orange goal on the right.</p>
          <div className="rl-difficulty" role="group" aria-label="Bot level">
            {DIFFICULTIES.map(d => (
              <button key={d.id} type="button" aria-pressed={difficulty === d.id} onClick={() => setDifficulty(d.id)}>{d.label}</button>
            ))}
          </div>
          <p className="rl-rotate">Turn your phone sideways for a wider view.</p>
          <p className="rl-record">{mine ? `Your record against ${DIFFICULTIES.find(d => d.id === difficulty)?.label}: ${mine.w} W · ${mine.l} L` : 'No matches played at this level yet'}</p>
          <button type="button" className="rl-primary" onClick={start}>Kick off</button>
          <dl className="rl-controls">
            <dt>A D / ← →</dt><dd>Drive; turn in the air</dd>
            <dt>W / ↑ / Space</dt><dd>Jump; again with a direction to flip</dd>
            <dt>Shift / J</dt><dd>Boost</dd>
            <dt>Esc</dt><dd>Pause</dd>
          </dl>
        </div>
      )}

      {screen === 'paused' && (
        <div className="rl-panel">
          <h2>Paused</h2>
          <button type="button" className="rl-primary" onClick={() => setScreen('playing')}>Resume</button>
          <button type="button" onClick={start}>Restart</button>
          <button type="button" onClick={() => setScreen('menu')}>Change level</button>
          <button type="button" onClick={onClose}>Quit</button>
        </div>
      )}

      {screen === 'over' && result && (
        <div className="rl-panel" data-result={won ? 'win' : 'loss'}>
          <h2>{won ? 'Victory!' : 'Defeat'}</h2>
          <p className="rl-final">
            <span className="rl-hud-team--blue">{result.score[0]}</span> – <span className="rl-hud-team--orange">{result.score[1]}</span>
            {result.overtime && ' (OT)'}
          </p>
          <table className="rl-stats">
            <thead>
              <tr><th scope="col" /><th scope="col">Blue</th><th scope="col">Orange</th></tr>
            </thead>
            <tbody>
              {(['goals', 'shots', 'saves', 'demos'] as const).map(k => (
                <tr key={k}>
                  <th scope="row">{k[0].toUpperCase() + k.slice(1)}</th>
                  <td>{result.stats[0][k]}</td>
                  <td>{result.stats[1][k]}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button type="button" className="rl-primary" onClick={start}>Play again</button>
          <button type="button" onClick={() => setScreen('menu')}>Change level</button>
          <button type="button" onClick={onClose}>Quit</button>
        </div>
      )}
    </div>
  )
}

/** The arena: night turf, neon walls, the goal pockets with their nets, and the pitch markings. */
function drawArena(ctx: CanvasRenderingContext2D) {
  const W = ARENA_W
  const H = ARENA_H
  const R = CORNER_R
  const outline = () => {
    ctx.beginPath()
    ctx.moveTo(-GOAL_D, H)
    ctx.lineTo(W + GOAL_D, H)
    ctx.lineTo(W + GOAL_D, H - GOAL_H)
    ctx.lineTo(W, H - GOAL_H)
    ctx.lineTo(W, R)
    ctx.arcTo(W, 0, W - R, 0, R)
    ctx.lineTo(R, 0)
    ctx.arcTo(0, 0, 0, R, R)
    ctx.lineTo(0, H - GOAL_H)
    ctx.lineTo(-GOAL_D, H - GOAL_H)
    ctx.closePath()
  }
  outline()
  const sky = ctx.createLinearGradient(0, 0, 0, H)
  sky.addColorStop(0, '#0b1338')
  sky.addColorStop(1, '#151d4a')
  ctx.fillStyle = sky
  ctx.fill()

  ctx.save()
  outline()
  ctx.clip()
  // Turf stripes along the floor, the halfway line and the centre circle.
  for (let i = 0; i < 16; i++) {
    ctx.fillStyle = i % 2 ? 'rgba(40,140,90,0.22)' : 'rgba(40,140,90,0.14)'
    ctx.fillRect(-GOAL_D + i * ((W + GOAL_D * 2) / 16), H - 26, (W + GOAL_D * 2) / 16, 26)
  }
  ctx.strokeStyle = 'rgba(255,255,255,0.12)'
  ctx.lineWidth = 4
  ctx.setLineDash([18, 14])
  ctx.beginPath()
  ctx.moveTo(W / 2, 0)
  ctx.lineTo(W / 2, H)
  ctx.stroke()
  ctx.setLineDash([])
  ctx.beginPath()
  ctx.arc(W / 2, H / 2, 120, 0, Math.PI * 2)
  ctx.stroke()
  // The halves glow faintly in their team's colour.
  for (const [x, color] of [[0, BLUE], [W, ORANGE]] as const) {
    const g = ctx.createRadialGradient(x, H, 10, x, H, W * 0.5)
    g.addColorStop(0, `${color}44`)
    g.addColorStop(1, `${color}00`)
    ctx.fillStyle = g
    ctx.fillRect(x - W * 0.5, 0, W, H)
  }
  // Goal nets: a diamond mesh in each pocket.
  for (const [x0, color] of [[-GOAL_D, BLUE], [W, ORANGE]] as const) {
    ctx.fillStyle = `${color}26`
    ctx.fillRect(x0, H - GOAL_H, GOAL_D, GOAL_H)
    ctx.strokeStyle = `${color}55`
    ctx.lineWidth = 2
    ctx.beginPath()
    for (let k = -GOAL_H; k < GOAL_D + GOAL_H; k += 26) {
      ctx.moveTo(x0 + k, H - GOAL_H)
      ctx.lineTo(x0 + k + GOAL_H, H)
      ctx.moveTo(x0 + k, H)
      ctx.lineTo(x0 + k + GOAL_H, H - GOAL_H)
    }
    ctx.stroke()
  }
  ctx.restore()

  // Neon walls, blue on the left half and orange on the right, and the goal frames brighter.
  ctx.save()
  ctx.lineWidth = 8
  ctx.shadowBlur = 24
  ctx.lineJoin = 'round'
  for (const [side, color] of [[0, BLUE], [1, ORANGE]] as const) {
    ctx.save()
    ctx.beginPath()
    ctx.rect(side ? W / 2 : -GOAL_D - 20, -20, W / 2 + GOAL_D + 20, H + 40)
    ctx.clip()
    ctx.strokeStyle = color
    ctx.shadowColor = color
    outline()
    ctx.stroke()
    ctx.restore()
  }
  // The goal lines, dashed, and a white crossbar.
  ctx.lineWidth = 5
  ctx.setLineDash([14, 10])
  for (const [x, color] of [[0, BLUE], [W, ORANGE]] as const) {
    ctx.strokeStyle = color
    ctx.shadowColor = color
    ctx.beginPath()
    ctx.moveTo(x, H - GOAL_H)
    ctx.lineTo(x, H)
    ctx.stroke()
  }
  ctx.setLineDash([])
  ctx.fillStyle = '#fff'
  for (const x of [0, W]) {
    ctx.beginPath()
    ctx.arc(x, H - GOAL_H, 9, 0, Math.PI * 2)
    ctx.fill()
  }
  ctx.restore()
}
