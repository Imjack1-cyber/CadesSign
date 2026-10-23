/**
 * One particle system per theme effect. Presets are plain data plus pure-ish update functions over
 * arrays, so they can be stepped in tests without a canvas; only draw() touches the 2D context.
 */
import type { EffectKind } from '../designs'
import type { ChromeEvent, ChromeMotion, Outcome } from '../signals'
import { type Bit, burstBits, drawBits, scaleCount, spawnBit, stepBits } from './bits'
import { plankton } from './deepsea'
import { ecg, ink, sand } from './interactive'
import { glass } from './ios'
import { blocks } from './minecraft'
import { boost } from './rocket'
import type { Sound } from './sound'
import { matrix } from './terminal'
import { desktop } from './win95'

export interface Pointer {
  x: number
  y: number
  /** Smoothed velocity in px/s. */
  vx: number
  vy: number
  /** False until the pointer has moved over the page. */
  active: boolean
  /** The pointer is a finger or pen, which jumps rather than moves and has no hover. */
  touch?: boolean
  /** A button is held; where it went down, and whether that was on bare page rather than a control or text. */
  down?: boolean
  downX?: number
  downY?: number
  bare?: boolean
  /** What kind of control the last press was on, if any (see controlKind in engine.ts). */
  control?: Control
}

/**
 * Kinds of control a press can land on. 'back' and 'forward' are the wizard's Back and Next buttons
 * and its step rail, whose moves arrive as activities once they happen.
 */
export type Control =
  | 'button' | 'choice' | 'toggle' | 'nav' | 'field' | 'upload' | 'download' | 'discard' | 'back' | 'forward' | 'disabled'

/**
 * Things the user got done: the wizard moved forward or back, a file went in or out, the app produced
 * one, the About panel opened or closed, or a tab of it was chosen.
 */
export type Activity = 'forward' | 'back' | 'file-in' | 'file-out' | 'saved' | 'panel-open' | 'panel-close' | 'tab'

/**
 * What the mouse rests on, at the 'wild' level: a control (its host's box and corner radius), or an
 * element with text of its own ('text', with its line height). The box follows the element as it moves.
 */
export interface Hover {
  box: Box
  radius: number
  kind: Control | 'text'
  /** Line height in px, for a text cursor. */
  line: number
}

export interface World {
  w: number
  h: number
  /** Seconds since start, and since the last frame. */
  t: number
  dt: number
  pointer: Pointer
  /** Gusting wind, roughly -1.6..1.6; positive blows to the right. */
  wind: number
  /** 'wild' doubles densities and turns on cursor reactions and click bursts. */
  wild: boolean
  rnd: () => number
  /** Keys per second over the last second or so; 0 when the user is not typing. */
  typing: number
  /** Present only when the user turned sound on. */
  sound?: Sound
  /** What the mouse is over, when it is over a control or text (see Hover). */
  hover?: Hover
  /**
   * Notifies the page of big moments, so CSS can react: <html> gets the class `app-<name>` for `ms`
   * milliseconds (600 by default); signalling again extends it and `ms` <= 0 removes it.
   */
  signal: (name: SignalName, ms?: number) => void
}

export type SignalName =
  | 'lightning' | 'carriage' | 'stamp' | 'void' | 'flicker' | 'flatline' | 'shock' | 'alarm' | 'normal' | 'knock' | 'gust'
  | 'hourglass' | 'starting' | 'lag' | 'hung' | 'stop' | 'tada' | 'saver'
  | 'typing' | 'busy' | 'ok' | 'warn' | 'fail' | 'degauss'
  | 'pointer' | 'push' | 'pop'
  | 'goal' | 'demo'
  | 'mine' | 'boom' | 'advancement' | 'night' | 'rain'

export type KeyKind = 'char' | 'space' | 'enter' | 'delete' | 'tab'

/** A key press, located at the caret (or the focused element) in viewport px. */
export interface AppKey {
  kind: KeyKind
  x: number
  y: number
  /** The field's font size, and its right edge. */
  size: number
  edge: number
  /** True when typing into a text field rather than pressing a key on the page. */
  field: boolean
  /** The typed character; never set for password fields. */
  glyph?: string
  /** The field was empty when the key was pressed. */
  empty?: boolean
}

/** What a request runs: 'sign' or 'verify', and the signature level (B, T, LT, LTA) when signing. */
export interface BusyInfo {
  action?: string
  level?: string
}

export interface Box {
  left: number
  top: number
  right: number
  bottom: number
}

export interface State {
  /** The main particles; their shape depends on the preset. */
  p: Array<Record<string, number>>
  bits: Bit[]
  /** Upper bound for p.length, checked by the tests. */
  max: number
  /** Optional height map of settled snow, one column per PILE_COL px. */
  pile?: Float32Array
  pileCap?: number
  [key: string]: unknown
}

export interface Preset {
  /** 'front' falls over the cards; 'back' shows between them; 'top' is above everything, overlays included. */
  layer: 'front' | 'back' | 'top'
  /** `prev` is the state before a resize, for presets that keep some of it. */
  init(world: World, prev?: State): State
  step(s: State, world: World): void
  draw(ctx: CanvasRenderingContext2D, s: State, world: World): void
  /** Runs once when the effect starts, not again when a resize restarts the preset. */
  start?(s: State, world: World): void
  burst?(s: State, world: World, x: number, y: number): void
  /** The hooks below only run at the 'wild' level. A key was typed, deleted, entered or tabbed. */
  key?(s: State, world: World, k: AppKey): void
  /** A text field gained focus. */
  focus?(s: State, world: World, box: Box): void
  /** A request started or ended; `info` says what runs, when the wizard knows. */
  busy?(s: State, world: World, on: boolean, info?: BusyInfo): void
  /** An operation ended; `box` is where its result is shown, if on screen, and `action` what was run. */
  outcome?(s: State, world: World, kind: Outcome, box: Box | null, action?: string): void
  /** The theme's own chrome was used (see signals.ts), optionally moving a window between two boxes. */
  chrome?(s: State, world: World, event: ChromeEvent, motion: ChromeMotion): void
  /** The user got something done in the app (see Activity). */
  activity?(s: State, world: World, a: Activity): void
  /** The pointer or the arrow keys moved onto another option in an open list; `index` is its place in the list. */
  browse?(s: State, world: World, index: number): void
  /** A command typed into the theme's command line was accepted (ok) or refused. */
  command?(s: State, world: World, ok: boolean): void
  /** The wheel scrolled the page or a panel by `dy` px (positive is down). */
  scroll?(s: State, world: World, dy: number): void
}

export const PILE_COL = 8

const TAU = Math.PI * 2
const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const speed = (p: Pointer) => Math.hypot(p.vx, p.vy)

export { scaleCount }

/** Pushes (or pulls, with negative strength) a particle relative to the pointer within radius. */
function pointerForce(q: Record<string, number>, world: World, radius: number, strength: number) {
  const { pointer, dt } = world
  if (!pointer.active) return
  const dx = q.x - pointer.x
  const dy = q.y - pointer.y
  const d = Math.hypot(dx, dy)
  if (d > radius || d < 1) return
  const f = (1 - d / radius) * strength * dt
  q.vx += (dx / d) * f
  q.vy += (dy / d) * f
}

/** Settles snow or leaves into the pile, spreading a little to the neighbours. */
function addToPile(s: State, x: number, amount: number) {
  if (!s.pile || !s.pileCap) return
  const i = Math.max(0, Math.min(s.pile.length - 1, Math.floor(x / PILE_COL)))
  for (const [j, k] of [[i, 0.5], [i - 1, 0.25], [i + 1, 0.25]] as const) {
    if (j >= 0 && j < s.pile.length) s.pile[j] = Math.min(s.pileCap, s.pile[j] + amount * k)
  }
}

const pileAt = (s: State, x: number) =>
  s.pile ? s.pile[Math.max(0, Math.min(s.pile.length - 1, Math.floor(x / PILE_COL)))] : 0

function newPile(world: World, capShare: number) {
  return { pile: new Float32Array(Math.ceil(world.w / PILE_COL) + 1), pileCap: world.h * capShare }
}

function drawPile(ctx: CanvasRenderingContext2D, s: State, world: World, fill: string | CanvasGradient) {
  if (!s.pile) return
  ctx.fillStyle = fill
  ctx.beginPath()
  ctx.moveTo(0, world.h)
  for (let i = 0; i < s.pile.length; i++) ctx.lineTo(i * PILE_COL, world.h - s.pile[i])
  ctx.lineTo(world.w, world.h)
  ctx.closePath()
  ctx.fill()
}

// ---------- Snow: three depths, gusts, flakes dodge the cursor, drifts build up. ----------

const snow: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 320 : 140)
    const p = Array.from({ length: n }, () => newFlake(world, world.rnd() * world.h))
    return { p, bits: [], max: n, ...newPile(world, world.wild ? 0.08 : 0.04) }
  },
  step(s, world) {
    const { dt, t, wind, w, h } = world
    for (const q of s.p) {
      if (world.wild) pointerForce(q, world, 140, 900)
      q.vx *= 1 - 2 * dt
      q.vy *= 1 - 2 * dt
      q.x += (wind * 90 * (0.4 + q.depth) + Math.sin(t * 1.3 + q.phase) * 18 + q.vx) * dt
      q.y += (q.fall * (0.5 + q.depth) + q.vy) * dt
      if (q.x < -20) q.x += w + 40
      if (q.x > w + 20) q.x -= w + 40
      if (q.y > h - pileAt(s, q.x)) {
        addToPile(s, q.x, q.r * 0.35)
        Object.assign(q, newFlake(world, -10))
      } else if (q.y < -40) q.y = -10
    }
    // A slow melt keeps the drift alive instead of sitting at its cap.
    if (s.pile) for (let i = 0; i < s.pile.length; i++) s.pile[i] = Math.max(0, s.pile[i] - dt * 0.6)
    stepBits(s.bits, dt)
  },
  draw(ctx, s, world) {
    // One path per depth band keeps hundreds of flakes cheap; a faint blue rim keeps white flakes
    // visible against the pale sky.
    ctx.fillStyle = '#fff'
    ctx.strokeStyle = 'rgba(90,140,190,0.55)'
    ctx.lineWidth = 1
    for (const band of [0, 1, 2]) {
      ctx.globalAlpha = 0.6 + band * 0.2
      ctx.beginPath()
      for (const q of s.p) {
        if (Math.min(2, Math.floor(q.depth * 3)) !== band) continue
        ctx.moveTo(q.x + q.r, q.y)
        ctx.arc(q.x, q.y, q.r, 0, TAU)
      }
      ctx.fill()
      ctx.stroke()
    }
    ctx.globalAlpha = 1
    const g = ctx.createLinearGradient(0, world.h - (s.pileCap ?? 0), 0, world.h)
    g.addColorStop(0, '#ffffff')
    g.addColorStop(1, '#dce9f5')
    drawPile(ctx, s, world, g)
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    burstBits(s.bits, world.rnd, x, y, 36, 420, { color: '#fff', size: 3, gravity: 600 })
    spawnBit(s.bits, { x, y, shape: 'ring', size: 6, grow: 260, life: 0.4, color: 'rgba(255,255,255,0.9)' })
  },
}

function newFlake(world: World, y: number) {
  const depth = world.rnd()
  return {
    x: world.rnd() * world.w, y, vx: 0, vy: 0, depth,
    r: 1 + depth * 3.5, fall: between(world.rnd, 30, 70), phase: world.rnd() * TAU,
  }
}

// ---------- Rain: slanted downpour, splashes, ripples and branching lightning. ----------

const rain: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 460 : 200)
    const p = Array.from({ length: n }, () => newDrop(world, world.rnd() * world.h))
    return { p, bits: [], max: n, nextBolt: 3 + world.rnd() * 4, bolt: null, flash: 0, bolts: [] as number[] }
  },
  step(s, world) {
    const { dt, wind, h, w } = world
    for (const q of s.p) {
      q.x += (wind * 260 + 90) * dt
      q.y += q.v * dt
      if (q.y > h - 2) {
        if (world.wild && world.rnd() < 0.5) {
          for (let i = 0; i < 2; i++) {
            spawnBit(s.bits, {
              x: q.x, y: h - 2, vx: between(world.rnd, -90, 90), vy: between(world.rnd, -260, -120),
              gravity: 1100, size: 1.3, life: 0.35, color: 'rgba(190,215,240,0.8)',
            })
          }
        }
        Object.assign(q, newDrop(world, -q.len))
      }
      if (q.x > w + 50) q.x -= w + 100
      if (q.x < -50) q.x += w + 100
    }
    // Lightning: at most once every 8-15 s (wild) or 15-30 s (calm), well under 3 flashes a second.
    if (world.t >= (s.nextBolt as number)) {
      s.bolt = { path: boltPath(world), life: 0.45 }
      s.flash = 1
      ;(s.bolts as number[]).push(world.t)
      s.nextBolt = world.t + (world.wild ? between(world.rnd, 8, 15) : between(world.rnd, 15, 30))
      world.signal('lightning')
    }
    const bolt = s.bolt as { life: number } | null
    if (bolt) {
      bolt.life -= dt
      if (bolt.life <= 0) s.bolt = null
    }
    s.flash = Math.max(0, (s.flash as number) - dt * 3)
    stepBits(s.bits, dt)
  },
  draw(ctx, s, world) {
    ctx.strokeStyle = 'rgba(180,210,240,0.6)'
    ctx.lineWidth = 1.2
    ctx.beginPath()
    const slant = (world.wind * 260 + 90) * 0.02
    for (const q of s.p) {
      ctx.moveTo(q.x, q.y)
      ctx.lineTo(q.x - slant * (q.len / 12), q.y - q.len)
    }
    ctx.stroke()
    const bolt = s.bolt as { path: Array<Array<[number, number]>>; life: number } | null
    if (bolt) {
      ctx.save()
      ctx.globalAlpha = Math.min(1, bolt.life * 3)
      ctx.strokeStyle = '#eef4ff'
      ctx.shadowColor = '#9fc3ff'
      ctx.shadowBlur = 18
      for (const [i, branch] of bolt.path.entries()) {
        ctx.lineWidth = i === 0 ? 3 : 1.4
        ctx.beginPath()
        branch.forEach(([x, y], j) => (j ? ctx.lineTo(x, y) : ctx.moveTo(x, y)))
        ctx.stroke()
      }
      ctx.restore()
    }
    if ((s.flash as number) > 0) {
      ctx.fillStyle = `rgba(215,228,255,${(s.flash as number) * 0.28})`
      ctx.fillRect(0, 0, world.w, world.h)
    }
    drawBits(ctx, s.bits)
  },
  burst(s, _world, x, y) {
    for (let i = 0; i < 3; i++) {
      spawnBit(s.bits, { x, y, shape: 'ring', size: 4 + i * 10, grow: 120, life: 0.9, color: 'rgba(170,205,240,0.7)' })
    }
  },
}

function newDrop(world: World, y: number) {
  return { x: between(world.rnd, -50, world.w + 50), y, v: between(world.rnd, 900, 1400), len: between(world.rnd, 10, 24) }
}

/** A jagged main bolt from the sky plus a few forks. */
function boltPath(world: World): Array<Array<[number, number]>> {
  const { rnd, w, h } = world
  const main: Array<[number, number]> = []
  let x = between(rnd, w * 0.15, w * 0.85)
  const end = between(rnd, h * 0.55, h * 0.85)
  for (let y = 0; y < end; y += between(rnd, 14, 30)) {
    x += between(rnd, -22, 22)
    main.push([x, y])
  }
  const branches = [main]
  for (let b = 0; b < 3; b++) {
    const start = main[Math.floor(between(rnd, 0.2, 0.7) * main.length)]
    if (!start) continue
    const fork: Array<[number, number]> = [start]
    let [fx, fy] = start
    const dir = rnd() < 0.5 ? -1 : 1
    for (let i = 0; i < 8; i++) {
      fx += dir * between(rnd, 6, 20)
      fy += between(rnd, 10, 24)
      fork.push([fx, fy])
    }
    branches.push(fork)
  }
  return branches
}

// ---------- Bubbles: iridescent, pop when touched, heart trail behind the cursor. ----------

const bubbles: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 70 : 32)
    const p = Array.from({ length: n }, () => newBubble(world, world.rnd() * world.h))
    return { p, bits: [], max: n * 2, base: n }
  },
  step(s, world) {
    const { dt, t, pointer } = world
    for (let i = s.p.length - 1; i >= 0; i--) {
      const q = s.p[i]
      q.y -= q.v * dt
      q.x += (Math.sin(t * 1.6 + q.phase) * 22 + world.wind * 25 + q.vx) * dt
      q.vx *= 1 - dt
      const touched = world.wild && pointer.active && Math.hypot(q.x - pointer.x, q.y - pointer.y) < q.r + 6
      if (touched) {
        burstBits(s.bits, world.rnd, q.x, q.y, 10, 160, { color: '#ff8cc6', size: 2 })
        spawnBit(s.bits, { x: q.x, y: q.y, shape: 'ring', size: q.r, grow: 90, life: 0.3, color: 'rgba(255,255,255,0.9)' })
      }
      if (touched || q.y < -q.r * 2) {
        if (s.p.length > (s.base as number)) s.p.splice(i, 1)
        else Object.assign(q, newBubble(world, world.h + 30))
      }
    }
    if (world.wild && pointer.active && speed(pointer) > 120 && world.rnd() < 0.6) {
      spawnBit(s.bits, {
        x: pointer.x, y: pointer.y, vx: between(world.rnd, -30, 30), vy: between(world.rnd, -80, -30),
        shape: world.rnd() < 0.5 ? 'heart' : 'star', size: between(world.rnd, 4, 8), life: 0.9,
        color: ['#ff5fa8', '#7ee8d0', '#b69cff', '#ffd166'][Math.floor(world.rnd() * 4)],
      })
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s, world) {
    for (const q of s.p) {
      const g = ctx.createRadialGradient(q.x - q.r * 0.35, q.y - q.r * 0.35, q.r * 0.1, q.x, q.y, q.r)
      const hue = (q.hue + world.t * 40) % 360
      g.addColorStop(0, 'rgba(255,255,255,0.85)')
      g.addColorStop(0.5, `hsla(${hue},90%,80%,0.25)`)
      g.addColorStop(1, `hsla(${(hue + 120) % 360},90%,75%,0.45)`)
      ctx.fillStyle = g
      ctx.beginPath()
      ctx.arc(q.x, q.y, q.r, 0, TAU)
      ctx.fill()
      ctx.strokeStyle = 'rgba(255,255,255,0.8)'
      ctx.lineWidth = 1
      ctx.stroke()
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    for (let i = 0; i < 12 && s.p.length < s.max; i++) {
      s.p.push({ ...newBubble(world, y), x: x + between(world.rnd, -30, 30), r: between(world.rnd, 6, 18), vx: between(world.rnd, -120, 120) })
    }
  },
}

function newBubble(world: World, y: number) {
  return {
    x: world.rnd() * world.w, y, r: between(world.rnd, 8, 30), v: between(world.rnd, 40, 110),
    phase: world.rnd() * TAU, hue: world.rnd() * 360, vx: 0,
  }
}

// ---------- Sprinkles: rainbow sprinkles that bounce and settle; clicks splat chocolate. ----------

const SPRINKLE_COLORS = ['#ff5f7e', '#ffd23f', '#3ddc97', '#4fc3f7', '#b388ff', '#fff3e0']

const sprinkles: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 240 : 100)
    return { p: Array.from({ length: n }, () => newSprinkle(world, world.rnd() * world.h)), bits: [], max: n }
  },
  step(s, world) {
    const { dt, h } = world
    for (const q of s.p) {
      if (q.rest > 0) {
        q.rest -= dt
        if (q.rest <= 0) Object.assign(q, newSprinkle(world, -10))
        continue
      }
      if (world.wild) pointerForce(q, world, 110, 1400)
      q.vy += 420 * dt
      q.x += (q.vx + world.wind * 40) * dt
      q.y += q.vy * dt
      q.rot += q.vr * dt
      if (q.y > h - 4) {
        q.y = h - 4
        if (Math.abs(q.vy) > 80) {
          q.vy *= -0.45
          q.vr *= -0.6
        } else {
          q.rest = between(world.rnd, 2, 5)
          q.rot = world.rnd() < 0.5 ? 0 : Math.PI
        }
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s) {
    ctx.lineCap = 'round'
    ctx.lineWidth = 3
    for (const q of s.p) {
      ctx.strokeStyle = SPRINKLE_COLORS[q.color]
      const dx = Math.cos(q.rot) * q.len
      const dy = Math.sin(q.rot) * q.len
      ctx.beginPath()
      ctx.moveTo(q.x - dx, q.y - dy)
      ctx.lineTo(q.x + dx, q.y + dy)
      ctx.stroke()
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    spawnBit(s.bits, { x, y, size: 16, life: 1.4, color: '#4a2412' })
    burstBits(s.bits, world.rnd, x, y, 18, 380, { color: '#5b2e17', size: 4, gravity: 900 })
    burstBits(s.bits, world.rnd, x, y, 10, 300, { color: '#e2a35b', size: 2.5, gravity: 900 })
  },
}

function newSprinkle(world: World, y: number) {
  return {
    x: world.rnd() * world.w, y, vx: between(world.rnd, -40, 40), vy: between(world.rnd, 40, 160),
    rot: world.rnd() * TAU, vr: between(world.rnd, -8, 8), len: between(world.rnd, 3, 6),
    color: Math.floor(world.rnd() * SPRINKLE_COLORS.length), rest: 0,
  }
}

// ---------- Stars: twinkling field, shooting stars, constellations around the cursor. ----------

const stars: Preset = {
  layer: 'back',
  init(world) {
    const n = scaleCount(world, world.wild ? 280 : 150)
    const p = Array.from({ length: n }, () => ({
      x: world.rnd() * world.w, y: world.rnd() * world.h, r: between(world.rnd, 0.5, 2),
      phase: world.rnd() * TAU, tw: between(world.rnd, 0.8, 3),
    }))
    return { p, bits: [], max: n, nextShot: 1 + world.rnd() * 2 }
  },
  step(s, world) {
    if (world.t >= (s.nextShot as number)) {
      const fromLeft = world.rnd() < 0.5
      const v = between(world.rnd, 700, 1100)
      spawnBit(s.bits, {
        x: fromLeft ? between(world.rnd, -50, world.w * 0.4) : between(world.rnd, world.w * 0.6, world.w + 50),
        y: between(world.rnd, 0, world.h * 0.4), vx: fromLeft ? v : -v, vy: v * 0.35,
        shape: 'streak', size: 2, life: 1.1, color: '#fff3c4',
      })
      s.nextShot = world.t + (world.wild ? between(world.rnd, 1.5, 4) : between(world.rnd, 5, 10))
    }
    stepBits(s.bits, world.dt)
  },
  draw(ctx, s, world) {
    for (const q of s.p) {
      ctx.globalAlpha = 0.25 + 0.75 * Math.abs(Math.sin(world.t * q.tw + q.phase))
      ctx.fillStyle = '#fff8d6'
      ctx.beginPath()
      ctx.arc(q.x, q.y, q.r, 0, TAU)
      ctx.fill()
    }
    ctx.globalAlpha = 1
    const { pointer } = world
    if (world.wild && pointer.active) {
      const near = s.p.filter(q => Math.hypot(q.x - pointer.x, q.y - pointer.y) < 170)
      ctx.lineWidth = 1
      for (const a of near) {
        const closest = near
          .filter(b => b !== a)
          .sort((b, c) => Math.hypot(b.x - a.x, b.y - a.y) - Math.hypot(c.x - a.x, c.y - a.y))
          .slice(0, 2)
        for (const b of closest) {
          ctx.strokeStyle = `rgba(242,193,78,${0.6 - Math.hypot(a.x - pointer.x, a.y - pointer.y) / 340})`
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(b.x, b.y)
          ctx.stroke()
        }
      }
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    spawnBit(s.bits, { x, y, shape: 'ring', size: 4, grow: 420, life: 0.7, color: '#fff3c4' })
    spawnBit(s.bits, { x, y, shape: 'ring', size: 2, grow: 260, life: 0.9, color: '#f2c14e' })
    burstBits(s.bits, world.rnd, x, y, 40, 520, { shape: 'star', size: 4, color: '#ffe8a3' })
  },
}

// ---------- Petals: a petal storm that swirls around the cursor. ----------

const petals: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 170 : 70)
    return { p: Array.from({ length: n }, () => newPetal(world, world.rnd() * world.h)), bits: [], max: n + 60, base: n }
  },
  step(s, world) {
    const { dt, t, pointer, w, h } = world
    for (let i = s.p.length - 1; i >= 0; i--) {
      const q = s.p[i]
      if (world.wild && pointer.active) {
        // Vortex: a sideways push around the cursor plus a slight pull inwards.
        const dx = q.x - pointer.x
        const dy = q.y - pointer.y
        const d = Math.hypot(dx, dy)
        if (d < 200 && d > 1) {
          const f = (1 - d / 200) * 900 * dt
          q.vx += (-dy / d) * f - (dx / d) * f * 0.25
          q.vy += (dx / d) * f - (dy / d) * f * 0.25
        }
      }
      q.vx *= 1 - 1.2 * dt
      q.vy *= 1 - 1.2 * dt
      q.x += (world.wind * 140 + Math.sin(t + q.phase) * 30 + q.vx) * dt
      q.y += (q.fall + q.vy) * dt
      q.rot += q.vr * dt
      q.flip += q.vf * dt
      if (q.y > h + 20 || q.x < -60 || q.x > w + 60) {
        if (s.p.length > (s.base as number)) s.p.splice(i, 1)
        else Object.assign(q, newPetal(world, -20))
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s) {
    for (const q of s.p) {
      ctx.save()
      ctx.translate(q.x, q.y)
      ctx.rotate(q.rot)
      ctx.scale(1, Math.abs(Math.cos(q.flip)) * 0.8 + 0.2)
      ctx.fillStyle = q.tone ? '#ffd1dc' : '#f7a1b8'
      ctx.beginPath()
      ctx.moveTo(0, -q.size)
      ctx.quadraticCurveTo(q.size, -q.size * 0.3, 0, q.size)
      ctx.quadraticCurveTo(-q.size, -q.size * 0.3, 0, -q.size)
      ctx.fill()
      ctx.restore()
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    for (let i = 0; i < 30 && s.p.length < s.max; i++) {
      const a = world.rnd() * TAU
      const v = between(world.rnd, 150, 420)
      s.p.push({ ...newPetal(world, y), x, vx: Math.cos(a) * v, vy: Math.sin(a) * v })
    }
  },
}

function newPetal(world: World, y: number) {
  return {
    x: between(world.rnd, -40, world.w + 40), y, vx: 0, vy: 0, fall: between(world.rnd, 35, 80),
    rot: world.rnd() * TAU, vr: between(world.rnd, -2, 2), flip: world.rnd() * TAU, vf: between(world.rnd, 1, 4),
    size: between(world.rnd, 5, 9), phase: world.rnd() * TAU, tone: world.rnd() < 0.5 ? 1 : 0,
  }
}

// ---------- Leaves: tumble down, pile up at the bottom, get kicked up by a fast cursor. ----------

const LEAF_COLORS = ['#d9772b', '#a9431c', '#e8b13a', '#8a8a2a', '#c2541f']
const MAX_RESTING_LEAVES = 140

const leaves: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 200 : 60)
    return { p: Array.from({ length: n }, () => newLeaf(world, world.rnd() * world.h)), bits: [], max: n }
  },
  step(s, world) {
    const { dt, t, pointer, h, w } = world
    const kicking = world.wild && pointer.active && speed(pointer) > 500
    let resting = 0
    for (const q of s.p) if (q.resting) resting++
    for (const q of s.p) {
      if (kicking && Math.hypot(q.x - pointer.x, q.y - pointer.y) < 110) {
        q.resting = 0
        q.vx += pointer.vx * 0.5 + between(world.rnd, -100, 100)
        q.vy = -between(world.rnd, 300, 600)
      }
      if (q.resting) continue
      // Kicked leaves arc back quickly; falling ones drift towards their own terminal speed.
      q.vy += (q.vy < 0 ? 900 : q.vy < q.fall ? 160 : -40) * dt
      q.vx *= 1 - 0.8 * dt
      q.x += (world.wind * 160 + Math.sin(t * 1.4 + q.phase) * 40 + q.vx) * dt
      q.y += q.vy * dt
      q.rot += q.vr * dt
      if (q.x < -40) q.x += w + 80
      if (q.x > w + 40) q.x -= w + 80
      if (q.y < -h * 0.5) Object.assign(q, newLeaf(world, -20))
      if (q.y > h - 6 - q.depth) {
        if (resting < MAX_RESTING_LEAVES) {
          q.y = h - 6 - q.depth
          q.resting = 1
          resting++
        } else Object.assign(q, newLeaf(world, -20))
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s) {
    for (const q of s.p) {
      ctx.save()
      ctx.translate(q.x, q.y)
      ctx.rotate(q.rot)
      ctx.fillStyle = LEAF_COLORS[q.color]
      ctx.beginPath()
      ctx.moveTo(0, -q.size)
      ctx.quadraticCurveTo(q.size * 0.8, 0, 0, q.size)
      ctx.quadraticCurveTo(-q.size * 0.8, 0, 0, -q.size)
      ctx.fill()
      ctx.strokeStyle = 'rgba(70,30,10,0.5)'
      ctx.lineWidth = 1
      ctx.beginPath()
      ctx.moveTo(0, -q.size)
      ctx.lineTo(0, q.size * 1.3)
      ctx.stroke()
      ctx.restore()
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    for (const q of s.p) {
      const d = Math.hypot(q.x - x, q.y - y)
      if (d < 220) {
        q.resting = 0
        q.vx += ((q.x - x) / (d || 1)) * 500
        q.vy = -between(world.rnd, 350, 750)
      }
    }
  },
}

function newLeaf(world: World, y: number) {
  return {
    x: world.rnd() * world.w, y, vx: 0, vy: 60, fall: between(world.rnd, 50, 110),
    rot: world.rnd() * TAU, vr: between(world.rnd, -4, 4), size: between(world.rnd, 6, 11),
    color: Math.floor(world.rnd() * LEAF_COLORS.length), phase: world.rnd() * TAU,
    depth: world.rnd() * 26, resting: 0,
  }
}

// ---------- Sparks: neon sparks off the horizon and a streaking cursor trail. ----------

const NEON = ['#ff4fd8', '#00f0ff', '#ffd23f']

const sparks: Preset = {
  layer: 'back',
  init() {
    return { p: [], bits: [], max: 0 }
  },
  step(s, world) {
    const { dt, rnd, w, h, pointer } = world
    // Matches the horizon in themes.css, which sits lower on phones.
    const horizon = h * (w <= 640 ? 0.82 : 0.72)
    if (rnd() < dt * (world.wild ? 30 : 10)) {
      spawnBit(s.bits, {
        x: rnd() * w, y: horizon, vx: between(rnd, -60, 60), vy: -between(rnd, 120, 380), gravity: 380,
        shape: 'streak', size: 2, life: 1.2, color: NEON[Math.floor(rnd() * 2)],
      })
    }
    if (world.wild && pointer.active && speed(pointer) > 80) {
      spawnBit(s.bits, {
        x: pointer.x, y: pointer.y, vx: -pointer.vx * 0.4, vy: -pointer.vy * 0.4,
        shape: 'streak', size: 3, life: 0.5, color: NEON[Math.floor(rnd() * 2)],
      })
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s) {
    ctx.save()
    ctx.shadowBlur = 10
    ctx.shadowColor = '#ff4fd8'
    drawBits(ctx, s.bits)
    ctx.restore()
  },
  burst(s, world, x, y) {
    for (const color of NEON) burstBits(s.bits, world.rnd, x, y, 24, 520, { shape: 'streak', size: 2, color, gravity: 300 })
  },
}

export const PRESETS: Record<EffectKind, Preset> = {
  snow, rain, bubbles, sprinkles, stars, petals, leaves, plankton, matrix, sparks, ink, ecg, sand, desktop, glass, boost, blocks,
}
