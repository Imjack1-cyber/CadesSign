/**
 * iPadOS / iOS: the pointer and the celebrations of Liquid Glass. With a mouse at the Wild level the
 * cursor is the iPadOS pointer: a soft gray disc that springs into the shape of the button under it
 * (pulled a little towards the mouse), turns into a text cursor over fields and text, shrinks when
 * pressed, hides while typing and fades when left alone. A finger gets a glow where it lands on a
 * control. Results are celebrated the way Messages does it: confetti for a signature, balloons that
 * pop for a verified one. A saved file flies in an arc into Files, and the camera on the lock screen
 * flashes. The rest of the theme is DOM (IosShell.tsx) and reaches here as chrome events, so every
 * sound the theme makes is chosen in one place. Like the other presets it keeps its state in plain
 * arrays so tests can step it without a canvas; only draw() touches the 2D context.
 */
import { getIosPrefs } from '../iosPrefs'
import type { Outcome } from '../signals'
import { burstBits, drawBits, spawnBit, stepBits } from './bits'
import type { Box, Control, Preset, State, World } from './presets'
import type { Sound } from './sound'

const TAU = Math.PI * 2
const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

/** The free pointer's diameter, and the padding around a control it turns into. */
export const POINTER_SIZE = 19
const PAD = 3
/** Seconds the mouse may rest before the pointer fades away. */
export const POINTER_IDLE_S = 3
/** Controls bigger than this keep the round pointer; the page lifts them instead (themes.css). */
const MORPH_W = 280
const MORPH_H = 72
/** How far (px) a highlighted control's shape leans towards the mouse. */
const MAGNET = 5
/** Spring stiffness for a pointer following the mouse, and for one settling on a control. */
const FOLLOW_K = 2600
const SETTLE_K = 520
export const CONFETTI_MAX = 160
/** Confetti comes down over about a second and is gone within three or four, as in Messages. */
const CONFETTI_PER_S = 160
export const BALLOONS_MAX = 14
const BALLOONS = 10
export const FLY_S = 0.75
const MAX_FLY = 4
/** How long a result's status class stays on <html>, in ms. */
const STATUS_MS = 2500
/** A long-lived class is renewed this often (s), so it never lapses while the pointer is drawn. */
const RENEW_S = 1800

const COLORS = ['#FF3B30', '#FF9500', '#FFCC00', '#34C759', '#00C7BE', '#007AFF', '#5856D6', '#AF52DE', '#FF2D55']

const enum Kind { Confetti, Balloon }
const enum Shape { Circle, Highlight, Beam }

/** What a press sounds like, by control. Back and Next stay quiet here: the slide they cause swooshes. */
const PRESS: Record<Control, ((sound: Sound) => void) | null> = {
  button: s => s.glasstap(), choice: s => s.pickertick(), toggle: s => s.switchtick(), nav: s => s.glasstap(),
  field: null, upload: s => s.glasstap(), download: s => s.glasstap(), discard: s => s.glasstap(), back: null, forward: null,
  disabled: s => s.haptic(),
}

const STATUS: Record<Outcome, 'ok' | 'warn' | 'fail' | null> = { success: 'ok', warning: 'warn', error: 'fail', info: null }

type Thing = Record<string, number>

interface Glass extends State {
  /** The pointer: centre, size and corner radius with their velocities, opacity and press scale. */
  cur: Thing
  fly: Thing[]
}

const center = (b: Box) => ({ x: (b.left + b.right) / 2, y: (b.top + b.bottom) / 2 })

/** A short buzz in the hand, where the device can and the user wants it. */
function buzz(ms: number) {
  if (getIosPrefs().haptics && typeof navigator !== 'undefined') navigator.vibrate?.(ms)
}

/**
 * Moves `key` of `q` towards `target` on a slightly underdamped spring of stiffness `k`. The step is
 * implicit (backward Euler), so a stiff spring stays stable however long a frame takes.
 */
function spring(q: Thing, key: string, target: number, k: number, dt: number) {
  const v = `v${key}`
  const damping = 2 * Math.sqrt(k) * 0.8
  q[v] = (q[v] + k * (target - q[key]) * dt) / (1 + damping * dt + k * dt * dt)
  q[key] += q[v] * dt
}

function confetti(world: World): Thing {
  const { rnd, w } = world
  return {
    type: Kind.Confetti, x: rnd() * w, y: -between(rnd, 10, 60), vx: between(rnd, -60, 60), vy: between(rnd, 160, 320),
    fall: between(rnd, 210, 330), rot: rnd() * TAU, vr: between(rnd, -6, 6), flip: rnd() * TAU, vf: between(rnd, 4, 10),
    w: between(rnd, 6, 11), h: between(rnd, 3, 6), color: Math.floor(rnd() * COLORS.length), round: rnd() < 0.2 ? 1 : 0,
    phase: rnd() * TAU,
  }
}

/** How many balloons fit across the screen: ten on a desktop, about four on a phone. */
const balloonCount = (world: World) => clamp(Math.round(world.w / 130), 4, BALLOONS)

function balloon(world: World, i: number, n: number): Thing {
  const { rnd, w, h } = world
  return {
    type: Kind.Balloon, x: w * ((i + 0.5) / n) + between(rnd, -30, 30), y: h + between(rnd, 30, 200),
    vx: 0, vy: -between(rnd, 200, 280), r: between(rnd, 26, 40), color: Math.floor(rnd() * COLORS.length), phase: rnd() * TAU,
  }
}

function pop(s: State, world: World, b: Thing) {
  burstBits(s.bits, world.rnd, b.x, b.y, 18, 260, { color: COLORS[b.color], size: 2.5, gravity: 500 })
  spawnBit(s.bits, { x: b.x, y: b.y, shape: 'ring', size: b.r * 0.6, grow: 220, life: 0.25, color: 'rgba(255,255,255,0.8)' })
  world.sound?.balloonpop()
}

/** Wakes the pointer: any input brings it back after typing or a rest. */
function wake(s: Glass) {
  s.cur.still = 0
  s.cur.typed = 0
}

/** Where the pointer wants to be, and in what shape. */
function target(world: World): { x: number; y: number; w: number; h: number; r: number; shape: Shape } {
  const { pointer, hover } = world
  const free = { x: pointer.x, y: pointer.y, w: POINTER_SIZE, h: POINTER_SIZE, r: POINTER_SIZE / 2, shape: Shape.Circle }
  if (!hover || hover.kind === 'disabled') return free
  const { box } = hover
  const bw = box.right - box.left
  const bh = box.bottom - box.top
  if (hover.kind === 'field' || hover.kind === 'text') {
    const h = clamp(hover.kind === 'field' ? bh * 0.55 : hover.line * 1.05, 14, 40)
    return { x: pointer.x, y: hover.kind === 'field' ? center(box).y : pointer.y, w: 2.5, h, r: 1.25, shape: Shape.Beam }
  }
  if (bw > MORPH_W || bh > MORPH_H) return free
  const c = center(box)
  return {
    x: c.x + clamp((pointer.x - c.x) * 0.1, -MAGNET, MAGNET),
    y: c.y + clamp((pointer.y - c.y) * 0.1, -MAGNET, MAGNET),
    w: bw + PAD * 2, h: bh + PAD * 2,
    r: Math.min((bh + PAD * 2) / 2, (hover.radius || 10) + PAD),
    shape: Shape.Highlight,
  }
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.max(0, Math.min(r, w / 2, h / 2))
  ctx.beginPath()
  ctx.moveTo(x + rr, y)
  ctx.arcTo(x + w, y, x + w, y + h, rr)
  ctx.arcTo(x + w, y + h, x, y + h, rr)
  ctx.arcTo(x, y + h, x, y, rr)
  ctx.arcTo(x, y, x + w, y, rr)
  ctx.closePath()
}

function drawConfetti(ctx: CanvasRenderingContext2D, q: Thing) {
  ctx.save()
  ctx.translate(q.x, q.y)
  ctx.rotate(q.rot)
  // Each piece tumbles: its face narrows to an edge and widens again.
  ctx.scale(1, Math.cos(q.flip))
  ctx.fillStyle = COLORS[q.color]
  if (q.round) {
    ctx.beginPath()
    ctx.arc(0, 0, q.h, 0, TAU)
    ctx.fill()
  } else ctx.fillRect(-q.w / 2, -q.h / 2, q.w, q.h)
  ctx.restore()
}

function drawBalloon(ctx: CanvasRenderingContext2D, b: Thing, t: number) {
  const { x, y, r } = b
  const sway = Math.sin(t * 1.4 + b.phase) * 8
  // The string, hanging from the knot and trailing behind the rise.
  ctx.strokeStyle = 'rgba(140,140,150,0.6)'
  ctx.lineWidth = 1
  ctx.beginPath()
  ctx.moveTo(x, y + r * 1.2)
  ctx.bezierCurveTo(x + sway, y + r * 2, x - sway, y + r * 2.6, x + sway * 0.5, y + r * 3.4)
  ctx.stroke()
  const g = ctx.createRadialGradient(x - r * 0.35, y - r * 0.45, r * 0.1, x, y, r * 1.2)
  g.addColorStop(0, 'rgba(255,255,255,0.85)')
  g.addColorStop(0.25, COLORS[b.color])
  g.addColorStop(1, 'rgba(0,0,0,0.35)')
  ctx.fillStyle = COLORS[b.color]
  ctx.beginPath()
  ctx.ellipse(x, y, r, r * 1.18, 0, 0, TAU)
  ctx.fill()
  ctx.fillStyle = g
  ctx.globalAlpha = 0.55
  ctx.fill()
  ctx.globalAlpha = 1
  ctx.fillStyle = COLORS[b.color]
  ctx.beginPath()
  ctx.moveTo(x, y + r * 1.12)
  ctx.lineTo(x - 5, y + r * 1.28)
  ctx.lineTo(x + 5, y + r * 1.28)
  ctx.closePath()
  ctx.fill()
}

/** A document flying from where it was made to Files, along an arc, shrinking as it goes. */
function flyAt(f: Thing) {
  const k = clamp(f.t / FLY_S, 0, 1)
  // Ease in and out, along a quadratic arc that peaks above both ends.
  const e = k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2
  const cx = (f.fx + f.tx) / 2
  const cy = Math.min(f.fy, f.ty) - 160
  const x = (1 - e) ** 2 * f.fx + 2 * (1 - e) * e * cx + e ** 2 * f.tx
  const y = (1 - e) ** 2 * f.fy + 2 * (1 - e) * e * cy + e ** 2 * f.ty
  return { x, y, scale: 1 - 0.6 * e }
}

function drawDoc(ctx: CanvasRenderingContext2D, x: number, y: number, scale: number) {
  const w = 24 * scale
  const h = 30 * scale
  ctx.save()
  ctx.shadowColor = 'rgba(0,0,0,0.25)'
  ctx.shadowBlur = 10 * scale
  ctx.shadowOffsetY = 3 * scale
  ctx.fillStyle = '#fff'
  roundRect(ctx, x - w / 2, y - h / 2, w, h, 3 * scale)
  ctx.fill()
  ctx.restore()
  ctx.fillStyle = '#d1d1d6'
  ctx.beginPath()
  ctx.moveTo(x + w / 2 - 7 * scale, y - h / 2)
  ctx.lineTo(x + w / 2, y - h / 2 + 7 * scale)
  ctx.lineTo(x + w / 2 - 7 * scale, y - h / 2 + 7 * scale)
  ctx.closePath()
  ctx.fill()
  ctx.fillStyle = '#8e8e93'
  for (let i = 0; i < 3; i++) ctx.fillRect(x - w / 2 + 4 * scale, y - h / 2 + (11 + i * 5) * scale, (i === 2 ? 9 : 15) * scale, 1.6 * scale)
}

export const glass: Preset = {
  layer: 'top',
  init(world) {
    const s: Glass = {
      p: [], bits: [], max: CONFETTI_MAX + BALLOONS_MAX, fly: [],
      cur: {
        x: world.w / 2, y: world.h / 2, w: POINTER_SIZE, h: POINTER_SIZE, r: POINTER_SIZE / 2,
        vx: 0, vy: 0, vw: 0, vh: 0, vr: 0, a: 0, press: 1, vpress: 0, shape: Shape.Circle,
        still: 0, typed: 0, lastX: 0, lastY: 0, on: 0, onAt: 0,
      },
      confettiLeft: 0, confettiT: 0, flash: 0, volume: -1,
    }
    return s
  },
  start(_s, world) {
    world.sound?.volume(getIosPrefs().volume)
    world.sound?.unlockchime()
  },
  step(state, world) {
    const s = state as Glass
    const { dt, t, pointer, w, h } = world
    const prefs = getIosPrefs()
    if (prefs.volume !== s.volume) {
      s.volume = prefs.volume
      world.sound?.volume(prefs.volume)
    }

    // The pointer: drawn only for a mouse, at Wild, when the user wants it.
    const c = s.cur
    const on = world.wild && prefs.pointer && pointer.active && !pointer.touch
    if (+on !== c.on || (on && t - c.onAt > RENEW_S)) {
      c.on = +on
      c.onAt = t
      world.signal('pointer', on ? RENEW_S * 2000 : 0)
    }
    if (Math.abs(pointer.x - c.lastX) + Math.abs(pointer.y - c.lastY) > 1) wake(s)
    else c.still += dt
    c.lastX = pointer.x
    c.lastY = pointer.y
    const goal = target(world)
    // A newly shown pointer starts where the mouse is rather than flying in from the last place.
    if (c.a < 0.02) {
      c.x = goal.x
      c.y = goal.y
    }
    const k = goal.shape === Shape.Circle ? FOLLOW_K : SETTLE_K
    spring(c, 'x', goal.x, k, dt)
    spring(c, 'y', goal.y, k, dt)
    spring(c, 'w', goal.w, SETTLE_K, dt)
    spring(c, 'h', goal.h, SETTLE_K, dt)
    spring(c, 'r', goal.r, SETTLE_K, dt)
    spring(c, 'press', pointer.down ? 0.88 : 1, 900, dt)
    c.shape = goal.shape
    const visible = on && !c.typed && c.still < POINTER_IDLE_S
    // Fades in quickly; fades out slowly when left alone, quickly when typing starts or a finger takes over.
    const rate = visible ? 14 : c.typed || !on ? 12 : 2.5
    c.a += ((visible ? 1 : 0) - c.a) * Math.min(1, rate * dt)
    c.w = Math.max(1, c.w)
    c.h = Math.max(1, c.h)

    // Confetti falls in over a second or so, then flutters down.
    if ((s.confettiLeft as number) > 0) {
      s.confettiT = (s.confettiT as number) + dt * CONFETTI_PER_S
      while ((s.confettiT as number) >= 1 && (s.confettiLeft as number) > 0) {
        s.confettiT = (s.confettiT as number) - 1
        s.confettiLeft = (s.confettiLeft as number) - 1
        if (s.p.filter(q => q.type === Kind.Confetti).length < CONFETTI_MAX) s.p.push(confetti(world))
      }
    }
    for (let i = s.p.length - 1; i >= 0; i--) {
      const q = s.p[i]
      if (q.type === Kind.Confetti) {
        q.vy += (q.fall - q.vy) * 1.5 * dt
        q.vx *= 1 - 1.2 * dt
        q.x += (q.vx + Math.sin(t * 2 + q.phase) * 30) * dt
        q.y += q.vy * dt
        q.rot += q.vr * dt
        q.flip += q.vf * dt
        if (q.y > h + 20) s.p.splice(i, 1)
        continue
      }
      // Balloons rise and sway, and drift aside from the pointer.
      if (world.wild && pointer.active) {
        const dx = q.x - pointer.x
        const dy = q.y - pointer.y
        const d = Math.hypot(dx, dy)
        if (d < q.r * 2 && d > 1) q.vx += (dx / d) * 300 * dt
      }
      q.vx *= 1 - 1.5 * dt
      q.x = clamp(q.x + (q.vx + Math.sin(t * 1.2 + q.phase) * 14) * dt, -q.r, w + q.r)
      q.y += q.vy * dt
      if (q.y < -q.r * 4) s.p.splice(i, 1)
    }

    for (let i = s.fly.length - 1; i >= 0; i--) {
      const f = s.fly[i]
      f.t += dt
      if (f.t >= FLY_S) {
        spawnBit(s.bits, { x: f.tx, y: f.ty, shape: 'ring', size: 6, grow: 90, life: 0.35, color: 'rgba(0,122,255,0.7)' })
        s.fly.splice(i, 1)
      }
    }
    s.flash = Math.max(0, (s.flash as number) - dt * 4)
    stepBits(s.bits, dt)
  },
  draw(ctx, state, world) {
    const s = state as Glass
    for (const q of s.p) {
      if (q.type === Kind.Confetti) drawConfetti(ctx, q)
      else drawBalloon(ctx, q, world.t)
    }
    for (const f of s.fly) {
      const { x, y, scale } = flyAt(f)
      drawDoc(ctx, x, y, scale)
    }
    drawBits(ctx, s.bits)
    if ((s.flash as number) > 0) {
      ctx.fillStyle = `rgba(255,255,255,${0.9 * (s.flash as number)})`
      ctx.fillRect(0, 0, world.w, world.h)
    }
    const c = s.cur
    if (c.a < 0.01) return
    const w = c.w * c.press
    const h = c.h * c.press
    ctx.globalAlpha = c.a
    // A neutral gray reads on light and dark glass alike; over a control it only tints it.
    ctx.fillStyle = c.shape === Shape.Beam ? 'rgba(110,110,120,0.9)' : c.shape === Shape.Highlight ? 'rgba(118,118,128,0.2)' : 'rgba(118,118,128,0.42)'
    roundRect(ctx, c.x - w / 2, c.y - h / 2, w, h, c.r * c.press)
    ctx.fill()
    ctx.globalAlpha = 1
  },
  burst(state, world, x, y) {
    const s = state as Glass
    wake(s)
    for (let i = s.p.length - 1; i >= 0; i--) {
      const b = s.p[i]
      if (b.type !== Kind.Balloon || Math.hypot(b.x - x, (b.y - y) / 1.18) > b.r) continue
      s.p.splice(i, 1)
      pop(s, world, b)
      return
    }
    const control = world.pointer.control
    if (!control) return
    const voice = PRESS[control]
    if (voice && world.sound) voice(world.sound)
    if (world.pointer.touch && control !== 'disabled') {
      // Liquid Glass lights up where the finger lands.
      spawnBit(s.bits, { x, y, size: 14, life: 0.3, color: 'rgba(255,255,255,0.35)' })
      spawnBit(s.bits, { x, y, shape: 'ring', size: 8, grow: 160, life: 0.35, color: 'rgba(255,255,255,0.7)' })
      buzz(8)
    }
  },
  key(state, world, k) {
    const s = state as Glass
    // iPadOS hides the pointer while you type, until the mouse moves again.
    s.cur.typed = 1
    if (!getIosPrefs().keyClicks) return
    world.sound?.keytap(k.kind === 'char' ? 'char' : k.kind === 'delete' ? 'delete' : 'modifier')
  },
  browse(_s, world, index) {
    world.sound?.pickertick(index)
  },
  busy(_s, world, on) {
    world.signal('busy', on ? 60_000 : 0)
  },
  outcome(state, world, kind, _box, action) {
    const s = state as Glass
    const status = STATUS[kind]
    if (status) world.signal(status, STATUS_MS)
    switch (kind) {
      case 'success':
        world.sound?.success()
        if (action === 'verify') {
          // Balloons for a signature that checks out; poppable, at most a handful at a time.
          const n = balloonCount(world)
          const room = BALLOONS_MAX - s.p.filter(q => q.type === Kind.Balloon).length
          for (let i = 0; i < Math.min(n, room); i++) s.p.push(balloon(world, i, n))
          world.sound?.triad()
        } else {
          s.confettiLeft = Math.min(CONFETTI_MAX, (s.confettiLeft as number) + CONFETTI_MAX - 20)
          world.sound?.popper()
        }
        return
      case 'warning':
        world.sound?.caution()
        return
      case 'error':
        world.sound?.failure()
        buzz(60)
        return
      default:
        world.sound?.notify()
    }
  },
  activity(_s, world, a) {
    const { sound } = world
    switch (a) {
      case 'forward':
      case 'back':
        // The new step slides in from the side it comes from (themes.css).
        world.signal(a === 'forward' ? 'push' : 'pop', 500)
        sound?.sheet(a === 'forward')
        return
      case 'file-in': sound?.airdrop(); return
      case 'file-out': sound?.discard(); return
      case 'saved': sound?.sent(); return
      case 'panel-open': sound?.sheet(true); return
      case 'panel-close': sound?.sheet(false); return
      case 'tab': sound?.pickertick(); return
    }
  },
  chrome(state, world, event, motion) {
    const s = state as Glass
    const { sound } = world
    const prefs = getIosPrefs()
    wake(s)
    switch (event) {
      case 'lock':
        if (prefs.lockSound) sound?.lockclick()
        return
      case 'unlock': sound?.unlockchime(); return
      case 'sheet-open': sound?.sheet(true); return
      case 'sheet-close': sound?.sheet(false); return
      case 'banner':
        if (!prefs.focus) sound?.notify()
        return
      case 'long-press':
        sound?.haptic()
        buzz(10)
        return
      case 'switch': sound?.switchtick(); return
      case 'volume':
        // The click plays at the new level, as the volume buttons do.
        s.volume = prefs.volume
        sound?.volume(prefs.volume)
        sound?.keytap('modifier')
        return
      case 'camera':
        s.flash = 1
        sound?.shutter()
        return
      case 'charge': sound?.chargechime(); return
      case 'battery': sound?.lowbattery(); return
      case 'fly': {
        if (!motion.from || !motion.to) return
        if (s.fly.length >= MAX_FLY) s.fly.shift()
        const from = center(motion.from)
        const to = center(motion.to)
        s.fly.push({ fx: from.x, fy: from.y, tx: to.x, ty: to.y, t: 0 })
        return
      }
    }
  },
  command(_s, world, ok) {
    if (ok) world.sound?.glasstap()
    else world.sound?.failure()
  },
}
