/**
 * Deep Sea: light shafts from the surface, marine snow sinking past in three depths, plankton that
 * glows only when something stirs the water, a school of fish that flocks, flees the flashlight and
 * scatters on a click but gathers in a light held still, and jellyfish that pulse their way upwards
 * trailing tentacles. Typing sends bubbles up from the caret and holding a press on bare water blows a
 * stream of them; sounds come from where they happen. A request pings sonar across the screen while
 * an anglerfish's lure bobs in the dark and draws the school in, and results answer with a whale call
 * or the hull groaning. Leave it alone long enough
 * and a whale passes far behind. Like the other presets it keeps its state in plain arrays so tests
 * can step it without a canvas; only draw() touches the 2D context.
 */
import type { Outcome } from '../signals'
import { burstBits, drawBits, scaleCount, spawnBit, stepBits } from './bits'
import type { Control, Preset, State, World } from './presets'
import type { Sound } from './sound'

const TAU = Math.PI * 2
const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

/** Seconds between two sonar pings while a request runs. */
export const PING_S = 1.6
/** Seconds without any input before a whale passes. */
export const WHALE_IDLE_S = 40
/** How long a result tints the plankton, in seconds. */
const TINT_S = 2.5
/** Fish cruise at this speed in px/s and flee at up to 3.5 times it. */
const CRUISE = 60
const NEIGHBOUR = 70
const SPACE = 20
/** The pointer scares fish within this radius when it moves faster than FLEE_SPEED px/s. */
const FLEE_R = 170
const FLEE_SPEED = 160
/** The flashlight's reach in px, and how long it must stay still (s) before fish come to it. */
const BEAM_R = 380
const STILL_S = 1
/** Bubbles per second while a press is held on bare water. */
const BLOW_PER_S = 14
/** What a resize keeps, so a request, a tint or a passing whale carries on. */
const KEEP = ['busy', 'pingT', 'lure', 'tint', 'tintT', 'whale', 'whaleX', 'idle', 'circleT'] as const
/** Tentacle segments per jellyfish, and their length in bell sizes. */
const SEGMENTS = 8
const MAX_BUBBLES = 120
/** Scrolled px per swish. */
const SWISH_PX = 160
/** Semitone steps of a major pentatonic scale, for browsing a list. */
const PENTATONIC = [0, 2, 4, 7, 9]

const enum Tint { None, Warn, Fail }

/** What a press sounds like, by control. Back and Next stay quiet here: the move they cause swishes. */
const PRESS: Record<Control, ((sound: Sound, pan: number) => void) | null> = {
  button: (s, pan) => s.bubble(1, 0, pan), choice: (s, pan) => s.sonar(1, pan), toggle: (s, pan) => s.bubble(0.8, 0, pan),
  nav: (s, pan) => s.swish(pan), field: (s, pan) => s.sonar(1, pan), upload: (s, pan) => s.bubble(0.7, 0, pan),
  download: (s, pan) => s.sonar(1, pan), discard: (s, pan) => s.bubble(1.6, 0, pan), back: null, forward: null,
  disabled: s => s.deny(),
}

const STATUS: Record<Outcome, 'ok' | 'warn' | 'fail' | null> = { success: 'ok', warning: 'warn', error: 'fail', info: null }

type Thing = Record<string, number>

interface Sea extends State {
  snow: Thing[]
  fish: Thing[]
  jelly: Thing[]
  /** One tentacle centre line per jellyfish, as x, y pairs from the bell down. */
  tails: number[][]
  bubbles: Thing[]
  /** Sonar and focus rings; the plankton they pass light up. */
  pings: Thing[]
}

/** How lit a point is: in the flashlight's beam when there is one, a dim half-light otherwise. Touch has no beam. */
function light(world: World, x: number, y: number) {
  const { pointer } = world
  if (!world.wild || !pointer.active || pointer.touch) return 0.5
  return 0.15 + 0.85 * Math.max(0, 1 - Math.hypot(x - pointer.x, y - pointer.y) / BEAM_R)
}

/** Stereo position for a sound at x: a little short of the far left and right. */
const panAt = (world: World, x: number) => clamp((x / world.w) * 2 - 1, -1, 1) * 0.8

/** Where the anglerfish's lure bobs. */
function lureAt(world: World) {
  const { t, w, h } = world
  return { x: w * 0.8 + Math.sin(t * 0.6) * 30, y: h * 0.82 + Math.sin(t * 1.3) * 10 }
}

function newJelly(world: World, y: number): Thing {
  return {
    x: between(world.rnd, 0.1, 0.9) * world.w, y, vx: 0, vy: 0, size: between(world.rnd, 16, 30),
    phase: world.rnd() * TAU, rate: between(world.rnd, 0.6, 0.9), flash: 0, alarm: 0, touched: 0,
  }
}

function newTail(j: Thing) {
  return Array.from({ length: SEGMENTS * 2 }, (_, i) => (i % 2 ? j.y + (i >> 1) * j.size * 0.4 : j.x))
}

/** Lets a bubble go at (x, y); the oldest goes when there are too many. */
function bubbleAt(s: Sea, world: World, x: number, y: number, r: number) {
  if (s.bubbles.length >= MAX_BUBBLES) s.bubbles.shift()
  s.bubbles.push({ x, y, r, vy: -between(world.rnd, 10, 30), phase: world.rnd() * TAU })
}

function pop(s: Sea, b: Thing) {
  spawnBit(s.bits, { x: b.x, y: b.y, shape: 'ring', size: b.r, grow: 40, life: 0.3, color: 'rgba(190,245,255,0.7)' })
}

function ping(s: Sea, x: number, y: number, reach: number) {
  s.pings.push({ x, y, r: 0, reach })
}

/** Lights the plankton within `radius` of (x, y), brightest at the middle. */
function stir(s: Sea, x: number, y: number, radius: number, amount = 1) {
  for (const q of s.p) {
    const d = Math.hypot(q.x - x, q.y - y)
    if (d < radius) q.glow = Math.max(q.glow, amount * (1 - d / radius))
  }
}

/** Startles the fish within `radius` of (x, y) and sends them away from it. */
function scare(s: Sea, x: number, y: number, radius: number) {
  for (const f of s.fish) {
    const dx = f.x - x
    const dy = f.y - y
    const d = Math.hypot(dx, dy) || 1
    if (d > radius) continue
    const k = 1 - d / radius
    f.startle = Math.max(f.startle, k)
    f.vx += (dx / d) * 260 * k
    f.vy += (dy / d) * 260 * k
  }
}

/**
 * Where the school is heading: the middle of the screen while it circles, just above the anglerfish's
 * lure while a request runs, or a slow wander.
 */
function goal(s: Sea, world: World) {
  if ((s.circleT as number) > 0) return { x: world.w / 2, y: world.h * 0.45 }
  if (s.busy && (s.lure as number) > 0.5) {
    const lure = lureAt(world)
    return { x: lure.x - 60, y: lure.y - 50 }
  }
  return {
    x: world.w * (0.5 + 0.35 * Math.sin(world.t * 0.05)),
    y: world.h * (0.5 + 0.25 * Math.sin(world.t * 0.083 + 1)),
  }
}

function swim(s: Sea, world: World) {
  const { dt, w, h, pointer } = world
  const target = goal(s, world)
  const circling = (s.circleT as number) > 0
  // A finger jumps from place to place, which would read as a lunge; only a mouse scares or lures them.
  const mouse = world.wild && pointer.active && !pointer.touch
  const fleeing = mouse && Math.hypot(pointer.vx, pointer.vy) > FLEE_SPEED
  const lit = mouse && (s.stillT as number) >= STILL_S
  const top = h * 0.08
  const bottom = h * 0.92
  const margin = 80
  for (const f of s.fish) {
    let sx = 0, sy = 0, ax = 0, ay = 0, cx = 0, cy = 0, n = 0
    for (const o of s.fish) {
      if (o === f) continue
      const dx = o.x - f.x
      const dy = o.y - f.y
      const d2 = dx * dx + dy * dy
      if (d2 > NEIGHBOUR * NEIGHBOUR) continue
      n++
      ax += o.vx
      ay += o.vy
      cx += o.x
      cy += o.y
      if (d2 < SPACE * SPACE) {
        const d = Math.sqrt(d2) || 1
        sx -= (dx / d) * (SPACE - d)
        sy -= (dy / d) * (SPACE - d)
      }
    }
    // Separation, alignment and cohesion, a pull towards where the school is going, and the walls.
    let fx = sx * 3
    let fy = sy * 3
    if (n) {
      fx += (ax / n - f.vx) * 0.8 + (cx / n - f.x) * 0.4
      fy += (ay / n - f.vy) * 0.8 + (cy / n - f.y) * 0.4
    }
    const gx = target.x - f.x
    const gy = target.y - f.y
    if (circling) {
      // Round and round the middle, about 160 px out.
      const d = Math.hypot(gx, gy) || 1
      fx += (-gy / d) * 140 + (gx / d) * (d - 160) * 0.6
      fy += (gx / d) * 140 + (gy / d) * (d - 160) * 0.6
    } else {
      fx += gx * 0.08
      fy += gy * 0.08
    }
    if (f.x < margin) fx += (margin - f.x) * 4
    if (f.x > w - margin) fx -= (f.x - (w - margin)) * 4
    if (f.y < top) fy += (top - f.y) * 4
    if (f.y > bottom) fy -= (f.y - bottom) * 4
    if (lit) {
      // Fish come to a steady light, and hang about it without touching.
      const dx = pointer.x - f.x
      const dy = pointer.y - f.y
      const d = Math.hypot(dx, dy) || 1
      if (d < BEAM_R) {
        const k = d < 50 ? -120 : 90 * (1 - d / BEAM_R)
        fx += (dx / d) * k
        fy += (dy / d) * k
      }
    }
    if (fleeing) {
      const dx = f.x - pointer.x
      const dy = f.y - pointer.y
      const d = Math.hypot(dx, dy) || 1
      if (d < FLEE_R) {
        const k = 1 - d / FLEE_R
        f.startle = Math.max(f.startle, k)
        fx += (dx / d) * 1600 * k
        fy += (dy / d) * 1600 * k
      }
    }
    f.vx += (fx + (s.current as number) * 0.6) * dt
    f.vy += fy * dt
    const topSpeed = CRUISE * (1 + 2.5 * f.startle)
    const v = Math.hypot(f.vx, f.vy) || 1
    const scale = v > topSpeed ? topSpeed / v : v < CRUISE * 0.4 ? (CRUISE * 0.4) / v : 1
    f.vx *= scale
    f.vy *= scale
    f.x = clamp(f.x + f.vx * dt, 0, w)
    f.y = clamp(f.y + f.vy * dt, 0, h)
    f.startle = Math.max(0, f.startle - dt * 0.8)
    // The tail beats faster the faster the fish goes.
    f.phase += dt * (5 + v * 0.06)
  }
}

function pulse(s: Sea, world: World) {
  const { dt, h, pointer } = world
  s.jelly.forEach((j, i) => {
    const touching = world.wild && pointer.active && Math.hypot(pointer.x - j.x, pointer.y - j.y) < j.size * 1.4
    if (touching && !j.touched) {
      j.flash = 1
      world.sound?.bubble(0.5, 0, panAt(world, j.x))
    }
    j.touched = touching ? 1 : 0
    // The bell only pushes while it contracts, so the jellyfish rises in pulses and sinks a little between.
    j.phase += dt * TAU * j.rate * (j.flash > 0.3 ? 2.2 : 1)
    const squeeze = Math.max(0, Math.sin(j.phase))
    j.vy -= squeeze * 70 * dt
    j.vx += (Math.sin(world.t * 0.2 + i * 2) * 4 + (s.current as number) * 0.2) * dt
    j.vy += 6 * dt
    j.vx *= 1 - 1.2 * dt
    j.vy *= 1 - 1.2 * dt
    j.x += j.vx * dt
    j.y += j.vy * dt
    j.flash = Math.max(0, j.flash - dt * 0.9)
    j.alarm = Math.max(0, j.alarm - dt * 0.5)
    if (j.y < -j.size * 6) {
      Object.assign(j, newJelly(world, h + j.size * 2))
      s.tails[i] = newTail(j)
    }
    // Each tentacle segment trails the one above at a fixed length, swaying a little.
    const tail = s.tails[i]
    const len = j.size * 0.4
    tail[0] = j.x
    tail[1] = j.y + j.size * 0.35
    for (let k = 1; k < SEGMENTS; k++) {
      const px = tail[(k - 1) * 2]
      const py = tail[(k - 1) * 2 + 1]
      let x = tail[k * 2] + Math.sin(world.t * 1.3 + k * 0.7 + i) * 6 * dt
      let y = tail[k * 2 + 1] + 10 * dt
      const d = Math.hypot(x - px, y - py) || 1
      x = px + ((x - px) / d) * len
      y = py + ((y - py) / d) * len
      tail[k * 2] = x
      tail[k * 2 + 1] = y
    }
  })
}

function drawFish(ctx: CanvasRenderingContext2D, f: Thing, alpha: number) {
  ctx.save()
  ctx.translate(f.x, f.y)
  ctx.rotate(Math.atan2(f.vy, f.vx))
  const s = f.size
  const wag = Math.sin(f.phase) * 0.45
  ctx.fillStyle = `rgba(150,215,235,${alpha})`
  ctx.beginPath()
  ctx.moveTo(s, 0)
  ctx.quadraticCurveTo(0.2 * s, -0.42 * s, -0.7 * s, 0)
  ctx.quadraticCurveTo(0.2 * s, 0.42 * s, s, 0)
  ctx.fill()
  // The tail fin swings from the root.
  ctx.translate(-0.65 * s, 0)
  ctx.rotate(wag)
  ctx.beginPath()
  ctx.moveTo(0, 0)
  ctx.lineTo(-0.5 * s, -0.3 * s)
  ctx.lineTo(-0.4 * s, 0)
  ctx.lineTo(-0.5 * s, 0.3 * s)
  ctx.closePath()
  ctx.fill()
  ctx.restore()
}

function drawJelly(ctx: CanvasRenderingContext2D, j: Thing, tail: number[], alpha: number) {
  const squeeze = Math.max(0, Math.sin(j.phase))
  const bw = j.size * (1 - 0.25 * squeeze)
  const bh = j.size * 0.7 * (1 + 0.15 * squeeze)
  const glow = 0.25 + 0.75 * j.flash
  const rgb = j.alarm > 0.05 ? '255,90,110' : '200,150,255'
  const a = Math.min(1, alpha + 0.4 * j.flash + 0.5 * j.alarm)
  // Tentacles: the centre line, offset for each of four.
  ctx.strokeStyle = `rgba(${rgb},${0.35 * a})`
  ctx.lineWidth = 1
  for (let t = -1.5; t <= 1.5; t++) {
    ctx.beginPath()
    for (let k = 0; k < SEGMENTS; k++) {
      const spread = t * bw * 0.25 * (1 - (k / SEGMENTS) * 0.5)
      const x = tail[k * 2] + spread
      const y = tail[k * 2 + 1]
      if (k) ctx.lineTo(x, y)
      else ctx.moveTo(x, y)
    }
    ctx.stroke()
  }
  ctx.fillStyle = `rgba(${rgb},${0.12 * glow})`
  ctx.beginPath()
  ctx.arc(j.x, j.y, bw * 1.8, 0, TAU)
  ctx.fill()
  ctx.fillStyle = `rgba(${rgb},${0.3 * a})`
  ctx.beginPath()
  ctx.ellipse(j.x, j.y, bw, bh, 0, Math.PI, TAU)
  ctx.quadraticCurveTo(j.x, j.y + bh * 0.3, j.x - bw, j.y)
  ctx.fill()
}

function drawWhale(ctx: CanvasRenderingContext2D, x: number, y: number, s: number) {
  ctx.fillStyle = 'rgba(110,190,215,0.06)'
  ctx.beginPath()
  ctx.ellipse(x, y, s, s * 0.22, 0, 0, TAU)
  ctx.fill()
  ctx.beginPath()
  ctx.moveTo(x - s * 0.9, y)
  ctx.quadraticCurveTo(x - s * 1.2, y - s * 0.05, x - s * 1.4, y - s * 0.22)
  ctx.lineTo(x - s * 1.25, y)
  ctx.lineTo(x - s * 1.4, y + s * 0.22)
  ctx.quadraticCurveTo(x - s * 1.2, y + s * 0.05, x - s * 0.9, y)
  ctx.fill()
}

/** Resets the idle clock; the whale only comes when nobody is around. */
const stirred = (s: State) => {
  s.idle = 0
}

export const plankton: Preset = {
  layer: 'back',
  init(world, prev) {
    const { rnd, w, h } = world
    const n = scaleCount(world, world.wild ? 170 : 80)
    const p = Array.from({ length: n }, () => ({
      x: rnd() * w, y: rnd() * h, vx: 0, vy: 0, r: between(rnd, 0.8, 2.2), phase: rnd() * TAU,
      hue: between(rnd, 175, 200), glow: 0,
    }))
    const snow = Array.from({ length: scaleCount(world, world.wild ? 120 : 70) }, () => {
      const z = [0.3, 0.6, 1][Math.floor(rnd() * 3)]
      return { x: rnd() * w, y: rnd() * h, z, r: 0.5 + 1.2 * z, phase: rnd() * TAU }
    })
    const fish = Array.from({ length: scaleCount(world, world.wild ? 36 : 24) }, () => ({
      x: w * between(rnd, 0.3, 0.7), y: h * between(rnd, 0.3, 0.7), vx: between(rnd, -1, 1) * CRUISE,
      vy: between(rnd, -0.3, 0.3) * CRUISE, size: between(rnd, 7, 12), phase: rnd() * TAU, startle: 0,
    }))
    const jelly = Array.from({ length: w < 640 ? 2 : 3 }, () => newJelly(world, between(rnd, 0.3, 1) * h))
    const sea: Sea = {
      p, bits: [], max: n, snow, fish, jelly, tails: jelly.map(newTail), bubbles: [], pings: [],
      busy: 0, pingT: 0, lure: 0, tint: Tint.None, tintT: 0, wave: -1, circleT: 0, current: 0,
      idle: 0, whaleX: 0, whale: 0, scrolled: 0, stillT: 0, blowT: 0, blown: 0,
    }
    if (prev) for (const k of KEEP) sea[k] = prev[k]
    return sea
  },
  start(_s, world) {
    world.sound?.ocean(true)
  },
  step(state, world) {
    const s = state as Sea
    const { dt, t, w, h, rnd, pointer } = world
    const speed = Math.hypot(pointer.vx, pointer.vy)
    const current = s.current as number
    s.current = current * Math.exp(-1.5 * dt)
    s.tintT = Math.max(0, (s.tintT as number) - dt)
    if (!s.tintT) s.tint = Tint.None
    s.circleT = Math.max(0, (s.circleT as number) - dt)
    if ((s.wave as number) >= 0) {
      s.wave = (s.wave as number) + 900 * dt
      if ((s.wave as number) > w + 100) s.wave = -1
    }
    s.stillT = world.wild && pointer.active && speed < 30 ? (s.stillT as number) + dt : 0
    // Holding a press on bare water blows a stream of bubbles and leaves a glowing wake behind the pointer.
    if (world.wild && pointer.down && pointer.bare) {
      stir(s, pointer.x, pointer.y, 50, 0.8)
      s.blowT = (s.blowT as number) + dt * BLOW_PER_S
      while ((s.blowT as number) >= 1) {
        s.blowT = (s.blowT as number) - 1
        bubbleAt(s, world, pointer.x + between(rnd, -6, 6), pointer.y + between(rnd, -4, 4), between(rnd, 1.5, 4))
        s.blown = (s.blown as number) + 1
        if ((s.blown as number) % 2) world.sound?.bubble(between(rnd, 0.8, 1.3), 0, panAt(world, pointer.x))
      }
    } else {
      s.blowT = 0
    }

    for (const m of s.snow) {
      m.y += (6 + 14 * m.z) * dt
      m.x += (Math.sin(t * 0.3 + m.phase) * 4 + world.wind * 3 + current * 0.3) * m.z * dt
      if (m.y > h) m.y -= h
      if (m.y < 0) m.y += h
      if (m.x < 0) m.x += w
      if (m.x > w) m.x -= w
    }

    // Plankton drift on their own and light up when the water around them is stirred.
    const disturbing = world.wild && pointer.active && speed > 200
    const wave = s.wave as number
    for (const q of s.p) {
      q.vx += (rnd() - 0.5) * 40 * dt
      q.vy += (rnd() - 0.5) * 40 * dt
      if (disturbing) {
        const d = Math.hypot(q.x - pointer.x, q.y - pointer.y)
        if (d < 120) {
          const k = 1 - d / 120
          q.glow = Math.max(q.glow, k * Math.min(1, speed / 800))
          q.vx += pointer.vx * 0.3 * k * dt
          q.vy += pointer.vy * 0.3 * k * dt
        }
      }
      if (wave >= 0 && Math.abs(q.x - wave) < 60) q.glow = 1
      q.vx *= 1 - 0.9 * dt
      q.vy *= 1 - 0.9 * dt
      q.x += (q.vx + Math.sin(t * 0.5 + q.phase) * 5 + current * 0.5) * dt
      q.y += (q.vy - 3) * dt
      q.glow *= Math.exp(-1.2 * dt)
      if (q.x < 0) q.x += w
      if (q.x > w) q.x -= w
      if (q.y < 0) q.y += h
      if (q.y > h) q.y -= h
    }
    // Fish darting past set them off too.
    for (const f of s.fish) {
      if (f.startle < 0.3) continue
      for (const q of s.p) {
        if (Math.abs(q.x - f.x) < 24 && Math.abs(q.y - f.y) < 24) q.glow = Math.max(q.glow, 0.6)
      }
    }

    swim(s, world)
    pulse(s, world)

    for (let i = s.bubbles.length - 1; i >= 0; i--) {
      const b = s.bubbles[i]
      // Bubbles speed up to their rising speed, wobble side to side and swell as the pressure drops.
      b.vy += (-(50 + b.r * 14) - b.vy) * 1.5 * dt
      b.phase += dt * 8
      b.x += (Math.sin(b.phase) * b.r * 6 + current * 0.4) * dt
      b.y += b.vy * dt
      b.r = Math.min(9, b.r * (1 + 0.03 * dt))
      if (b.y < 20) {
        pop(s, b)
        s.bubbles.splice(i, 1)
      }
    }

    for (let i = s.pings.length - 1; i >= 0; i--) {
      const r = s.pings[i]
      r.r += 420 * dt
      // The plankton light up as the ring passes them.
      for (const q of s.p) {
        if (Math.abs(Math.hypot(q.x - r.x, q.y - r.y) - r.r) < 12) q.glow = Math.max(q.glow, 0.7 * (1 - r.r / r.reach))
      }
      if (r.r >= r.reach) s.pings.splice(i, 1)
    }

    if (s.busy) {
      s.pingT = (s.pingT as number) - dt
      if ((s.pingT as number) <= 0) {
        s.pingT = PING_S
        ping(s, w / 2, h * 0.45, Math.hypot(w, h) * 0.6)
        world.sound?.sonar()
      }
    }
    s.lure = clamp((s.lure as number) + (s.busy ? dt : -dt) * 0.8, 0, 1)

    // Nobody around: now and then a whale passes far behind, calling.
    if (world.wild) {
      s.idle = speed > 30 ? 0 : (s.idle as number) + dt
      if (!s.whale && (s.idle as number) >= WHALE_IDLE_S) {
        s.whale = 1
        s.whaleX = -w * 0.3
        s.idle = 0
        world.sound?.whale()
      }
    }
    if (s.whale) {
      s.whaleX = (s.whaleX as number) + 40 * dt
      if ((s.whaleX as number) > w * 1.4) s.whale = 0
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, state, world) {
    const s = state as Sea
    const { t, w, h } = world
    ctx.save()
    ctx.globalCompositeOperation = 'lighter'
    // Shafts of light from the surface, swaying, fading with depth.
    for (let i = 0; i < 3; i++) {
      const x = w * (0.15 + i * 0.3) + Math.sin(t * 0.1 + i * 2) * 40
      const spread = 60 + 30 * Math.sin(t * 0.17 + i)
      const g = ctx.createLinearGradient(0, 0, 0, h * 0.75)
      g.addColorStop(0, 'rgba(120,230,255,0.07)')
      g.addColorStop(1, 'rgba(120,230,255,0)')
      ctx.fillStyle = g
      ctx.beginPath()
      ctx.moveTo(x - 30, 0)
      ctx.lineTo(x + 30, 0)
      ctx.lineTo(x + spread + 120, h * 0.75)
      ctx.lineTo(x - spread + 60, h * 0.75)
      ctx.closePath()
      ctx.fill()
    }
    ctx.restore()

    if (s.whale) drawWhale(ctx, s.whaleX as number, h * 0.3, Math.min(320, w * 0.25))

    for (const m of s.snow) {
      ctx.fillStyle = `rgba(220,240,245,${0.12 + 0.3 * m.z})`
      ctx.beginPath()
      ctx.arc(m.x, m.y, m.r, 0, TAU)
      ctx.fill()
    }

    const tint = s.tint as Tint
    const dim = tint === Tint.Fail ? 0.15 : 1
    for (const q of s.p) {
      const hue = tint === Tint.Warn ? 38 : q.hue
      const glow = (0.12 + 0.88 * q.glow) * dim
      if (q.glow > 0.05) {
        ctx.fillStyle = `hsla(${hue},100%,65%,${0.25 * glow})`
        ctx.beginPath()
        ctx.arc(q.x, q.y, q.r * 6, 0, TAU)
        ctx.fill()
      }
      ctx.fillStyle = `hsla(${hue},100%,80%,${0.9 * glow})`
      ctx.beginPath()
      ctx.arc(q.x, q.y, q.r, 0, TAU)
      ctx.fill()
    }

    s.jelly.forEach((j, i) => drawJelly(ctx, j, s.tails[i], 0.4 + 0.5 * light(world, j.x, j.y)))
    for (const f of s.fish) drawFish(ctx, f, 0.1 + 0.6 * light(world, f.x, f.y))

    const lure = s.lure as number
    if (lure > 0) {
      // The anglerfish itself stays in the dark; only its lure and a hint of the stalk show.
      const { x: lx, y: ly } = lureAt(world)
      const flicker = 0.8 + 0.2 * Math.sin(t * 9)
      ctx.strokeStyle = `rgba(120,160,170,${0.25 * lure})`
      ctx.lineWidth = 1.5
      ctx.beginPath()
      ctx.moveTo(lx + 40, ly + 60)
      ctx.quadraticCurveTo(lx + 30, ly, lx, ly)
      ctx.stroke()
      ctx.fillStyle = `rgba(190,255,230,${0.15 * lure * flicker})`
      ctx.beginPath()
      ctx.arc(lx, ly, 22, 0, TAU)
      ctx.fill()
      ctx.fillStyle = `rgba(220,255,240,${0.9 * lure * flicker})`
      ctx.beginPath()
      ctx.arc(lx, ly, 4, 0, TAU)
      ctx.fill()
    }

    ctx.lineWidth = 1
    for (const b of s.bubbles) {
      ctx.strokeStyle = 'rgba(190,245,255,0.55)'
      ctx.beginPath()
      ctx.arc(b.x, b.y, b.r, 0, TAU)
      ctx.stroke()
      ctx.fillStyle = 'rgba(230,255,255,0.5)'
      ctx.beginPath()
      ctx.arc(b.x - b.r * 0.35, b.y - b.r * 0.35, b.r * 0.25, 0, TAU)
      ctx.fill()
    }
    ctx.lineWidth = 2
    for (const r of s.pings) {
      ctx.strokeStyle = `rgba(46,230,214,${0.5 * (1 - r.r / r.reach)})`
      ctx.beginPath()
      ctx.arc(r.x, r.y, r.r, 0, TAU)
      ctx.stroke()
    }
    drawBits(ctx, s.bits)
  },
  burst(state, world, x, y) {
    const s = state as Sea
    stirred(s)
    scare(s, x, y, 300)
    stir(s, x, y, 140)
    if (world.pointer.bare) {
      for (let i = 0; i < 8; i++) bubbleAt(s, world, x + between(world.rnd, -14, 14), y + between(world.rnd, -8, 8), between(world.rnd, 1.5, 5))
      burstBits(s.bits, world.rnd, x, y, 16, 160, { color: '#8ffcff', size: 1.5 })
      const pan = panAt(world, x)
      for (let i = 0; i < 4; i++) world.sound?.bubble(between(world.rnd, 0.7, 1.3), i * 0.07, pan)
      world.sound?.swish(pan)
    } else if (world.pointer.control) {
      const voice = PRESS[world.pointer.control]
      if (voice && world.sound) voice(world.sound, panAt(world, x))
    }
  },
  key(state, world, k) {
    const s = state as Sea
    stirred(s)
    if (k.kind === 'tab') return
    stir(s, k.x, k.y, 60, 0.7)
    const pan = panAt(world, k.x)
    switch (k.kind) {
      case 'delete': {
        // The newest bubble pops.
        const b = s.bubbles.pop()
        if (b) pop(s, b)
        world.sound?.bubble(1.6, 0, pan)
        return
      }
      case 'enter':
        for (let i = 0; i < 5; i++) {
          bubbleAt(s, world, k.x + between(world.rnd, -10, 10), k.y - i * 6, between(world.rnd, 2, 5))
          world.sound?.bubble(between(world.rnd, 0.6, 1), i * 0.06, pan)
        }
        return
      case 'space':
        bubbleAt(s, world, k.x, k.y, 4)
        world.sound?.bubble(0.9, 0, pan)
        return
      default:
        bubbleAt(s, world, k.x, k.y, between(world.rnd, 1.5, 3))
        world.sound?.bubble(between(world.rnd, 1.1, 1.4), 0, pan)
    }
  },
  focus(state, world, box) {
    const s = state as Sea
    stirred(s)
    const x = (box.left + box.right) / 2
    ping(s, x, (box.top + box.bottom) / 2, 160)
    world.sound?.sonar(1, panAt(world, x))
  },
  browse(state, world, index) {
    const s = state as Sea
    stirred(s)
    const step = PENTATONIC[index % PENTATONIC.length] + 12 * Math.floor(index / PENTATONIC.length)
    if (world.pointer.active) spawnBit(s.bits, { x: world.pointer.x, y: world.pointer.y, size: 2, life: 0.4, vy: -40, color: '#bff' })
    world.sound?.bubble(2 ** (step / 12), 0, world.pointer.active ? panAt(world, world.pointer.x) : 0)
  },
  activity(state, world, a) {
    const s = state as Sea
    stirred(s)
    const { w, h, rnd } = world
    switch (a) {
      case 'forward':
      case 'back':
        // A current sweeps everything the way the wizard went.
        // The water rushes across from one side to the other.
        s.current = a === 'forward' ? 160 : -160
        world.sound?.swish(a === 'forward' ? 0.6 : -0.6)
        return
      case 'file-in':
        for (let i = 0; i < 12; i++) bubbleAt(s, world, w / 2 + between(rnd, -60, 60), h - between(rnd, 0, 80), between(rnd, 1.5, 5))
        for (let i = 0; i < 5; i++) world.sound?.bubble(between(rnd, 0.6, 1.1), i * 0.08)
        return
      case 'file-out': {
        const b = s.bubbles.pop()
        if (b) pop(s, b)
        world.sound?.bubble(1.6)
        return
      }
      case 'saved':
        ping(s, w / 2, h * 0.45, 260)
        world.sound?.sonar(2)
        return
      case 'panel-open':
        ping(s, w / 2, h * 0.45, 220)
        world.sound?.swish()
        return
      default:
        world.sound?.swish()
    }
  },
  scroll(state, world, dy) {
    const s = state as Sea
    stirred(s)
    // Nearer things move further: the depth bands slide past each other.
    for (const m of s.snow) m.y -= dy * 0.15 * m.z
    for (const q of s.p) q.y -= dy * 0.08
    const scrolled = (s.scrolled as number) + Math.abs(dy)
    s.scrolled = scrolled % SWISH_PX
    if (scrolled >= SWISH_PX) world.sound?.swish()
  },
  busy(state, world, on) {
    const s = state as Sea
    stirred(s)
    s.busy = on ? 1 : 0
    s.pingT = 0
    world.signal('busy', on ? 60_000 : 0)
  },
  outcome(state, world, kind, box) {
    const s = state as Sea
    stirred(s)
    const status = STATUS[kind]
    if (status) world.signal(status, TINT_S * 1000)
    switch (kind) {
      case 'success':
        // The school bolts from the lure (the anglerfish missed), a wave of light runs through the
        // plankton and the school circles.
        scare(s, lureAt(world).x, lureAt(world).y, 400)
        s.wave = 0
        s.circleT = 4
        world.sound?.whale()
        world.sound?.sonar()
        return
      case 'warning':
        s.tint = Tint.Warn
        s.tintT = TINT_S
        world.sound?.creak()
        return
      case 'error':
        s.tint = Tint.Fail
        s.tintT = TINT_S
        for (const j of s.jelly) j.alarm = 1
        s.lure = 0
        scare(s, world.w / 2, world.h / 2, Math.max(world.w, world.h))
        world.sound?.creak(true)
        return
      default:
        const x = box ? (box.left + box.right) / 2 : world.w / 2
        ping(s, x, box ? (box.top + box.bottom) / 2 : world.h / 2, 300)
        world.sound?.sonar(1, panAt(world, x))
    }
  },
}
