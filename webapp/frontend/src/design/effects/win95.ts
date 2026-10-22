/**
 * Windows 95: the desktop reacting the way the old one did. Pointer trails follow the mouse, a drag
 * on bare page draws the dotted rubber band, windows open, minimize and maximize with zooming
 * outlines, requests show the hourglass while the modem dials and the disk chatters, results answer
 * with tada or the chord, and a minute without input starts the starfield screensaver.
 * Hammering keys or clicks makes the app stop responding for a moment: the cursor turns into an
 * hourglass that smears copies of itself over the unpainted screen until the app catches up and
 * repaints, and clicks in the meantime only beep. Like the other presets it keeps its
 * state in plain arrays so tests can step it without a canvas; only draw() touches the 2D context.
 */
import type { ChromeMotion } from '../signals'
import type { Box, Preset, State, World } from './presets'
import { scaleCount } from './bits'

const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const lerp = (a: number, b: number, k: number) => a + (b - a) * k

const enum Kind { Ghost, Zoom }

/** Pointer trails: how many ghosts at most, and how often one is left behind. */
const MAX_GHOSTS = 12
const GHOST_EVERY = 0.03
const MAX_ZOOMS = 6
/** Seconds without input before the screensaver starts, and how long it takes to fade in. */
export const IDLE_S = 60
const SAVER_FADE = 2
/** Keys, or clicks, per second that make the app stop responding for a moment, and how often it may. */
const LAG_TYPING = 10
const LAG_CLICKS = 6
const LAG_COOLDOWN = 8
const LAG_S = 1.6
/** A request running longer than this stops responding until it ends. */
export const HUNG_S = 6
/** Hourglass copies left on the unpainted screen at most, and how long the repaint takes to wipe them. */
const MAX_SMEAR = 300
const REPAINT_S = 0.35
/** Pointer speed (px/s) that counts as moving the mouse. */
const MOVING = 20

/** The classic arrow cursor, tip at (0, 0). */
const ARROW: ReadonlyArray<[number, number]> = [[0, 0], [0, 16], [4, 12], [7, 19], [9, 18], [6, 11], [11, 11]]
/** The hourglass cursor's outline, centred on (0, 0). */
const HOURGLASS: ReadonlyArray<[number, number]> = [[-6, -10], [6, -10], [6, -7], [1, 0], [6, 7], [6, 10], [-6, 10], [-6, 7], [-1, 0], [-6, -7]]

interface Star {
  x: number
  y: number
  z: number
}

const newStar = (rnd: () => number, z = rnd()): Star => ({ x: between(rnd, -1, 1), y: between(rnd, -1, 1), z: Math.max(0.05, z) })

/** Where the Start button sits; result windows zoom out of it. */
const startBox = (world: World): Box => ({ left: 2, top: world.h - 26, right: 60, bottom: world.h - 2 })

function zoom(s: State, from: Box, to: Box, life = 0.3) {
  const zooms = s.p.filter(q => q.type === Kind.Zoom)
  if (zooms.length >= MAX_ZOOMS) s.p.splice(s.p.indexOf(zooms[0]), 1)
  s.p.push({
    type: Kind.Zoom, x: (to.left + to.right) / 2, y: (to.top + to.bottom) / 2,
    fl: from.left, ft: from.top, fr: from.right, fb: from.bottom,
    tl: to.left, tt: to.top, tr: to.right, tb: to.bottom, life, max: life,
  })
}

/** Any input wakes the desktop: the idle clock restarts and a running screensaver ends at once. */
function wake(s: State, world: World) {
  s.idle = 0
  if ((s.saver as number) > 0) {
    s.saver = 0
    world.signal('saver', 0)
  }
}

function outline(ctx: CanvasRenderingContext2D, shape: ReadonlyArray<[number, number]>, x: number, y: number) {
  ctx.beginPath()
  for (const [dx, dy] of shape) ctx.lineTo(x + dx, y + dy)
  ctx.closePath()
  ctx.fill()
  ctx.stroke()
}

const lagging = (s: State, world: World) => world.t < (s.lagUntil as number)

/** The app stops responding for `seconds`, unless it did so a moment ago. */
function hang(s: State, world: World, seconds = LAG_S) {
  if (lagging(s, world) || world.t < (s.lagAt as number) + LAG_COOLDOWN) return
  s.lagAt = world.t
  s.lagUntil = world.t + seconds
  s.seekAt = world.t
  world.signal('lag', seconds * 1000)
}

export const desktop: Preset = {
  layer: 'front',
  init(world) {
    const stars = Array.from({ length: scaleCount(world, 220) }, () => newStar(world.rnd))
    return {
      p: [], bits: [], max: MAX_GHOSTS + MAX_ZOOMS, stars,
      smear: [] as Array<{ x: number; y: number }>, wipe: -1, clicks: 0,
      idle: 0, saver: 0, ghostAt: 0, lagAt: -LAG_COOLDOWN, lagUntil: 0, busy: 0, busyAt: 0, hung: 0, seekAt: 0,
    }
  },
  start(_s, world) {
    world.sound?.startup()
  },
  step(s, world) {
    const { dt, t, pointer, rnd } = world
    const speed = pointer.active ? Math.hypot(pointer.vx, pointer.vy) : 0
    if (speed > MOVING || pointer.down) wake(s, world)

    for (let i = s.p.length - 1; i >= 0; i--) {
      const q = s.p[i]
      q.life -= dt
      if (q.life <= 0) s.p.splice(i, 1)
    }

    if (world.wild && speed > MOVING * 3 && t >= (s.ghostAt as number)) {
      // Faster movement leaves longer trails, like the slider in the Mouse control panel.
      const ghosts = s.p.filter(q => q.type === Kind.Ghost)
      if (ghosts.length >= MAX_GHOSTS) s.p.splice(s.p.indexOf(ghosts[0]), 1)
      const life = 0.15 + Math.min(0.35, speed / 5000)
      s.p.push({ type: Kind.Ghost, x: pointer.x, y: pointer.y, life, max: life })
      s.ghostAt = t + GHOST_EVERY
    }

    s.clicks = (s.clicks as number) * Math.exp(-dt)
    const smear = s.smear as Array<{ x: number; y: number }>
    if (lagging(s, world)) {
      // Nothing repaints while the app is hung, so the hourglass leaves copies of itself behind.
      const last = smear[smear.length - 1]
      if (pointer.active && (!last || Math.hypot(pointer.x - last.x, pointer.y - last.y) > 6)) {
        if (smear.length >= MAX_SMEAR) smear.shift()
        smear.push({ x: pointer.x, y: pointer.y })
      }
    } else if (smear.length) {
      // Caught up: the repaint sweeps down the screen and wipes the smear away.
      if ((s.wipe as number) < 0) s.wipe = 0
      s.wipe = (s.wipe as number) + dt / REPAINT_S
      if ((s.wipe as number) >= 1) {
        smear.length = 0
        s.wipe = -1
      }
    }

    if (s.busy && !s.hung && t - (s.busyAt as number) >= HUNG_S) {
      s.hung = 1
      world.signal('hung', 3_600_000)
    }

    if (s.busy || lagging(s, world)) {
      if (t >= (s.seekAt as number)) {
        world.sound?.seek()
        s.seekAt = t + between(rnd, 0.3, 0.8)
      }
    } else if (world.wild) {
      s.idle = (s.idle as number) + dt
      if ((s.idle as number) >= IDLE_S) {
        if (!s.saver) world.signal('saver', 3_600_000)
        s.saver = Math.min(1, (s.saver as number) + dt / SAVER_FADE)
      }
    }

    if (s.saver) {
      const stars = s.stars as Star[]
      for (let i = 0; i < stars.length; i++) {
        stars[i].z -= dt * 0.35
        if (stars[i].z <= 0.05) stars[i] = newStar(rnd, 1)
      }
    }
  },
  draw(ctx, s, world) {
    const { pointer } = world
    ctx.lineWidth = 1

    if (world.wild && pointer.down && pointer.bare && pointer.downX !== undefined && pointer.downY !== undefined) {
      const w = pointer.x - pointer.downX
      const h = pointer.y - pointer.downY
      if (Math.abs(w) > 6 || Math.abs(h) > 6) {
        // The rubber band: a dotted outline, black over white so it shows on any colour.
        ctx.setLineDash([1, 1])
        ctx.strokeStyle = '#fff'
        ctx.strokeRect(pointer.downX + 0.5, pointer.downY + 0.5, w, h)
        ctx.lineDashOffset = 1
        ctx.strokeStyle = '#000'
        ctx.strokeRect(pointer.downX + 0.5, pointer.downY + 0.5, w, h)
        ctx.lineDashOffset = 0
        ctx.setLineDash([])
      }
    }

    for (const q of s.p) {
      const a = q.life / q.max
      if (q.type === Kind.Ghost) {
        ctx.globalAlpha = a * 0.8
        ctx.fillStyle = '#fff'
        ctx.strokeStyle = '#000'
        outline(ctx, ARROW, q.x + 0.5, q.y + 0.5)
        continue
      }
      // The window opening: a few outlines chasing each other from the source to the target.
      ctx.globalAlpha = 1
      ctx.strokeStyle = '#808080'
      ctx.lineWidth = 2
      for (const lag of [0, 0.18, 0.36]) {
        const k = Math.max(0, Math.min(1, 1 - a - lag))
        if (k <= 0) continue
        const l = lerp(q.fl, q.tl, k)
        const top = lerp(q.ft, q.tt, k)
        ctx.strokeRect(l, top, lerp(q.fr, q.tr, k) - l, lerp(q.fb, q.tb, k) - top)
      }
      ctx.lineWidth = 1
    }
    ctx.globalAlpha = 1

    const smear = s.smear as Array<{ x: number; y: number }>
    if (smear.length) {
      const below = (s.wipe as number) < 0 ? -Infinity : (s.wipe as number) * world.h
      ctx.fillStyle = '#fff'
      ctx.strokeStyle = '#000'
      for (const q of smear) if (q.y > below) outline(ctx, HOURGLASS, q.x + 0.5, q.y + 0.5)
    }

    const saver = s.saver as number
    if (saver > 0) {
      ctx.fillStyle = `rgba(0,0,0,${saver})`
      ctx.fillRect(0, 0, world.w, world.h)
      const cx = world.w / 2
      const cy = world.h / 2
      const reach = Math.max(world.w, world.h) * 0.5
      for (const star of s.stars as Star[]) {
        const x = cx + (star.x / star.z) * reach
        const y = cy + (star.y / star.z) * reach
        const size = Math.max(1, (1 - star.z) * 3)
        const lum = Math.round(255 * Math.min(1, (1 - star.z) * 1.6))
        ctx.fillStyle = `rgba(${lum},${lum},${lum},${saver})`
        ctx.fillRect(x, y, size, size)
      }
    }
  },
  burst(s, world) {
    wake(s, world)
    // A hung app only beeps at clicks.
    if (lagging(s, world)) {
      world.sound?.ding()
      return
    }
    world.sound?.click(0.6)
    s.clicks = (s.clicks as number) + 1
    if ((s.clicks as number) > LAG_CLICKS) hang(s, world)
  },
  key(s, world, k) {
    wake(s, world)
    const { sound, rnd } = world
    switch (k.kind) {
      case 'char':
        if (k.field) sound?.click(between(rnd, 0.7, 0.85))
        if (world.typing > LAG_TYPING) hang(s, world)
        break
      case 'space':
        if (k.field) sound?.click(0.6)
        break
      case 'delete':
        // Nothing left to delete: the default beep, exactly as 95 complained.
        if (k.field && k.empty) sound?.ding()
        else if (k.field) sound?.click(0.55)
        break
      case 'enter':
        sound?.click(0.5)
        break
      case 'tab':
        sound?.click(0.45)
        break
    }
  },
  focus(s, world, box) {
    wake(s, world)
    zoom(s, { left: box.left - 40, top: box.top - 24, right: box.right + 40, bottom: box.bottom + 24 }, box, 0.22)
  },
  busy(s, world, on) {
    wake(s, world)
    s.busy = on ? 1 : 0
    s.busyAt = world.t
    world.sound?.modem(on)
    // The arrow with a small hourglass while the request gets going, then the full hourglass.
    world.signal('starting', on ? 700 : 0)
    world.signal('hourglass', on ? 3_600_000 : 0)
    if (!on && s.hung) {
      s.hung = 0
      world.signal('hung', 0)
    }
    // The disk joins in once the modem has finished dialling.
    s.seekAt = world.t + 2.5
  },
  outcome(s, world, kind, box) {
    wake(s, world)
    const { sound } = world
    if (box && kind !== 'info') zoom(s, startBox(world), box, 0.35)
    switch (kind) {
      case 'success':
        sound?.tada()
        world.signal('tada', 1200)
        break
      case 'warning':
        sound?.exclamation()
        break
      case 'error':
        sound?.chord()
        world.signal('stop', 700)
        break
      case 'info':
        sound?.asterisk()
        break
    }
  },
  chrome(s, world, event, motion: ChromeMotion) {
    wake(s, world)
    const { sound } = world
    if (motion.from && motion.to) zoom(s, motion.from, motion.to, event === 'navigate' ? 0.3 : 0.25)
    switch (event) {
      case 'shutdown': sound?.shutdown(); break
      case 'startup': sound?.startup(); break
      case 'minimize': sound?.minimize(); break
      case 'maximize':
      case 'restore': sound?.maximize(); break
      case 'close': sound?.recycle(); break
      case 'assistant': sound?.pop(); break
      default: sound?.menu()
    }
  },
}
