/**
 * Retro Terminal: falling glyph columns behind a green phosphor screen that answers like a real
 * terminal. Typed characters drop into the rain under the caret with a buckling-spring clack, a
 * request turns every column on while the PC speaker chatters, results print their status (themes.css
 * shows the status line off the signals) and a click on bare page degausses the tube. Every kind of
 * control has its own sound, and so do going forward or back, files going in or out, and the mouse ball.
 * Like the other presets it keeps its state in plain arrays so tests can step it without a canvas;
 * only draw() touches the 2D context.
 */
import type { Outcome } from '../signals'
import type { Control, Preset } from './presets'

const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)

const GLYPHS = 'アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789ABCDEF'
const GLYPH_SIZE = 16
/** How fast the rain falls while a request runs, and how often the speaker chatters meanwhile. */
const BUSY_RUSH = 2.5
const CHATTER_PER_S = 10
/** Seconds between two degausses; the coil needs to cool down. */
export const DEGAUSS_COOLDOWN = 3
/** Pointer travel, in px, between two roller ticks, and the speed (px/s) that ticks loudest. */
const TICK_PX = 90
const TICK_LOUD = 2000
/** Scrolled px per line fed. */
const LINE_PX = 40
/** At most this many line feeds per wheel step, so a fling does not rattle on. */
const MAX_FEED = 8
/** How long a result's status stays on the status line, in ms. */
const STATUS_MS = 2500

/** Rain tints after a result: none, warning amber, error red. */
const enum Tint { None, Warn, Fail }
const TINT_RGB = ['51,255,102', '255,204,51', '255,85,85']

/**
 * The sound a press makes, by control. Back, Next and the step rail stay quiet here: the move they
 * cause plays back() or advance(). A field beeps on the press and on focus; the rate limit keeps it to one.
 */
const PRESS: Record<Control, 'press' | 'select' | 'toggle' | 'channel' | 'cursor' | 'insert' | 'write' | 'erase' | 'deny' | null> = {
  button: 'press', choice: 'select', toggle: 'toggle', nav: 'channel', field: 'cursor', upload: 'insert',
  download: 'write', discard: 'erase', back: null, forward: null, disabled: 'deny',
}

const STATUS: Record<Outcome, 'ok' | 'warn' | 'fail' | null> = { success: 'ok', warning: 'warn', error: 'fail', info: null }

export const matrix: Preset = {
  layer: 'back',
  init(world) {
    const cols = Math.ceil(world.w / GLYPH_SIZE)
    const p = Array.from({ length: cols }, (_, i) => {
      const on = world.wild || world.rnd() < 0.45 ? 1 : 0
      return {
        x: i * GLYPH_SIZE, y: world.rnd() * world.h, v: between(world.rnd, 60, 200), len: Math.floor(between(world.rnd, 8, 24)),
        on, base: on, seed: Math.floor(world.rnd() * 1000), hot: 0, ch: 0,
      }
    })
    return { p, bits: [], max: cols, busy: 0, tint: Tint.None, tintT: 0, degaussT: -DEGAUSS_COOLDOWN, travel: 0, off: 0, feed: 0 }
  },
  start(_s, world) {
    world.sound?.poweron()
    world.sound?.hum(true)
  },
  step(s, world) {
    const { dt, pointer, h, rnd } = world
    const rush = s.busy ? BUSY_RUSH : 1
    for (const q of s.p) {
      const near = world.wild && pointer.active && Math.abs(q.x - pointer.x) < 60
      q.y += q.v * rush * (near ? 2.5 : 1) * dt
      q.hot = Math.max(0, q.hot - dt)
      if (rnd() < dt * 8) q.seed++
      if (q.y - q.len * GLYPH_SIZE > h) {
        q.y = -between(rnd, 0, h * 0.5)
        q.v = between(rnd, 60, 200)
        q.ch = 0
        if (!s.busy) q.on = q.base
      }
    }
    s.tintT = Math.max(0, (s.tintT as number) - dt)
    if (!s.tintT) s.tint = Tint.None
    if (s.busy && rnd() < dt * CHATTER_PER_S) world.sound?.beep(between(rnd, 600, 2600), 25, 0, 'square')
    // The mouse ball's rollers tick as it moves, faster and a little louder with speed.
    if (world.wild && pointer.active) {
      const v = Math.hypot(pointer.vx, pointer.vy)
      s.travel = (s.travel as number) + v * dt
      if ((s.travel as number) >= TICK_PX) {
        s.travel = 0
        world.sound?.tick(Math.min(1, v / TICK_LOUD))
      }
    }
  },
  draw(ctx, s) {
    if (s.off) return
    ctx.font = `${GLYPH_SIZE}px ui-monospace, monospace`
    ctx.textBaseline = 'top'
    const rgb = TINT_RGB[s.tint as Tint]
    for (const q of s.p) {
      if (!q.on) continue
      for (let k = 0; k < q.len; k++) {
        const y = q.y - k * GLYPH_SIZE
        if (y < -GLYPH_SIZE) break
        const head = k === 0
        const glyph = head && q.ch
          ? String.fromCharCode(q.ch)
          : GLYPHS[(q.seed * 7 + k * 13 + Math.floor(y / GLYPH_SIZE)) % GLYPHS.length]
        ctx.fillStyle = head || q.hot > 0 ? '#d8ffe0' : `rgba(${rgb},${0.55 * (1 - k / q.len)})`
        ctx.fillText(glyph, q.x, y)
      }
    }
  },
  burst(s, world, x, y) {
    // A press on bare page hits the degauss button; a control answers with its own sound. Either way the
    // columns around it glitch.
    if (world.pointer.bare && world.t - (s.degaussT as number) >= DEGAUSS_COOLDOWN) {
      s.degaussT = world.t
      world.signal('degauss', 900)
      world.sound?.degauss()
    } else if (world.pointer.control) {
      const voice = PRESS[world.pointer.control]
      if (voice) world.sound?.[voice]()
    }
    for (const q of s.p) {
      if (Math.abs(q.x - x) < 100) {
        q.on = 1
        q.y = y
        q.hot = 0.6
      }
    }
  },
  key(s, world, k) {
    world.sound?.keyclack(k.kind === 'tab' ? 'char' : k.kind)
    if (k.kind === 'delete' && k.empty) world.sound?.beep(750, 120, 0, 'square')
    if (k.kind === 'tab') return
    world.signal('typing', 900)
    // The typed character drops into the rain from the caret.
    const q = s.p[Math.max(0, Math.min(s.p.length - 1, Math.floor(k.x / GLYPH_SIZE)))]
    q.on = 1
    q.y = k.y
    q.hot = 0.4
    q.ch = k.kind === 'char' && k.glyph ? k.glyph.charCodeAt(0) : 0
  },
  chrome(s, world, event) {
    // The command line's shutdown and power-on.
    if (event === 'shutdown') {
      s.off = 1
      world.sound?.poweroff()
      world.sound?.hum(false)
    } else if (event === 'startup') {
      s.off = 0
      world.sound?.poweron()
      world.sound?.hum(true)
    }
  },
  command(_s, world, ok) {
    // Enter already clacked as a key; an accepted command adds a short acknowledging beep.
    if (ok) world.sound?.beep(1568, 30, 0.05, 'square')
    else world.sound?.deny()
  },
  focus(_s, world) {
    world.sound?.cursor()
  },
  browse(_s, world, index) {
    world.sound?.option(index)
  },
  activity(s, world, a) {
    switch (a) {
      case 'panel-open':
        // The About panel pops up like a window and its page prints out, while the rain flashes.
        for (const q of s.p) q.hot = Math.max(q.hot, 0.25)
        world.sound?.maximize()
        world.sound?.printout(8)
        return
      case 'panel-close':
        world.sound?.minimize()
        return
      case 'tab':
        world.sound?.printout(5)
        return
    }
    const voice = ({ forward: 'advance', back: 'back', 'file-in': 'load', 'file-out': 'erase', saved: 'write' } as const)[a]
    world.sound?.[voice]()
  },
  scroll(s, world, dy) {
    // The paper feeds a line at a time; the rain behind stays where it is.
    const feed = (s.feed as number) + Math.abs(dy)
    const lines = Math.floor(feed / LINE_PX)
    s.feed = feed - lines * LINE_PX
    if (lines) world.sound?.linefeed(Math.min(MAX_FEED, lines))
  },
  busy(s, world, on) {
    s.busy = on ? 1 : 0
    world.signal('busy', on ? 60_000 : 0)
    if (on) for (const q of s.p) q.on = 1
  },
  outcome(s, world, kind) {
    const status = STATUS[kind]
    if (status) world.signal(status, STATUS_MS)
    switch (kind) {
      case 'success':
        for (const q of s.p) q.hot = 0.5
        ;[523.3, 659.3, 784].forEach((f, i) => world.sound?.beep(f, 70, i * 0.09, 'square'))
        break
      case 'warning':
        s.tint = Tint.Warn
        s.tintT = STATUS_MS / 1000
        world.sound?.beep(660, 90, 0, 'square')
        world.sound?.beep(660, 90, 0.16, 'square')
        break
      case 'error':
        s.tint = Tint.Fail
        s.tintT = STATUS_MS / 1000
        world.sound?.beep(110, 350, 0, 'square')
        world.sound?.beep(750, 120, 0.4, 'square')
        break
      default:
        world.sound?.beep(1200, 40, 0, 'square')
    }
  },
}
