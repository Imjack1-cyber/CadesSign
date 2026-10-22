/**
 * Presets that react to the whole interaction, not just the pointer: keys typed, deleted and
 * entered, focused fields, requests in flight and their results (see the key/focus/busy/outcome
 * hooks in presets.ts). Like the other presets they keep their state in plain arrays so tests can
 * step them without a canvas; only draw() touches the 2D context.
 */
import type { Outcome } from '../signals'
import { burstBits, drawBits, scaleCount, spawnBit, stepBits } from './bits'
import type { Box, Preset, State, World } from './presets'

const TAU = Math.PI * 2
const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const gauss = (t: number, c: number, w: number, a: number) => a * Math.exp(-((t - c) ** 2) / (2 * w * w))
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

/** Where the result stamp and wax seal sit relative to the result box; themes.css draws them there. */
const stampAt = (box: Box) => ({ x: box.right - 144, y: box.top + 16 })
const sealAt = (box: Box) => ({ x: box.right - 39, y: box.top + 48 })

// ---------- Ink (Notary's Desk): typebar strikes, correction tape, ink blots, stamps, wax. ----------

const enum Mark { Dust, Strike, Tape, Blot, Wax, Feed, Ring }
const MAX_MARKS = 160
const RIBBON = '29,26,46'
const STAMP_INK: Record<Outcome, string> = { success: '43,58,143', warning: '184,100,27', error: '179,18,46', info: '43,58,143' }

/** Adds a mark, dropping the oldest non-dust mark when full. */
function addMark(s: State, q: Record<string, number>) {
  if (s.p.length >= s.max) {
    const i = s.p.findIndex(m => m.type !== Mark.Dust)
    if (i < 0) return
    s.p.splice(i, 1)
  }
  s.p.push(q)
}

function newDust(world: World) {
  return {
    type: Mark.Dust, x: world.rnd() * world.w * 0.6, y: world.rnd() * world.h * 0.8,
    vx: 0, vy: 0, r: between(world.rnd, 0.6, 1.6), phase: world.rnd() * TAU, life: 1, max: 1,
  }
}

export const ink: Preset = {
  layer: 'front',
  init(world) {
    const n = scaleCount(world, world.wild ? 60 : 30)
    const p = Array.from({ length: n }, () => newDust(world))
    return { p, bits: [], max: n + MAX_MARKS, busy: 0, nextPress: 0, sealAt: 0, sealX: 0, sealY: 0, flickerAt: 0 }
  },
  step(s, world) {
    const { dt, t, w, h, rnd, pointer } = world
    for (let i = s.p.length - 1; i >= 0; i--) {
      const q = s.p[i]
      if (q.type === Mark.Dust) {
        // Dust motes turning slowly in the lamp light; a passing pen stirs them.
        if (world.wild && pointer.active) {
          const dx = q.x - pointer.x
          const dy = q.y - pointer.y
          const d = Math.hypot(dx, dy)
          if (d < 90 && d > 1) {
            q.vx += (dx / d) * 40 * dt
            q.vy += (dy / d) * 40 * dt
          }
        }
        q.vx = q.vx * (1 - dt) + (rnd() - 0.5) * 12 * dt
        q.vy = q.vy * (1 - dt) + (rnd() - 0.5) * 12 * dt
        q.x += (q.vx + Math.sin(t * 0.3 + q.phase) * 3) * dt
        q.y += (q.vy + 1.5) * dt
        if (q.x < 0) q.x += w * 0.6
        if (q.x > w * 0.6) q.x -= w * 0.6
        if (q.y < 0) q.y += h * 0.8
        if (q.y > h * 0.8) q.y -= h * 0.8
        continue
      }
      q.life -= dt
      if (q.life <= 0) {
        s.p.splice(i, 1)
        continue
      }
      if (q.type === Mark.Wax) {
        // Molten wax runs down and slows as it cools.
        q.y += q.vy * dt
        q.vy *= 1 - 1.4 * dt
      } else if (q.type === Mark.Blot) {
        q.r += (q.grow - q.r) * Math.min(1, 6 * dt) + 0.6 * dt
      } else if (q.type === Mark.Ring) {
        q.r += 50 * dt
      }
    }
    if (s.busy && t >= (s.nextPress as number)) {
      // The embosser pressing while the request runs.
      addMark(s, { type: Mark.Ring, x: w / 2, y: h * 0.42, r: 24, life: 1, max: 1 })
      world.sound?.click(0.45)
      s.nextPress = t + 0.9
    }
    if ((s.sealAt as number) > 0 && t >= (s.sealAt as number)) {
      s.sealAt = 0
      world.sound?.thud()
      for (let i = 0; i < 4; i++) {
        addMark(s, {
          type: Mark.Wax, x: (s.sealX as number) + between(rnd, -20, 20), y: (s.sealY as number) + between(rnd, 16, 24),
          vy: between(rnd, 25, 60), r: between(rnd, 2.5, 5), life: 9, max: 9,
        })
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s, world) {
    const fast = world.typing > 8
    for (const q of s.p) {
      const a = q.life / q.max
      switch (q.type) {
        case Mark.Dust: {
          const glow = 0.25 + 0.25 * Math.sin(world.t * 0.8 + q.phase)
          ctx.fillStyle = `rgba(255,236,190,${glow})`
          ctx.beginPath()
          ctx.arc(q.x, q.y, q.r, 0, TAU)
          ctx.fill()
          break
        }
        case Mark.Strike: {
          const age = q.max - q.life
          // The typebar swinging up to the platen, for the first few frames only.
          if (age < 0.07) {
            ctx.strokeStyle = `rgba(60,60,66,${0.5 * (1 - age / 0.07)})`
            ctx.lineWidth = 2
            ctx.beginPath()
            ctx.moveTo(q.x + q.size * 0.4, q.y + q.size * 2.4)
            ctx.lineTo(q.x, q.y + q.size * 0.4)
            ctx.stroke()
          }
          const slam = age < 0.05 ? 1.25 - age * 5 : 1
          ctx.save()
          ctx.translate(q.x, q.y + q.dy)
          ctx.rotate(q.rot)
          ctx.scale(slam, slam)
          ctx.font = `700 ${q.size}px "Courier Prime", "Courier New", monospace`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          const draw = (dx: number, alpha: number) => {
            ctx.fillStyle = `rgba(${RIBBON},${alpha})`
            if (q.code) ctx.fillText(String.fromCodePoint(q.code), dx, 0)
            else ctx.fillRect(dx - q.size * 0.25, -q.size * 0.35, q.size * 0.5, q.size * 0.7)
          }
          // Two passes a hair apart: ribbon ink bleeding into the paper fibres.
          draw(0, q.dark * a)
          draw(0.6, q.dark * a * 0.35)
          if (fast) draw(2, q.dark * a * 0.25)
          ctx.restore()
          break
        }
        case Mark.Tape: {
          ctx.fillStyle = `rgba(0,0,0,${0.08 * a})`
          ctx.fillRect(q.x - q.w / 2 + 1, q.y - q.h / 2 + 1, q.w, q.h)
          ctx.fillStyle = `rgba(255,253,246,${0.95 * a})`
          ctx.fillRect(q.x - q.w / 2, q.y - q.h / 2, q.w, q.h)
          break
        }
        case Mark.Blot: {
          // An irregular blot that feathers into the paper as it soaks in.
          ctx.fillStyle = `rgba(20,26,78,${0.7 * Math.min(1, a * 1.6)})`
          ctx.beginPath()
          for (let i = 0; i <= 12; i++) {
            const ang = (i / 12) * TAU
            const r = q.r * (1 + 0.22 * Math.sin(ang * 3 + q.seed) + 0.12 * Math.sin(ang * 5 + q.seed * 2))
            ctx.lineTo(q.x + Math.cos(ang) * r, q.y + Math.sin(ang) * r)
          }
          ctx.fill()
          break
        }
        case Mark.Wax: {
          const hot = clamp((q.life - q.max + 3) / 3, 0, 1)
          ctx.fillStyle = `rgb(${110 + 69 * hot},${11 + 7 * hot},${26 + 20 * hot})`
          ctx.beginPath()
          ctx.ellipse(q.x, q.y, q.r * 0.8, q.r, 0, 0, TAU)
          ctx.fill()
          ctx.fillStyle = `rgba(255,220,220,${0.35 * Math.min(1, a * 3)})`
          ctx.beginPath()
          ctx.arc(q.x - q.r * 0.3, q.y - q.r * 0.35, q.r * 0.25, 0, TAU)
          ctx.fill()
          break
        }
        case Mark.Feed: {
          // The shadow of a fresh sheet sliding in over the field.
          const y = q.top + (q.bottom - q.top) * (1 - a)
          const g = ctx.createLinearGradient(0, y - 14, 0, y)
          g.addColorStop(0, 'rgba(70,50,30,0)')
          g.addColorStop(1, `rgba(70,50,30,${0.2 * a})`)
          ctx.fillStyle = g
          ctx.fillRect(q.left, y - 14, q.right - q.left, 14)
          break
        }
        case Mark.Ring: {
          ctx.strokeStyle = `rgba(120,90,40,${0.45 * a})`
          ctx.lineWidth = 2
          ctx.setLineDash([4, 6])
          ctx.beginPath()
          ctx.arc(q.x, q.y, q.r, 0, TAU)
          ctx.stroke()
          ctx.setLineDash([])
          break
        }
      }
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    addMark(s, { type: Mark.Blot, x, y, r: 2, grow: between(world.rnd, 8, 16), seed: world.rnd() * 10, life: 3, max: 3 })
  },
  key(s, world, k) {
    const { rnd, sound } = world
    switch (k.kind) {
      case 'char':
        if (!k.field) return
        addMark(s, {
          type: Mark.Strike, x: k.x + k.size * 0.3, y: k.y, dy: between(rnd, -1.5, 1.5), size: k.size * 1.15,
          rot: between(rnd, -0.06, 0.06), dark: between(rnd, 0.55, 0.95), code: k.glyph?.codePointAt(0) ?? 0,
          life: 0.45, max: 0.45,
        })
        burstBits(s.bits, rnd, k.x + k.size * 0.3, k.y, 2, 40, { color: `rgba(${RIBBON},0.6)`, size: 0.8, life: 0.3 })
        sound?.click(between(rnd, 0.85, 1.15))
        if (world.typing > 8 && world.t >= (s.flickerAt as number)) {
          // Hammering the keys makes the desk lamp flicker.
          world.signal('flicker', 400)
          s.flickerAt = world.t + 1.2
        }
        break
      case 'space':
        if (k.field) sound?.click(0.65)
        break
      case 'delete':
        if (!k.field) return
        addMark(s, { type: Mark.Tape, x: k.x, y: k.y, w: k.size * 0.9, h: k.size * 1.4, life: 1.1, max: 1.1 })
        for (let i = 0; i < 4; i++) {
          spawnBit(s.bits, {
            x: k.x + between(rnd, -4, 4), y: k.y + k.size * 0.5, vx: between(rnd, -60, 60), vy: between(rnd, -60, -20),
            gravity: 600, size: 1.6, shape: 'square', life: 0.8, color: 'rgba(214,170,170,0.9)',
          })
        }
        sound?.rasp()
        break
      case 'enter':
        // Carriage return: the page slides back, the bell rings at the right margin.
        world.signal('carriage', 520)
        for (let i = 0; i < 2; i++) {
          spawnBit(s.bits, { x: k.edge - 12, y: k.y, shape: 'ring', size: 3 + i * 6, grow: 60, life: 0.6, color: 'rgba(180,140,60,0.7)' })
        }
        sound?.whoosh()
        sound?.bell()
        break
      case 'tab':
        sound?.click(0.5)
        break
    }
  },
  focus(s, world, box) {
    addMark(s, { type: Mark.Feed, ...box, x: box.left, y: box.top, life: 0.45, max: 0.45 })
    world.sound?.whoosh()
  },
  busy(s, world, on) {
    s.busy = on ? 1 : 0
    s.nextPress = world.t
  },
  outcome(s, world, kind, box) {
    if (kind === 'info') return
    world.signal(kind === 'error' ? 'void' : 'stamp', 900)
    world.sound?.thud()
    if (!box) return
    const at = stampAt(box)
    burstBits(s.bits, world.rnd, at.x, at.y, 16, 140, { color: `rgba(${STAMP_INK[kind]},0.7)`, size: 1.4, life: 0.5 })
    if (kind === 'success') {
      const seal = sealAt(box)
      s.sealAt = world.t + 0.55
      s.sealX = seal.x
      s.sealY = seal.y
    }
  },
}

// ---------- ECG (Vital Signs): a bedside monitor whose patient is the user. ----------

const enum Rhythm { Sinus, Fibrillation, Asystole }
/** Trace resolution in px, sweep speed in px/s (25 mm/s on a typical screen) and the erase gap. */
const COL = 2
const SWEEP = 110
const GAP = 8
const REST_HR = 62
const FIBRILLATION_S = 2.5
const ASYSTOLE_S = 8
const LEADS: ReadonlyArray<[string, number]> = [['II', 1], ['V1', -0.7], ['V5', 1.25], ['aVR', -0.8], ['III', 0.7]]

/** One beat, t seconds after it started: P, Q, R, S and T as Gaussians; a PVC is wide with no P. */
function beatShape(t: number, pvc: number, rr: number) {
  if (pvc) return gauss(t, 0.1, 0.035, -0.35) + gauss(t, 0.16, 0.04, 1.35) + gauss(t, 0.4, 0.08, -0.5)
  const qt = 0.36 * Math.sqrt(rr)
  return gauss(t, 0.08, 0.022, 0.12) + gauss(t, 0.165, 0.008, -0.1) + gauss(t, 0.19, 0.009, 1)
    + gauss(t, 0.215, 0.01, -0.28) + gauss(t, 0.19 + qt * 0.72, 0.05, 0.3)
}

/** The finger-clip pulse: a steep upstroke and a dicrotic notch, weaker after a PVC. */
const plethShape = (t: number, pvc: number) => (gauss(t, 0.34, 0.06, 1) + gauss(t, 0.52, 0.07, 0.35)) * (pvc ? 0.4 : 1)

function ecgSample(s: State, world: World, lag: number) {
  const tb = (s.sinceBeat as number) - lag
  let v: number
  let pleth: number
  switch (s.rhythm as Rhythm) {
    case Rhythm.Fibrillation: {
      const tt = world.t - lag
      const fade = 1 - 0.6 * Math.min(1, (s.rhythmT as number) / FIBRILLATION_S)
      v = (0.6 * Math.sin(tt * TAU * 5.3) + 0.4 * Math.sin(tt * TAU * 3.7 + 1) + 0.3 * Math.sin(tt * TAU * 7.9)) * 0.45 * fade
      pleth = 0.1 * Math.sin(tt * TAU * 2)
      break
    }
    case Rhythm.Asystole:
      v = 0
      pleth = 0
      break
    default:
      v = beatShape(tb, s.beatType as number, s.rr as number) + beatShape(tb + (s.prevInterval as number), s.prevType as number, s.prevRR as number)
      pleth = plethShape(tb, s.beatType as number) + plethShape(tb + (s.prevInterval as number), s.prevType as number)
  }
  v += (world.rnd() - 0.5) * (0.03 + 0.4 * (s.noise as number)) + 0.04 * Math.sin((world.t - lag) * 0.9)
  v *= LEADS[s.lead as number][1]
  if ((s.shockT as number) > 0) v = 2.6 * ((s.shockT as number) / 0.35)
  return { v, pleth }
}

function recover(s: State, world: World, shocked: boolean) {
  s.rhythm = Rhythm.Sinus
  s.rhythmT = 0
  s.hr = shocked ? 118 : 96
  s.sinceBeat = -0.6
  world.signal('flatline', 0)
  world.sound?.tone(false)
}

export const ecg: Preset = {
  layer: 'back',
  init(world) {
    const panel = Math.min(180, world.w * 0.28)
    const cols = Math.max(16, Math.ceil((world.w - panel) / COL))
    return {
      p: [], bits: [], max: 0, panel, cols,
      ecg: new Float32Array(cols), pleth: new Float32Array(cols), resp: new Float32Array(cols), head: 0,
      hr: REST_HR, rhythm: Rhythm.Sinus, rhythmT: 0, sinceBeat: 0, rr: 60 / REST_HR,
      beatType: 0, prevType: 0, prevInterval: 1, prevRR: 1, pvcPending: 0, afterPvc: 0, lastPvc: -10,
      noise: 0, lead: 0, busy: 0, nibpT: 0, sys: 118, dia: 76, spo2: 98, respPhase: 0, okPulse: 0, shockT: 0, beatFlash: 0,
    }
  },
  step(s, world) {
    const { dt, rnd, pointer } = world
    const sinus = s.rhythm === Rhythm.Sinus
    // The user is the patient: typing, a busy request and a fast pointer raise the pulse, which
    // climbs over a few seconds and relaxes over about ten.
    const moving = pointer.active ? Math.min(20, Math.hypot(pointer.vx, pointer.vy) / 90) : 0
    const target = Math.min(140, REST_HR + world.typing * 7 + moving + (s.busy ? 22 : 0))
    const hr = s.hr as number
    s.hr = hr + (target - hr) * Math.min(1, (target > hr ? 0.35 : 0.1) * dt)

    s.sinceBeat = (s.sinceBeat as number) + dt
    s.rhythmT = (s.rhythmT as number) + dt
    if (sinus) {
      const rr = 60 / (s.hr as number)
      const due = s.pvcPending ? rr * 0.62 : s.afterPvc ? rr * 1.38 : rr
      if ((s.sinceBeat as number) >= due) {
        s.prevType = s.beatType
        s.prevInterval = s.sinceBeat
        s.prevRR = s.rr
        s.sinceBeat = 0
        s.rr = rr
        s.beatType = s.pvcPending
        s.afterPvc = s.pvcPending
        s.pvcPending = 0
        s.beatFlash = 1
        // The QRS beep drops in pitch as saturation falls.
        world.sound?.beep(880 - (98 - (s.spo2 as number)) * 20, 60)
      }
    } else if (s.rhythm === Rhythm.Fibrillation && (s.rhythmT as number) > FIBRILLATION_S) {
      s.rhythm = Rhythm.Asystole
      s.rhythmT = 0
      world.sound?.tone(true)
    } else if (s.rhythm === Rhythm.Asystole && (s.rhythmT as number) > ASYSTOLE_S) {
      recover(s, world, false)
    }
    s.spo2 = sinus ? Math.min(98, (s.spo2 as number) + dt * 0.8) : Math.max(72, (s.spo2 as number) - dt * 1.5)

    const respRate = Math.min(28, 14 + world.typing * 0.8)
    s.respPhase = ((s.respPhase as number) + dt * (respRate / 60) * TAU) % TAU

    const speedPx = SWEEP * (s.busy ? 2 : 1)
    const cols = s.cols as number
    const head = s.head as number
    const next = head + (speedPx * dt) / COL
    const ecgBuf = s.ecg as Float32Array
    const plethBuf = s.pleth as Float32Array
    const respBuf = s.resp as Float32Array
    for (let c = Math.floor(head) + 1; c <= Math.floor(next); c++) {
      const lag = ((next - c) * COL) / speedPx
      const { v, pleth } = ecgSample(s, world, lag)
      const i = c % cols
      ecgBuf[i] = v
      plethBuf[i] = pleth
      respBuf[i] = Math.sin((s.respPhase as number) - lag * (respRate / 60) * TAU)
    }
    s.head = next >= cols ? next - cols : next

    s.noise = Math.max(0, (s.noise as number) - 2.5 * dt)
    s.beatFlash = Math.max(0, (s.beatFlash as number) - 4 * dt)
    s.okPulse = Math.max(0, (s.okPulse as number) - dt)
    s.shockT = Math.max(0, (s.shockT as number) - dt)
    if ((s.nibpT as number) > 0) {
      s.nibpT = (s.nibpT as number) - dt
      if ((s.nibpT as number) <= 0) {
        s.sys = Math.round(112 + ((s.hr as number) - REST_HR) * 0.4 + rnd() * 8)
        s.dia = Math.round(70 + rnd() * 8)
        world.sound?.beep(1200, 50)
        world.sound?.beep(1200, 50, 0.12)
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s, world) {
    const { w, h, t } = world
    const cols = s.cols as number
    const head = Math.floor(s.head as number)
    const panel = s.panel as number
    // Phones keep the waves lower and the numerics smaller, out of the way of the content.
    const phone = w <= 640
    const [ecgY, plethY, respY] = phone ? [h * 0.8, h * 0.9, h * 0.96] : [h * 0.72, h * 0.85, h * 0.94]
    const ecgAmp = h * (phone ? 0.055 : 0.09)
    const strips: Array<[Float32Array, number, number, string, string]> = [
      [s.ecg as Float32Array, ecgY, ecgAmp, '61,255,122', LEADS[s.lead as number][0]],
      [s.pleth as Float32Array, plethY, h * (phone ? 0.025 : 0.035), '54,214,255', 'Pleth'],
      [s.resp as Float32Array, respY, h * (phone ? 0.012 : 0.018), '255,225,77', 'Resp'],
    ]
    ctx.lineJoin = 'round'
    for (const [buf, y0, amp, rgb, label] of strips) {
      // A wide faint pass under a thin bright one: phosphor glow without an expensive shadow blur.
      for (const [width, alpha] of [[4, 0.18], [1.6, 0.95]] as const) {
        ctx.strokeStyle = `rgba(${rgb},${alpha})`
        ctx.lineWidth = width
        ctx.beginPath()
        let pen = false
        for (let c = 0; c < cols; c++) {
          const d = (c - head + cols) % cols
          if (d > 0 && d < GAP) {
            pen = false
            continue
          }
          const y = y0 - buf[c] * amp
          if (pen) ctx.lineTo(c * COL, y)
          else ctx.moveTo(c * COL, y)
          pen = true
        }
        ctx.stroke()
      }
      ctx.fillStyle = `rgba(${rgb},1)`
      ctx.beginPath()
      ctx.arc(head * COL, y0 - buf[head] * amp, 2.5, 0, TAU)
      ctx.fill()
      ctx.font = '600 11px ui-monospace, Menlo, Consolas, monospace'
      ctx.textAlign = 'left'
      ctx.fillStyle = `rgba(${rgb},0.75)`
      const ecgLabel = buf === s.ecg && !phone
      ctx.fillText(ecgLabel ? `${label}  x1  ${s.busy ? 50 : 25} mm/s` : label, 10, y0 - amp - 10)
    }

    // Numerics on the right, as on a bedside monitor.
    const x = w - 14
    const arrested = s.rhythm !== Rhythm.Sinus
    const blink = Math.sin(t * TAU * 2) > 0
    ctx.textAlign = 'right'
    const numeric = (value: string, unit: string, y: number, size: number, rgb: string) => {
      ctx.font = `700 ${size}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`
      ctx.fillStyle = `rgba(${rgb},0.25)`
      ctx.fillText(value, x + 1, y + 1)
      ctx.fillStyle = `rgb(${rgb})`
      ctx.fillText(value, x, y)
      ctx.font = '600 11px ui-monospace, Menlo, Consolas, monospace'
      ctx.fillText(unit, x, y - size * 0.85)
    }
    const hrRgb = arrested ? (blink ? '255,70,70' : '140,30,30') : (s.okPulse as number) > 0 ? '160,255,190' : '61,255,122'
    const hrText = s.rhythm === Rhythm.Fibrillation ? '---' : s.rhythm === Rhythm.Asystole ? '0' : String(Math.round(s.hr as number))
    const hrSize = phone ? 26 : Math.min(44, h * 0.06)
    numeric(hrText, `HR ${(s.beatFlash as number) > 0.3 ? '♥' : ' '}`, ecgY + 6, hrSize, hrRgb)
    numeric(String(Math.round(s.spo2 as number)), 'SpO₂ %', plethY + 6, phone ? 18 : Math.min(30, h * 0.04), '54,214,255')
    numeric(String(Math.round(Math.min(28, 14 + world.typing * 0.8))), 'RR', respY + 6, phone ? 14 : Math.min(22, h * 0.03), '255,225,77')
    if (!phone) {
      ctx.font = '600 12px ui-monospace, Menlo, Consolas, monospace'
      ctx.fillStyle = 'rgba(235,240,245,0.85)'
      const nibp = (s.nibpT as number) > 0
        ? `NIBP ${Math.round(40 + 140 * Math.sin(((4 - (s.nibpT as number)) / 4) * Math.PI))} mmHg`
        : `NIBP ${s.sys}/${s.dia}`
      ctx.fillText(nibp, x, ecgY - hrSize - 4)
    }

    // Status messages over the ECG strip.
    const status = s.rhythm === Rhythm.Fibrillation ? ['VFIB', '255,70,70']
      : s.rhythm === Rhythm.Asystole ? ['ASYSTOLE – click to shock', '255,70,70']
        : s.busy ? ['ANALYZING…', '255,225,77']
          : (s.okPulse as number) > 0 ? ['Sinus rhythm', '160,255,190'] : null
    if (status && (!arrested || blink)) {
      ctx.textAlign = 'center'
      ctx.font = '700 14px ui-monospace, Menlo, Consolas, monospace'
      ctx.fillStyle = `rgb(${status[1]})`
      ctx.fillText(status[0], (w - panel) / 2, ecgY - ecgAmp - 12)
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    if (s.rhythm !== Rhythm.Sinus) {
      // Defibrillation: a jolt, an off-scale spike, then the heart restarts.
      s.shockT = 0.35
      world.signal('shock', 500)
      world.sound?.thud()
      burstBits(s.bits, world.rnd, x, y, 22, 420, { shape: 'streak', size: 1.6, color: '#e8f4ff', life: 0.35 })
      recover(s, world, true)
    } else {
      s.noise = Math.min(1, (s.noise as number) + 0.5)
    }
  },
  key(s, world, k) {
    if (s.rhythm !== Rhythm.Sinus) return
    switch (k.kind) {
      case 'char':
      case 'space':
        s.noise = Math.min(1, (s.noise as number) + 0.25)
        break
      case 'delete':
        // A skipped beat: a premature ventricular contraction, at most one every two seconds.
        if (world.t - (s.lastPvc as number) > 2) {
          s.pvcPending = 1
          s.lastPvc = world.t
        }
        break
      case 'enter':
        if ((s.nibpT as number) <= 0) s.nibpT = 4
        break
      case 'tab':
        break
    }
  },
  focus(s) {
    s.lead = ((s.lead as number) + 1) % LEADS.length
  },
  busy(s, _world, on) {
    s.busy = on ? 1 : 0
  },
  outcome(s, world, kind) {
    switch (kind) {
      case 'success':
        if (s.rhythm !== Rhythm.Sinus) recover(s, world, false)
        s.okPulse = 2.5
        s.noise = 0
        world.signal('normal', 2500)
        world.sound?.chime()
        break
      case 'warning':
        // Medium-priority alarm: three tones.
        world.signal('alarm', 3000)
        for (let i = 0; i < 3; i++) world.sound?.beep(660, 150, i * 0.25)
        break
      case 'error':
        s.rhythm = Rhythm.Fibrillation
        s.rhythmT = 0
        world.signal('flatline', 60000)
        for (let i = 0; i < 3; i++) world.sound?.beep(988, 110, i * 0.16)
        break
      case 'info':
        break
    }
  },
}

// ---------- Sand (Zen Garden): a raked height field with pebbles, rings and cracks. ----------

const MAX_STONES = 24
/** Rake tines are this many cells apart; grooves and ridges alternate across it. */
const TINE = 3
const RAKE_HALF = 7.5

/** The value a raked groove profile has `o` cells across the rake: -1 in a groove, +1 on a ridge. */
const profile = (o: number) => -Math.cos((o * TAU) / TINE)

function markDirty(s: State, gy0: number, gy1: number) {
  s.dirty0 = Math.min(s.dirty0 as number, Math.max(0, Math.floor(gy0) - 1))
  s.dirty1 = Math.max(s.dirty1 as number, Math.min((s.gh as number) - 1, Math.ceil(gy1) + 1))
}

/** Blends cell (gx, gy) towards v by a, unless a stone sits there. */
function setCell(s: State, gx: number, gy: number, v: number, a: number) {
  const gw = s.gw as number
  const x = Math.round(gx)
  const y = Math.round(gy)
  if (x < 0 || y < 0 || x >= gw || y >= (s.gh as number)) return
  const cell = s.cell as number
  for (const q of s.p) {
    if (Math.hypot(q.x / cell - x, q.y / cell - y) < q.r / cell + 1) return
  }
  const H = s.H as Float32Array
  const i = y * gw + x
  H[i] += (v - H[i]) * a
}

/** Drags the rake from one grid point to another, leaving parallel grooves along the stroke. */
function rakeSegment(s: State, x0: number, y0: number, x1: number, y1: number) {
  const len = Math.hypot(x1 - x0, y1 - y0)
  if (len < 0.01) return
  const ux = (x1 - x0) / len
  const uy = (y1 - y0) / len
  for (let d = 0; d <= len; d += 0.75) {
    const sx = x0 + ux * d
    const sy = y0 + uy * d
    for (let o = -RAKE_HALF; o <= RAKE_HALF; o += 0.5) {
      const edge = Math.abs(o) > RAKE_HALF - 1.5 ? (RAKE_HALF - Math.abs(o)) / 1.5 : 1
      setCell(s, sx - uy * o, sy + ux * o, profile(o) * 0.9, 0.55 * edge)
    }
  }
  markDirty(s, Math.min(y0, y1) - RAKE_HALF, Math.max(y0, y1) + RAKE_HALF)
}

/** Concentric grooves around a pebble at (gx, gy) of radius r0 cells, with a dimple under it. */
function stampRings(s: State, gx: number, gy: number, r0: number, rings: number) {
  const outer = r0 + TINE * rings
  for (let y = Math.floor(gy - outer); y <= gy + outer; y++) {
    for (let x = Math.floor(gx - outer); x <= gx + outer; x++) {
      const d = Math.hypot(x - gx, y - gy)
      if (d > outer) continue
      const H = s.H as Float32Array
      const i = y * (s.gw as number) + x
      if (x < 0 || y < 0 || x >= (s.gw as number) || y >= (s.gh as number)) continue
      if (d < r0) H[i] += (-1.2 + (d / r0) * 0.6 - H[i]) * 0.6
      else H[i] += (profile(d - r0) * 0.9 - H[i]) * 0.7 * Math.min(1, (outer - d) / 1.5)
    }
  }
  markDirty(s, gy - outer, gy + outer)
}

/**
 * Rakes `rings` grooves around a box (a card, a field), like the lines raked around a rock. With
 * `half`, only the left half is done, as if the raking was interrupted.
 */
function rakeAround(s: State, box: Box, rings: number, half = false) {
  const cell = s.cell as number
  const l = box.left / cell
  const r = box.right / cell
  const t = box.top / cell
  const b = box.bottom / cell
  const pad = 1 + TINE * rings
  const midX = (l + r) / 2
  for (let y = Math.floor(t - pad); y <= b + pad; y++) {
    for (let x = Math.floor(l - pad); x <= r + pad; x++) {
      if (half && x > midX) continue
      const dx = Math.max(l - x, 0, x - r)
      const dy = Math.max(t - y, 0, y - b)
      const d = Math.hypot(dx, dy)
      if (d < 1 || d > pad) continue
      setCell(s, x, y, profile(d - 1) * 0.9, 0.6 * Math.min(1, (pad - d) / 1.5))
    }
  }
  markDirty(s, t - pad, b + pad)
}

/** Softens the sand around (gx, gy), as a palm smoothing it. */
function smooth(s: State, gx: number, gy: number, radius: number) {
  const H = s.H as Float32Array
  const gw = s.gw as number
  const gh = s.gh as number
  for (let pass = 0; pass < 2; pass++) {
    for (let y = Math.max(1, Math.floor(gy - radius)); y <= Math.min(gh - 2, gy + radius); y++) {
      for (let x = Math.max(1, Math.floor(gx - radius)); x <= Math.min(gw - 2, gx + radius); x++) {
        const f = 1 - Math.hypot(x - gx, y - gy) / radius
        if (f <= 0) continue
        const i = y * gw + x
        const avg = (H[i - 1] + H[i + 1] + H[i - gw] + H[i + gw]) / 4
        H[i] += (avg * 0.6 - H[i]) * 0.7 * f
      }
    }
  }
  markDirty(s, gy - radius, gy + radius)
}

/** A crack running away from the box: a deep jagged groove with a branch or two. */
function crack(s: State, world: World, box: Box) {
  const { rnd } = world
  const cell = s.cell as number
  // Jagged but keeping its heading, two cells wide with raised lips, forking now and then.
  const carve = (x: number, y: number, heading: number, steps: number, depth: number) => {
    let ang = heading
    for (let i = 0; i < steps; i++) {
      ang += between(rnd, -0.7, 0.7) + (heading - ang) * 0.2
      x += Math.cos(ang) * 1.2
      y += Math.sin(ang) * 1.2
      const nx = -Math.sin(ang)
      const ny = Math.cos(ang)
      setCell(s, x, y, -2.6 * depth, 0.95)
      setCell(s, x + nx * 0.6, y + ny * 0.6, -2.2 * depth, 0.8)
      setCell(s, x + nx * 1.8, y + ny * 1.8, 1 * depth, 0.6)
      setCell(s, x - nx * 1.2, y - ny * 1.2, 1 * depth, 0.6)
      if (depth > 0.6 && rnd() < 0.05) carve(x, y, ang + (rnd() < 0.5 ? -0.8 : 0.8), Math.floor(steps * 0.45), depth * 0.7)
    }
    markDirty(s, 0, s.gh as number)
  }
  // From under the result down into the open sand, leaning left or right.
  const x = between(rnd, box.left + (box.right - box.left) * 0.2, box.right - (box.right - box.left) * 0.2) / cell
  carve(x, box.bottom / cell, Math.PI / 2 + between(rnd, -0.6, 0.6), 80, 1)
}

function dropStone(s: State, world: World, x: number, y: number, r: number, rings = r > 14 ? 3 : 2) {
  if (s.p.length >= s.max) s.p.shift()
  s.p.push({
    x, y, r, rings, drop: 1, lift: 0, rot: world.rnd() * TAU, squash: between(world.rnd, 0.75, 0.95), tone: between(world.rnd, -12, 12),
  })
  world.sound?.pebble()
}

export const sand: Preset = {
  layer: 'back',
  init(world) {
    const cell = Math.max(4, Math.ceil(Math.sqrt((world.w * world.h) / 120000)))
    const gw = Math.ceil(world.w / cell) + 1
    const gh = Math.ceil(world.h / cell) + 1
    const H = new Float32Array(gw * gh)
    const grain = new Float32Array(gw * gh)
    for (let y = 0; y < gh; y++) {
      for (let x = 0; x < gw; x++) {
        // Long parallel lines with a gentle meander, as the garden is left each morning.
        H[y * gw + x] = profile(y + 1.5 * Math.sin(x * 0.035)) * 0.9
        grain[y * gw + x] = world.rnd() * 2 - 1
      }
    }
    return {
      p: [], bits: [], max: MAX_STONES, cell, gw, gh, H, grain, dirty0: 0, dirty1: gh - 1,
      lastX: -1, lastY: -1, auto: 0, autoX: 0, autoY: 0, autoDir: 1,
    }
  },
  step(s, world) {
    const { dt, pointer } = world
    const cell = s.cell as number
    // The pointer is the rake. A jump (the pointer coming back in) starts a new stroke.
    if (world.wild && pointer.active) {
      const gx = pointer.x / cell
      const gy = pointer.y / cell
      const lx = s.lastX as number
      const ly = s.lastY as number
      const jump = lx < 0 || Math.hypot(gx - lx, gy - ly) > 60
      if (!jump && Math.hypot(pointer.vx, pointer.vy) > 20) rakeSegment(s, lx, ly, gx, gy)
      s.lastX = gx
      s.lastY = gy
    }
    if (s.auto) {
      // While a request runs, an unseen hand rakes the garden afresh, row by row.
      const gw = s.gw as number
      const x0 = s.autoX as number
      const x1 = clamp(x0 + ((s.autoDir as number) * 260 * dt) / cell, 0, gw)
      rakeSegment(s, x0, s.autoY as number, x1, s.autoY as number)
      s.autoX = x1
      if (x1 <= 0 || x1 >= gw) {
        s.autoDir = -(s.autoDir as number)
        s.autoY = ((s.autoY as number) + RAKE_HALF * 2) % (s.gh as number)
      }
    }
    for (let i = s.p.length - 1; i >= 0; i--) {
      const q = s.p[i]
      if (q.drop > 0) {
        q.drop = Math.max(0, q.drop - dt * 4)
        if (q.drop === 0) stampRings(s, q.x / cell, q.y / cell, q.r / cell + 0.5, q.rings)
      }
      if (q.lift > 0) {
        q.lift += dt * 2.5
        if (q.lift >= 1) s.p.splice(i, 1)
      }
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, s, world) {
    const gw = s.gw as number
    const gh = s.gh as number
    const cell = s.cell as number
    if (!s.surface) {
      const surface = document.createElement('canvas')
      surface.width = gw
      surface.height = gh
      const sctx = surface.getContext('2d')
      if (!sctx) return
      s.surface = surface
      s.sctx = sctx
      s.image = sctx.createImageData(gw, gh)
    }
    const y0 = s.dirty0 as number
    const y1 = s.dirty1 as number
    if (y1 >= y0) {
      // Light from the top left: brightness follows the slope, with a fixed grain and deep cracks darker.
      const H = s.H as Float32Array
      const grain = s.grain as Float32Array
      const data = (s.image as ImageData).data
      for (let y = y0; y <= y1; y++) {
        for (let x = 0; x < gw; x++) {
          const i = y * gw + x
          const dx = H[x < gw - 1 ? i + 1 : i] - H[x > 0 ? i - 1 : i]
          const dy = H[y < gh - 1 ? i + gw : i] - H[y > 0 ? i - gw : i]
          let b = 1 - (dx * 0.6 + dy * 0.8) * 0.11 + grain[i] * 0.035 + H[i] * 0.015
          if (H[i] < -1.6) b *= 0.5
          data[i * 4] = clamp(228 * b, 0, 255)
          data[i * 4 + 1] = clamp(217 * b, 0, 255)
          data[i * 4 + 2] = clamp(193 * b, 0, 255)
          data[i * 4 + 3] = 255
        }
      }
      ;(s.sctx as CanvasRenderingContext2D).putImageData(s.image as ImageData, 0, 0, 0, y0, gw, y1 - y0 + 1)
      s.dirty0 = Infinity
      s.dirty1 = -1
    }
    ctx.imageSmoothingEnabled = true
    ctx.drawImage(s.surface as HTMLCanvasElement, 0, 0, gw * cell, gh * cell)

    for (const q of s.p) {
      const fall = q.drop
      const alpha = 1 - q.lift
      const scale = 1 + fall * 0.5 + q.lift * 0.3
      // The contact shadow, offset and softer while the pebble is in the air.
      ctx.fillStyle = `rgba(70,58,36,${0.35 * alpha * (1 - fall * 0.6)})`
      ctx.beginPath()
      ctx.ellipse(q.x + 2 + fall * 10, q.y + 3 + fall * 14, q.r * 1.05, q.r * q.squash * 1.05, q.rot, 0, TAU)
      ctx.fill()
      const g = ctx.createRadialGradient(q.x - q.r * 0.35, q.y - q.r * 0.4, q.r * 0.1, q.x, q.y, q.r * scale)
      g.addColorStop(0, `rgba(${200 + q.tone},${196 + q.tone},${186 + q.tone},${alpha})`)
      g.addColorStop(1, `rgba(${98 + q.tone},${94 + q.tone},${86 + q.tone},${alpha})`)
      ctx.fillStyle = g
      ctx.beginPath()
      ctx.ellipse(q.x, q.y, q.r * scale, q.r * q.squash * scale, q.rot, 0, TAU)
      ctx.fill()
    }

    // Dappled shade from a maple overhead, drifting with the breeze.
    for (let i = 0; i < 5; i++) {
      const x = ((i * 0.23 + 0.1) * world.w + Math.sin(world.t * 0.07 + i * 1.7) * 60 + world.wind * 20) % world.w
      const y = (0.15 + ((i * 0.37) % 1) * 0.7) * world.h + Math.cos(world.t * 0.05 + i) * 30
      const r = 90 + i * 25
      const g = ctx.createRadialGradient(x, y, 0, x, y, r)
      g.addColorStop(0, 'rgba(60,70,40,0.07)')
      g.addColorStop(1, 'rgba(60,70,40,0)')
      ctx.fillStyle = g
      ctx.fillRect(x - r, y - r, r * 2, r * 2)
    }
    drawBits(ctx, s.bits)
  },
  burst(s, world, x, y) {
    dropStone(s, world, x, y, between(world.rnd, 12, 20))
  },
  key(s, world, k) {
    const { rnd } = world
    const cell = s.cell as number
    // Pebbles land just under the field (above it at the bottom of the screen), so the rings show.
    const x = k.x + between(rnd, -10, 10)
    const below = k.y + k.size * 1.6
    const y = (below < world.h - 12 ? below : k.y - k.size * 1.6) + between(rnd, -4, 6)
    switch (k.kind) {
      case 'char':
        if (k.field) dropStone(s, world, x, y, between(rnd, 6, 10))
        break
      case 'space':
        if (k.field) dropStone(s, world, x, y, between(rnd, 11, 15))
        break
      case 'delete': {
        smooth(s, x / cell, y / cell, 6)
        // The nearest pebble is picked up again.
        let nearest: Record<string, number> | null = null
        let best = 80
        for (const q of s.p) {
          const d = Math.hypot(q.x - x, q.y - y)
          if (q.lift === 0 && d < best) {
            best = d
            nearest = q
          }
        }
        if (nearest) nearest.lift = 0.01
        world.sound?.whoosh()
        break
      }
      case 'enter':
        // The shishi-odoshi tips, knocks and spills into the basin.
        world.signal('knock', 1200)
        world.sound?.knock()
        for (let i = 0; i < 3; i++) {
          spawnBit(s.bits, {
            x: world.w - 70, y: world.h - 26, shape: 'ring', size: 2 + i * 5, grow: 26, life: 1.4, color: 'rgba(120,150,160,0.6)',
          })
        }
        break
      case 'tab':
        break
    }
  },
  focus(s, _world, box) {
    rakeAround(s, { left: box.left - 6, top: box.top - 6, right: box.right + 6, bottom: box.bottom + 6 }, 1)
  },
  busy(s, world, on) {
    s.auto = on ? 1 : 0
    s.autoX = 0
    s.autoDir = 1
    s.autoY = world.rnd() * (s.gh as number) * 0.5
  },
  outcome(s, world, kind, box) {
    const b = box ?? { left: world.w * 0.3, top: world.h * 0.35, right: world.w * 0.7, bottom: world.h * 0.55 }
    switch (kind) {
      case 'success':
        // Lines raked around the result, and a rock set in open sand below it with its own rings.
        rakeAround(s, b, 4)
        dropStone(s, world, b.left + (b.right - b.left) * 0.72, Math.min(world.h - 40, b.bottom + 90), 26, 5)
        world.signal('knock', 1200)
        world.sound?.knock()
        break
      case 'warning':
        rakeAround(s, b, 4, true)
        world.sound?.pebble()
        break
      case 'error': {
        crack(s, world, b)
        world.signal('gust', 900)
        world.sound?.rasp()
        world.sound?.whoosh()
        const { rnd } = world
        for (let i = 0; i < 80; i++) {
          spawnBit(s.bits, {
            x: between(rnd, -40, world.w * 0.4), y: between(rnd, 0, world.h), vx: between(rnd, 300, 700), vy: between(rnd, -30, 30),
            shape: 'square', size: between(rnd, 1, 2.2), life: between(rnd, 0.8, 1.6), color: 'rgba(150,130,96,0.7)',
          })
        }
        break
      }
      case 'info':
        break
    }
  },
}
