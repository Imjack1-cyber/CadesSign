/**
 * Rocket League: a night stadium. A ball rolls about the pitch along the bottom of the screen and now
 * and then a car drives in, picks up a boost pad and taps it; the crowd's camera flashes twinkle in the
 * stands. A fast pointer leaves a boost flame (supersonic it turns white), holding a press on bare
 * turf boosts and a click there sends a shockwave that knocks the ball towards it. Typing fills the
 * boost gauge in the corner and Enter spends it. A request is a kickoff countdown with the ball held
 * at centre; results score a goal, ring the crossbar or get demolished, each with its quick chat.
 * Leave it alone and a car boosts across. While the minigame is open the stadium goes quiet. Like the
 * other presets it keeps its state in plain arrays so tests can step it without a canvas.
 */
import type { Outcome } from '../signals'
import { burstBits, drawBits, scaleCount, spawnBit, stepBits } from './bits'
import type { Control, Preset, State, World } from './presets'
import type { Sound } from './sound'

const TAU = Math.PI * 2
const between = (rnd: () => number, lo: number, hi: number) => lo + rnd() * (hi - lo)
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

export const BLUE = '#2b8cff'
export const ORANGE = '#ff7a1a'
/** Where the pitch line runs, as a share of the height; matches the turf in themes.css. */
const PITCH = 0.94
const BALL_R = 16
const GRAVITY = 1400
/** Seconds without any input before a car boosts across on its own. */
export const IDLE_CAR_S = 40
/** Seconds of kickoff countdown when a request starts. */
export const COUNTDOWN_S = 3
/** The boost gauge: what a key adds, and how much Enter needs before it fires. */
export const METER_PER_KEY = 4
export const METER_MIN_SPEND = 20
/** Pointer speeds, in px/s, for a boost flame and for the white supersonic trail. */
const FLAME_SPEED = 150
const SUPERSONIC = 1400
/** Seconds a boost pad takes to come back after a car takes it. */
const PAD_RESPAWN_S = 4
/** How long GO! stays up once the countdown ends. */
const GO_S = 0.8
const PADS = [0.12, 0.34, 0.66, 0.88]
const CHAT_S = 3.5
const MAX_CHATS = 4
/** What a resize keeps, so a request, the gauge and the quiet of an open game carry on. */
const KEEP = ['busy', 'countT', 'goT', 'meter', 'idle', 'quiet', 'nextCar'] as const

/** What a press sounds like, by control. Back and Next stay quiet: the move they cause boosts. */
const PRESS: Record<Control, ((sound: Sound, pan: number) => void) | null> = {
  button: s => s.pad(), choice: (s, pan) => s.ballhit(0.3, pan), toggle: s => s.pad(), nav: (s, pan) => s.ballhit(0.2, pan),
  field: s => s.pad(), upload: (s, pan) => s.ballhit(0.5, pan), download: s => s.pad(), discard: s => s.clang(),
  back: null, forward: null, disabled: s => s.deny(),
}

/** Quick chat for each result, and the team that says it. */
const CHAT: Record<Outcome, { text: string[]; team: 0 | 1 }> = {
  success: { text: ['What a save!', 'Nice shot!', 'Great pass!', 'What a play!'], team: 0 },
  warning: { text: ['Close one!', 'Whew.', 'Wow!'], team: 1 },
  error: { text: ['Demolished!', 'Oops!', 'No problem.'], team: 1 },
  info: { text: ['Nice shot!', 'I got it!', 'Thanks!'], team: 0 },
}

type Thing = Record<string, number>

interface Chat {
  text: string
  team: 0 | 1
  life: number
}

interface Pitch extends State {
  ball: Thing
  car: Thing
  /** Seconds until each boost pad is back; 0 when it is there to take. */
  pads: number[]
  lines: Thing[]
  chats: Chat[]
}

const floorOf = (world: World) => world.h * PITCH
const panAt = (world: World, x: number) => clamp((x / world.w) * 2 - 1, -1, 1) * 0.8

/** Resets the idle clock; the lone car only comes when nobody is around. */
const stirred = (s: State) => {
  s.idle = 0
}

function chat(s: Pitch, text: string, team: 0 | 1) {
  if (s.chats.length >= MAX_CHATS) s.chats.shift()
  s.chats.push({ text, team, life: CHAT_S })
}

function pick<T>(rnd: () => number, list: readonly T[]): T {
  return list[Math.floor(rnd() * list.length)]
}

/** Sends a car in from one side; with `cross` it boosts straight over instead of going for the ball. */
function sendCar(s: Pitch, world: World, cross: boolean) {
  const fromLeft = cross ? world.rnd() < 0.5 : s.ball.x > world.w / 2
  Object.assign(s.car, {
    on: 1, dir: fromLeft ? 1 : -1, x: fromLeft ? -60 : world.w + 60, vx: 0, cross: cross ? 1 : 0,
    team: world.rnd() < 0.5 ? 0 : 1, hit: 0, y: 0, vy: 0,
  })
}

/** An explosion of team colour and a shockwave, where a goal went in. */
function goalBurst(s: Pitch, world: World, x: number, y: number, team: 0 | 1) {
  const color = team ? ORANGE : BLUE
  spawnBit(s.bits, { x, y, shape: 'ring', size: 10, grow: 700, life: 0.7, color })
  spawnBit(s.bits, { x, y, shape: 'ring', size: 4, grow: 420, life: 0.9, color: '#fff' })
  burstBits(s.bits, world.rnd, x, y, 50, 700, { shape: 'streak', size: 3, color, gravity: 500 })
  burstBits(s.bits, world.rnd, x, y, 30, 420, { shape: 'star', size: 4, color: '#ffe08a', gravity: 300 })
}

/** A demolition: a flash, a cloud of smoke and burning debris. */
function demoBurst(s: Pitch, world: World, x: number, y: number) {
  spawnBit(s.bits, { x, y, shape: 'ring', size: 8, grow: 520, life: 0.5, color: '#ffd27a' })
  burstBits(s.bits, world.rnd, x, y, 26, 260, { size: 10, grow: 30, color: 'rgba(70,70,80,0.6)', life: 1.4 })
  burstBits(s.bits, world.rnd, x, y, 24, 620, { shape: 'square', size: 5, color: '#ff5a2a', gravity: 900 })
  burstBits(s.bits, world.rnd, x, y, 16, 480, { shape: 'square', size: 4, color: '#2a2f45', gravity: 900 })
}

/** Lets out a jet of boost flame at (x, y), pointing along (dx, dy). */
function flame(s: Pitch, world: World, x: number, y: number, dx: number, dy: number, hot = false) {
  const { rnd } = world
  for (let i = 0; i < (hot ? 3 : 1); i++) {
    spawnBit(s.bits, {
      x: x + between(rnd, -3, 3), y: y + between(rnd, -3, 3),
      vx: dx * between(rnd, 80, 220) + between(rnd, -30, 30), vy: dy * between(rnd, 80, 220) + between(rnd, -30, 30),
      size: between(rnd, 2, 4.5), life: between(rnd, 0.2, 0.4), color: pick(rnd, ['#ffd23f', ORANGE, '#ff4d1a']),
    })
  }
  if (rnd() < 0.3) spawnBit(s.bits, { x, y, vx: dx * 40, vy: dy * 40 - 20, size: 4, grow: 14, life: 0.7, color: 'rgba(160,170,190,0.25)' })
}

/** Kicks the ball towards (x, y), harder the further it has to go. */
function kick(s: Pitch, world: World, x: number, y: number, power = 1) {
  const b = s.ball
  b.vx = clamp((x - b.x) * 1.4, -900, 900) * power
  b.vy = -clamp(Math.abs(y - b.y) * 1.2 + 300, 300, 900) * power
  world.sound?.ballhit(clamp(power * 0.8, 0, 1), panAt(world, b.x))
}

function stepBall(s: Pitch, world: World) {
  const { dt, w } = world
  const b = s.ball
  const floor = floorOf(world) - BALL_R
  if (s.busy) {
    // Held at centre for the kickoff, spinning.
    b.x += (w / 2 - b.x) * Math.min(1, dt * 4)
    b.y += (floor - b.y) * Math.min(1, dt * 4)
    b.vx = 0
    b.vy = 0
    b.rot += dt * 6
    return
  }
  b.vy += GRAVITY * dt
  b.x += b.vx * dt
  b.y += b.vy * dt
  if (b.y > floor) {
    b.y = floor
    b.vy = Math.abs(b.vy) > 120 ? -b.vy * 0.55 : 0
    b.vx *= 1 - 0.6 * dt
  }
  if (b.x < BALL_R) {
    b.x = BALL_R
    b.vx = Math.abs(b.vx) * 0.6
  } else if (b.x > w - BALL_R) {
    b.x = w - BALL_R
    b.vx = -Math.abs(b.vx) * 0.6
  }
  if (b.y < BALL_R) {
    b.y = BALL_R
    b.vy = Math.abs(b.vy) * 0.5
  }
  b.rot += (b.vx / BALL_R) * dt
}

function stepCar(s: Pitch, world: World) {
  const { dt, w, rnd } = world
  const c = s.car
  if (!c.on) return
  const floor = floorOf(world)
  const top = c.cross ? 900 : 520
  // Goes for the ball until it has hit it, then drives on and out.
  const chasing = !c.cross && !c.hit
  const want = chasing ? Math.sign(s.ball.x - c.x) || c.dir : c.dir
  c.vx += want * 900 * dt
  c.vx = clamp(c.vx, -top, top)
  c.x += c.vx * dt
  // A little hop when it reaches a bouncing ball.
  c.vy += GRAVITY * dt
  c.y = Math.min(0, c.y + c.vy * dt)
  if (c.y === 0 && c.vy > 0) c.vy = 0
  if (chasing && Math.abs(s.ball.x - c.x) < 120 && s.ball.y < floor - BALL_R * 3 && c.y === 0) c.vy = -500
  if (Math.abs(c.vx) > 400 || c.cross) flame(s, world, c.x - Math.sign(c.vx) * 26, floor + c.y - 10, -Math.sign(c.vx), 0)
  if (chasing && Math.abs(s.ball.x - c.x) < BALL_R + 26 && Math.abs(s.ball.y - (floor + c.y - 10)) < BALL_R + 20) {
    c.hit = 1
    c.dir = Math.sign(c.vx) || c.dir
    s.ball.vx = c.vx * 1.4 + c.dir * 200
    s.ball.vy = -between(rnd, 400, 800)
    world.sound?.ballhit(0.7, panAt(world, c.x))
    spawnBit(s.bits, { x: s.ball.x, y: s.ball.y, shape: 'ring', size: BALL_R, grow: 200, life: 0.3, color: '#fff' })
  }
  // Boost pads it drives over.
  PADS.forEach((f, i) => {
    if (!s.pads[i] && Math.abs(c.x - f * w) < 14) {
      s.pads[i] = PAD_RESPAWN_S
      world.sound?.pad()
      spawnBit(s.bits, { x: f * w, y: floor, shape: 'ring', size: 6, grow: 80, life: 0.4, color: ORANGE })
    }
  })
  if (c.x < -120 || c.x > w + 120) c.on = 0
}

export const boost: Preset = {
  layer: 'back',
  init(world, prev) {
    const { rnd, w, h } = world
    const n = scaleCount(world, world.wild ? 90 : 50)
    // Camera flashes in the stands, up behind the header.
    const p = Array.from({ length: n }, () => ({ x: rnd() * w, y: between(rnd, 0.02, 0.2) * h, flash: 0, r: between(rnd, 0.8, 1.8) }))
    const pitch: Pitch = {
      p, bits: [], max: n,
      ball: { x: w * 0.4, y: floorOf(world) - BALL_R, vx: 120, vy: 0, rot: 0 },
      car: { on: 0, x: -60, y: 0, vx: 0, vy: 0, dir: 1, team: 0, cross: 0, hit: 0 },
      pads: PADS.map(() => 0), lines: [], chats: [],
      busy: 0, countT: 0, goT: 0, meter: 0, idle: 0, quiet: 0, nextCar: 6,
    }
    if (prev) for (const k of KEEP) pitch[k] = prev[k]
    return pitch
  },
  start(_s, world) {
    world.sound?.crowd(true)
  },
  step(state, world) {
    const s = state as Pitch
    const { dt, w, rnd, pointer } = world
    const speed = Math.hypot(pointer.vx, pointer.vy)
    const quiet = !!s.quiet

    for (const q of s.p) {
      q.flash = Math.max(0, q.flash - dt * 6)
      if (!quiet && rnd() < dt * (s.busy ? 0.6 : 0.08)) q.flash = 1
    }
    s.pads = s.pads.map(v => Math.max(0, v - dt))

    // Boost flame behind a fast mouse, white once supersonic; a held press on bare turf boosts hard.
    const mouse = world.wild && pointer.active && !pointer.touch && !quiet
    if (mouse && speed > FLAME_SPEED) {
      const dx = -pointer.vx / speed
      const dy = -pointer.vy / speed
      flame(s, world, pointer.x, pointer.y, dx, dy)
      if (speed > SUPERSONIC) spawnBit(s.bits, { x: pointer.x, y: pointer.y, vx: dx * 300, vy: dy * 300, shape: 'streak', size: 2, life: 0.25, color: '#fff' })
    }
    if (world.wild && pointer.down && pointer.bare && !quiet) {
      flame(s, world, pointer.x, pointer.y, speed > 30 ? -pointer.vx / speed : 0, speed > 30 ? -pointer.vy / speed : 1, true)
      world.sound?.boost(panAt(world, pointer.x))
    }

    // Kickoff countdown, a beep on each second and a higher one on GO.
    if (s.busy && (s.countT as number) > 0) {
      const before = Math.ceil(s.countT as number)
      s.countT = Math.max(0, (s.countT as number) - dt)
      const after = Math.ceil(s.countT as number)
      if (after !== before) world.sound?.beep(after ? 440 : 880, after ? 120 : 380)
    } else if (s.busy) s.goT = (s.goT as number) + dt

    stepBall(s, world)
    if (!quiet) {
      s.nextCar = (s.nextCar as number) - dt
      if (!s.car.on && !s.busy && (s.nextCar as number) <= 0) {
        sendCar(s, world, false)
        s.nextCar = world.wild ? between(rnd, 12, 25) : between(rnd, 25, 45)
      }
    }
    stepCar(s, world)

    // Nobody around: a car boosts across.
    if (world.wild) {
      s.idle = speed > 30 ? 0 : (s.idle as number) + dt
      if (!quiet && !s.car.on && (s.idle as number) >= IDLE_CAR_S) {
        stirred(s)
        sendCar(s, world, true)
        world.sound?.boost()
      }
    }

    for (let i = s.lines.length - 1; i >= 0; i--) {
      const l = s.lines[i]
      l.x += l.v * dt
      if (l.x < -l.len - 50 || l.x > w + l.len + 50) s.lines.splice(i, 1)
    }
    for (let i = s.chats.length - 1; i >= 0; i--) {
      s.chats[i].life -= dt
      if (s.chats[i].life <= 0) s.chats.splice(i, 1)
    }
    stepBits(s.bits, dt)
  },
  draw(ctx, state, world) {
    const s = state as Pitch
    const { t, w, h } = world
    const floor = floorOf(world)

    ctx.fillStyle = '#fff'
    for (const q of s.p) {
      if (q.flash < 0.02) continue
      ctx.globalAlpha = q.flash
      ctx.beginPath()
      ctx.arc(q.x, q.y, q.r * (1 + q.flash * 2), 0, TAU)
      ctx.fill()
    }
    ctx.globalAlpha = 1

    // Boost pads glow and pulse until taken.
    PADS.forEach((f, i) => {
      const x = f * w
      const ready = !s.pads[i]
      ctx.fillStyle = ready ? `rgba(255,170,60,${0.55 + 0.25 * Math.sin(t * 4 + i)})` : 'rgba(255,170,60,0.12)'
      ctx.beginPath()
      ctx.ellipse(x, floor, 14, 4, 0, 0, TAU)
      ctx.fill()
    })

    ctx.strokeStyle = 'rgba(255,255,255,0.6)'
    ctx.lineCap = 'round'
    for (const l of s.lines) {
      ctx.globalAlpha = 0.5
      ctx.lineWidth = l.width
      ctx.beginPath()
      ctx.moveTo(l.x, l.y)
      ctx.lineTo(l.x - Math.sign(l.v) * l.len, l.y)
      ctx.stroke()
    }
    ctx.globalAlpha = 1

    if (s.car.on) drawCar(ctx, s.car.x, floor + s.car.y, Math.sign(s.car.vx) || s.car.dir, s.car.team ? ORANGE : BLUE)
    drawBall(ctx, s.ball, floor)
    drawBits(ctx, s.bits)

    // The kickoff countdown, big and faint over the middle.
    if (s.busy && (s.goT as number) < GO_S) {
      const n = Math.ceil(s.countT as number)
      const frac = (s.countT as number) - Math.floor(s.countT as number)
      ctx.save()
      ctx.globalAlpha = n ? 0.25 + 0.35 * frac : 0.4
      ctx.fillStyle = n ? '#fff' : ORANGE
      ctx.font = `italic 900 ${Math.round(Math.min(w, h) * 0.22)}px system-ui, sans-serif`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(n ? String(n) : 'GO!', w / 2, h * 0.45)
      ctx.restore()
    }

    drawGauge(ctx, s.meter as number, w, h)
    drawChats(ctx, s.chats, w, floor)
  },
  burst(state, world, x, y) {
    const s = state as Pitch
    stirred(s)
    if (s.quiet) return
    if (world.pointer.bare) {
      spawnBit(s.bits, { x, y, shape: 'ring', size: 6, grow: 500, life: 0.45, color: 'rgba(255,255,255,0.8)' })
      spawnBit(s.bits, { x, y, shape: 'ring', size: 4, grow: 300, life: 0.6, color: ORANGE })
      burstBits(s.bits, world.rnd, x, y, 14, 380, { shape: 'streak', size: 2, color: '#ffd23f' })
      if (!s.busy) kick(s, world, x, y)
    } else if (world.pointer.control) {
      const voice = PRESS[world.pointer.control]
      if (voice && world.sound) voice(world.sound, panAt(world, x))
    }
  },
  key(state, world, k) {
    const s = state as Pitch
    stirred(s)
    // Keys played in the minigame are not typing.
    if (s.quiet) return
    const before = s.meter as number
    switch (k.kind) {
      case 'tab':
        return
      case 'delete':
        s.meter = Math.max(0, before - 8)
        spawnBit(s.bits, { x: k.x, y: k.y, vy: -30, size: 5, grow: 12, life: 0.6, color: 'rgba(160,170,190,0.35)' })
        return
      case 'enter':
        if (before < METER_MIN_SPEND) {
          world.sound?.deny()
          return
        }
        // Spends the gauge in one burst of boost from the caret.
        for (let i = 0; i < Math.round(before / 5); i++) flame(s, world, k.x, k.y, -1, between(world.rnd, -0.3, 0.3), true)
        world.sound?.boost(panAt(world, k.x))
        s.meter = 0
        if (!s.busy) kick(s, world, k.x, k.y, before / 100)
        return
      default:
        s.meter = Math.min(100, before + (k.kind === 'space' ? METER_PER_KEY * 1.5 : METER_PER_KEY))
        spawnBit(s.bits, { x: k.x, y: k.y, vx: between(world.rnd, -20, 20), vy: -between(world.rnd, 30, 70), size: 1.6, life: 0.4, color: ORANGE })
        // A zap each quarter the gauge fills.
        if (Math.floor((s.meter as number) / 25) > Math.floor(before / 25)) world.sound?.pad()
    }
  },
  focus(state, world, box) {
    const s = state as Pitch
    stirred(s)
    const x = (box.left + box.right) / 2
    const y = (box.top + box.bottom) / 2
    spawnBit(s.bits, { x, y, shape: 'ring', size: 8, grow: 160, life: 0.4, color: ORANGE })
    world.sound?.pad()
  },
  browse(state, world, index) {
    stirred(state)
    world.sound?.option(index)
  },
  activity(state, world, a) {
    const s = state as Pitch
    stirred(s)
    const { w, h, rnd } = world
    switch (a) {
      case 'forward':
      case 'back': {
        // Speed lines rush past the way the wizard went.
        const v = a === 'forward' ? -1800 : 1800
        for (let i = 0; i < 14; i++) {
          s.lines.push({ x: v < 0 ? w + between(rnd, 0, w * 0.5) : -between(rnd, 0, w * 0.5), y: between(rnd, 0.1, 0.9) * h, len: between(rnd, 60, 220), v, width: between(rnd, 1, 3) })
        }
        world.sound?.boost(a === 'forward' ? 0.6 : -0.6)
        return
      }
      case 'file-in':
        s.meter = 100
        chat(s, '+100 BOOST', 0)
        world.sound?.pad()
        return
      case 'file-out':
        s.meter = Math.max(0, (s.meter as number) - 30)
        world.sound?.clang()
        return
      case 'saved':
        chat(s, 'Calculated.', 0)
        world.sound?.pad()
        return
      case 'panel-open':
        chat(s, 'Hello!', 1)
        world.sound?.ballhit(0.3)
        return
      default:
        world.sound?.ballhit(0.2)
    }
  },
  scroll(state, world, dy) {
    const s = state as Pitch
    stirred(s)
    // The stands slide by, and a hard scroll bumps the ball off the turf.
    for (const q of s.p) {
      q.y -= dy * 0.05
      if (q.y < 0) q.y += world.h * 0.2
      if (q.y > world.h * 0.2) q.y -= world.h * 0.2
    }
    if (!s.busy && Math.abs(dy) > 60 && s.ball.vy === 0) s.ball.vy = -Math.min(500, Math.abs(dy) * 2)
  },
  chrome(state, world, event) {
    const s = state as Pitch
    if (event === 'game-open') {
      s.quiet = 1
      world.sound?.crowd(false)
    } else if (event === 'game-close') {
      s.quiet = 0
      stirred(s)
      world.sound?.crowd(true)
    }
  },
  busy(state, world, on) {
    const s = state as Pitch
    stirred(s)
    s.busy = on ? 1 : 0
    s.countT = on ? COUNTDOWN_S : 0
    s.goT = 0
    world.signal('busy', on ? 60_000 : 0)
    if (on) world.sound?.beep(440, 120)
    if (!on) kick(s, world, world.w * (world.rnd() < 0.5 ? 0.2 : 0.8), world.h * 0.5, 0.8)
  },
  outcome(state, world, kind, box) {
    const s = state as Pitch
    stirred(s)
    const { w, h, rnd } = world
    const said = CHAT[kind]
    chat(s, pick(rnd, said.text), said.team)
    const x = box ? (box.left + box.right) / 2 : w / 2
    const y = box ? (box.top + box.bottom) / 2 : h / 2
    switch (kind) {
      case 'success':
        // Into the orange goal on the right, and an explosion where the result shows.
        s.ball.x = w - BALL_R
        s.ball.vx = 0
        goalBurst(s, world, w - 40, floorOf(world) - 60, 0)
        goalBurst(s, world, x, y, 0)
        world.signal('goal', 1200)
        world.sound?.horn()
        world.sound?.cheer()
        return
      case 'warning':
        s.ball.vy = -700
        s.ball.vx = -300
        spawnBit(s.bits, { x: w - 30, y: floorOf(world) - 120, shape: 'ring', size: 6, grow: 200, life: 0.5, color: '#fff' })
        world.sound?.clang()
        return
      case 'error':
        demoBurst(s, world, x, y)
        world.signal('demo', 900)
        world.sound?.demo(panAt(world, x))
        return
      default:
        world.sound?.ballhit(0.5, panAt(world, x))
    }
  },
}

/** A low wedge of a car with its wheels, facing `dir` (1 right, -1 left). */
export function drawCar(ctx: CanvasRenderingContext2D, x: number, y: number, dir: number, color: string, scale = 1) {
  ctx.save()
  ctx.translate(x, y)
  ctx.scale(dir * scale, scale)
  ctx.fillStyle = color
  ctx.beginPath()
  ctx.moveTo(-26, -6)
  ctx.lineTo(-24, -16)
  ctx.lineTo(-6, -20)
  ctx.lineTo(8, -14)
  ctx.lineTo(26, -10)
  ctx.lineTo(28, -4)
  ctx.lineTo(-26, -4)
  ctx.closePath()
  ctx.fill()
  ctx.fillStyle = 'rgba(200,230,255,0.75)'
  ctx.beginPath()
  ctx.moveTo(-4, -18)
  ctx.lineTo(6, -14)
  ctx.lineTo(-6, -14)
  ctx.closePath()
  ctx.fill()
  ctx.fillStyle = '#111522'
  for (const wx of [-16, 16]) {
    ctx.beginPath()
    ctx.arc(wx, -4, 6, 0, TAU)
    ctx.fill()
  }
  ctx.restore()
}

/** The ball: grey panels turning with it, a soft glow and its shadow on the turf. */
export function drawBall(ctx: CanvasRenderingContext2D, b: Thing | { x: number; y: number; rot: number }, floor: number, r = BALL_R) {
  const lift = clamp((floor - r - b.y) / 400, 0, 1)
  ctx.fillStyle = `rgba(0,0,0,${0.35 * (1 - lift)})`
  ctx.beginPath()
  ctx.ellipse(b.x, floor, r * (1 - 0.5 * lift), r * 0.25, 0, 0, TAU)
  ctx.fill()
  const g = ctx.createRadialGradient(b.x - r * 0.3, b.y - r * 0.3, r * 0.1, b.x, b.y, r)
  g.addColorStop(0, '#f4f6fb')
  g.addColorStop(1, '#8d94a8')
  ctx.fillStyle = g
  ctx.beginPath()
  ctx.arc(b.x, b.y, r, 0, TAU)
  ctx.fill()
  ctx.strokeStyle = 'rgba(40,46,66,0.55)'
  ctx.lineWidth = Math.max(1, r / 10)
  for (let i = 0; i < 3; i++) {
    const a = b.rot + (i * TAU) / 3
    ctx.beginPath()
    ctx.moveTo(b.x + Math.cos(a) * r * 0.35, b.y + Math.sin(a) * r * 0.35)
    ctx.lineTo(b.x + Math.cos(a) * r, b.y + Math.sin(a) * r)
    ctx.stroke()
  }
  ctx.beginPath()
  ctx.arc(b.x, b.y, r * 0.35, 0, TAU)
  ctx.stroke()
}

/** The boost gauge in the bottom-right corner: a three-quarter ring and the number inside. */
function drawGauge(ctx: CanvasRenderingContext2D, meter: number, w: number, h: number) {
  if (meter <= 0) return
  const r = 34
  const x = w - r - 22
  const y = h - r - 70
  const start = Math.PI * 0.75
  ctx.save()
  ctx.lineWidth = 7
  ctx.lineCap = 'round'
  ctx.strokeStyle = 'rgba(255,255,255,0.15)'
  ctx.beginPath()
  ctx.arc(x, y, r, start, start + Math.PI * 1.5)
  ctx.stroke()
  ctx.strokeStyle = meter >= 100 ? '#ffd23f' : ORANGE
  ctx.shadowColor = ORANGE
  ctx.shadowBlur = 12
  ctx.beginPath()
  ctx.arc(x, y, r, start, start + Math.PI * 1.5 * (meter / 100))
  ctx.stroke()
  ctx.shadowBlur = 0
  ctx.fillStyle = '#fff'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.font = 'italic 800 20px system-ui, sans-serif'
  ctx.fillText(String(Math.round(meter)), x, y)
  ctx.font = '700 9px system-ui, sans-serif'
  ctx.fillText('BOOST', x, y + r * 0.75)
  ctx.restore()
}

/** The quick chat feed, stacked up from the pitch beside the blue goal, each line in its team's colour. */
function drawChats(ctx: CanvasRenderingContext2D, chats: Chat[], w: number, floor: number) {
  if (!chats.length) return
  ctx.save()
  ctx.font = '700 13px system-ui, sans-serif'
  ctx.textBaseline = 'middle'
  const x = w < 640 ? 64 : 120
  chats.forEach((c, i) => {
    const y = floor - 40 - (chats.length - 1 - i) * 26
    ctx.globalAlpha = Math.min(1, c.life * 2)
    const label = `${c.team ? 'Orange' : 'Blue'}: `
    const width = ctx.measureText(label + c.text).width + 16
    ctx.fillStyle = 'rgba(5,8,24,0.7)'
    ctx.fillRect(x, y - 11, width, 22)
    ctx.fillStyle = c.team ? ORANGE : BLUE
    ctx.fillRect(x, y - 11, 3, 22)
    ctx.fillText(label, x + 8, y)
    ctx.fillStyle = '#fff'
    ctx.fillText(c.text, x + 8 + ctx.measureText(label).width, y)
  })
  ctx.restore()
}
