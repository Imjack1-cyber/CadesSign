/**
 * The Rocket League theme's minigame, after Rocket League Sideswipe: a side view of a small arena
 * where two cars drive on the floor, up the goal and the walls and along the ceiling, jump, flip and
 * boost into aerials, and play a timed 1v1. Blue (the player) defends the left goal, Orange (a bot)
 * the right one. This module is the whole game without a canvas: plain state, stepped at a fixed rate,
 * reporting what happened as events for RocketGame.tsx to draw and sound. Coordinates are arena
 * units with y pointing down; the floor is at y = ARENA_H.
 */

export const ARENA_W = 1600
export const ARENA_H = 800
/** Rounding of the arena's top corners, where the walls curve into the ceiling. */
const CORNER_R = 140
/** The goal mouths: openings at the bottom of the side walls, and how far back the net is. */
export const GOAL_H = 230
export const GOAL_D = 150
/** The goal pockets reach this far into the arena so their roofs read as one surface with it. */
const POCKET_IN = 300
const POCKET_R = 30

export const BALL_R = 42
/** Half the car's length and height; the body is a box that size. */
export const CAR_HL = 45
export const CAR_HH = 16

const G_CAR = 1500
const G_BALL = 1000
const ACCEL = 1400
const COAST = 600
const BRAKE = 2600
const MAX_DRIVE = 760
const MAX_SPEED = 1300
const MAX_BALL = 1700
const BOOST_ACCEL = 1350
export const JUMP = 640
const DODGE = 480
const AIR_ROT = 5.2
/** Below this speed along a wall or the ceiling a car falls off; on the floor it always holds. */
export const STICK_SPEED = 260
/** At this speed a car is supersonic: it trails, and running into the other car demolishes it. */
export const SUPERSONIC = 1050
/** Seconds after the first jump that a second jump or flip is still allowed. */
export const FLIP_WINDOW = 1.25
const FLIP_S = 0.45
/** Extra push a car gives the ball on contact, and more again during a flip. */
export const HIT_BONUS = 100
export const FLIP_BONUS = 360
/** Both cars touching the ball within this many seconds squeeze it up into the air. */
const SQUEEZE_S = 0.12
/** Boost meter: what it starts each kickoff with, drains per second while boosting, and regains. */
const BOOST_START = 40
const BOOST_DRAIN = 33
const BOOST_REGEN = 8

export const MATCH_S = 120
export const COUNTDOWN_S = 3
export const GOAL_PAUSE_S = 2.5
export const DEMO_S = 2
/** The simulation runs at this rate whatever the frame rate; stepMatch catches up in whole steps. */
export const STEP = 1 / 120

export type Team = 0 | 1
export type Difficulty = 'rookie' | 'pro' | 'allstar'
export type Phase = 'countdown' | 'play' | 'goal' | 'ended'

export const DIFFICULTIES: ReadonlyArray<{ id: Difficulty; label: string }> = [
  { id: 'rookie', label: 'Rookie' },
  { id: 'pro', label: 'Pro' },
  { id: 'allstar', label: 'All-Star' },
]

/** How the bot plays at each level: seconds between decisions, engine power and how keen it is on boost, flips and aerials. */
const BOT: Record<Difficulty, { think: number; power: number; boost: number; aim: number; hesitate: number; flips: boolean; aerials: boolean }> = {
  rookie: { think: 0.28, power: 0.72, boost: 0.15, aim: 140, hesitate: 0.5, flips: false, aerials: false },
  pro: { think: 0.14, power: 0.9, boost: 0.55, aim: 70, hesitate: 0.15, flips: true, aerials: false },
  allstar: { think: 0.06, power: 1, boost: 0.9, aim: 25, hesitate: 0, flips: true, aerials: true },
}

/** What a car is told to do: drive or rotate left / right, and whether jump and boost are held. */
export interface Input {
  dir: -1 | 0 | 1
  jump: boolean
  boost: boolean
}

export const NO_INPUT: Input = { dir: 0, jump: false, boost: false }

export interface Car {
  team: Team
  x: number
  y: number
  vx: number
  vy: number
  /** Body angle; the body's x axis is (cos a, sin a) and its up is (sin a, -cos a). */
  a: number
  /** Which way along the body's x axis the nose points. */
  face: 1 | -1
  ground: boolean
  boost: number
  boosting: boolean
  /** Seconds since the car left the ground, while a second jump is still open; -1 when not. */
  airT: number
  secondUsed: boolean
  /** Seconds of flip left, and its spin in rad/s. */
  flipT: number
  spin: number
  /** Seconds before the car may stick to a surface again after jumping off it. */
  noStick: number
  /** Seconds before it can hit the ball again, so one touch is one impulse. */
  hitCd: number
  /** Seconds until a demolished car comes back; 0 while it plays. */
  demoT: number
  jumpHeld: boolean
  /** Engine power: 1 for the player, less for a gentler bot. */
  power: number
}

export interface Ball {
  x: number
  y: number
  vx: number
  vy: number
  rot: number
  /** False between a goal and the next kickoff. */
  live: boolean
}

export interface Stats {
  goals: number
  shots: number
  saves: number
  demos: number
}

export type GameEvent =
  | { type: 'countdown'; n: number }
  | { type: 'go' }
  | { type: 'hit'; team: Team; power: number; x: number; y: number }
  | { type: 'goal'; team: Team; x: number; y: number }
  | { type: 'demo'; team: Team; x: number; y: number }
  | { type: 'jump' | 'flip' | 'land'; team: Team }
  | { type: 'boost'; team: Team; on: boolean }
  | { type: 'overtime' }
  | { type: 'end'; winner: Team }

export interface Mind {
  t: number
  input: Input
  /** Seconds the bot keeps jump held, then lets go so the next press counts. */
  hold: number
  /** A flip it means to do this many seconds after jumping, towards `flipDir`. */
  flipIn: number
  flipDir: -1 | 1
  /** Whether it has picked how to take the coming kickoff, and seconds left of waiting before going for it. */
  planned: boolean
  wait: number
  /** Seconds left of the kickoff rush, when it boosts flat out at the ball. */
  rush: number
  /** How far off the ball it aims this time, so it does not hit it the same way every time. */
  aim: number
}

export interface Match {
  phase: Phase
  /** Seconds left in the countdown or the goal celebration. */
  phaseT: number
  /** Seconds of play left, or played in overtime. */
  clock: number
  overtime: boolean
  score: [number, number]
  stats: [Stats, Stats]
  cars: [Car, Car]
  ball: Ball
  difficulty: Difficulty
  winner: Team | null
  /** The team whose goal the last shot was heading for, until someone touches it or it goes in. */
  threat: Team | null
  events: GameEvent[]
  mind: Mind
  rnd: () => number
  /** Left over from the last stepMatch, less than one STEP. */
  carry: number
  /** Seconds since the match began, and when each team last touched the ball. */
  time: number
  touched: [number, number]
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))
const sign = (v: number) => (v > 0 ? 1 : v < 0 ? -1 : 0)

/** Signed distance to a box with rounded corners (negative inside); radii are top-left, top-right, bottom-right, bottom-left. */
function sdBox(px: number, py: number, cx: number, cy: number, hx: number, hy: number, r: readonly number[]) {
  const rr = px > cx ? (py > cy ? r[2] : r[1]) : (py > cy ? r[3] : r[0])
  const qx = Math.abs(px - cx) - hx + rr
  const qy = Math.abs(py - cy) - hy + rr
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - rr
}

const ARENA_RADII = [CORNER_R, CORNER_R, 0, 0]
const POCKET_RADII = [POCKET_R, POCKET_R, POCKET_R, POCKET_R]
const POCKET_HX = (POCKET_IN + GOAL_D) / 2

/**
 * How far (x, y) is from the arena's surface: negative inside the playing space, which is the arena
 * and the two goal pockets together.
 */
export function arenaDistance(x: number, y: number) {
  return Math.min(
    sdBox(x, y, ARENA_W / 2, ARENA_H / 2, ARENA_W / 2, ARENA_H / 2, ARENA_RADII),
    sdBox(x, y, -GOAL_D + POCKET_HX, ARENA_H - GOAL_H / 2, POCKET_HX, GOAL_H / 2, POCKET_RADII),
    sdBox(x, y, ARENA_W + GOAL_D - POCKET_HX, ARENA_H - GOAL_H / 2, POCKET_HX, GOAL_H / 2, POCKET_RADII),
  )
}

/** The outward normal of the nearest surface to (x, y). */
export function arenaNormal(x: number, y: number): [number, number] {
  const e = 0.5
  const nx = arenaDistance(x + e, y) - arenaDistance(x - e, y)
  const ny = arenaDistance(x, y + e) - arenaDistance(x, y - e)
  const len = Math.hypot(nx, ny) || 1
  return [nx / len, ny / len]
}

/** The body's x axis for an up vector, and the angle that gives it. */
const axisOf = (ux: number, uy: number): [number, number] => [-uy, ux]
const angleOf = (ux: number, uy: number) => Math.atan2(ux, -uy)

function newCar(team: Team, power: number): Car {
  return {
    team, x: 0, y: 0, vx: 0, vy: 0, a: 0, face: team ? -1 : 1, ground: true, boost: BOOST_START, boosting: false,
    airT: -1, secondUsed: false, flipT: 0, spin: 0, noStick: 0, hitCd: 0, demoT: 0, jumpHeld: false, power,
  }
}

/** Puts a car back on the floor at its side's kickoff spot (or by its goal after a demolition). */
function place(car: Car, x: number) {
  Object.assign(car, {
    x, y: ARENA_H - CAR_HH, vx: 0, vy: 0, a: 0, face: car.team ? -1 : 1, ground: true, boosting: false,
    airT: -1, secondUsed: false, flipT: 0, spin: 0, noStick: 0, hitCd: 0,
  })
}

function kickoff(m: Match) {
  place(m.cars[0], ARENA_W * 0.25)
  place(m.cars[1], ARENA_W * 0.75)
  for (const car of m.cars) {
    car.boost = BOOST_START
    car.demoT = 0
  }
  // The ball sits on the centre spot, so both cars meet at it.
  Object.assign(m.ball, { x: ARENA_W / 2, y: ARENA_H - BALL_R, vx: 0, vy: 0, rot: 0, live: true })
  m.phase = 'countdown'
  m.phaseT = COUNTDOWN_S
  m.threat = null
  m.touched = [-1, -1]
  m.mind = createMind()
  m.events.push({ type: 'countdown', n: COUNTDOWN_S })
}

export const createMind = (): Mind => ({ t: 0, input: NO_INPUT, hold: 0, flipIn: -1, flipDir: -1, planned: false, wait: 0, rush: 0, aim: 0 })

export function createMatch(difficulty: Difficulty = 'pro', rnd: () => number = Math.random): Match {
  const stats = (): Stats => ({ goals: 0, shots: 0, saves: 0, demos: 0 })
  const m: Match = {
    phase: 'countdown', phaseT: COUNTDOWN_S, clock: MATCH_S, overtime: false, score: [0, 0], stats: [stats(), stats()],
    cars: [newCar(0, 1), newCar(1, BOT[difficulty].power)],
    ball: { x: 0, y: 0, vx: 0, vy: 0, rot: 0, live: true },
    difficulty, winner: null, threat: null, events: [], mind: createMind(),
    rnd, carry: 0, time: 0, touched: [-1, -1],
  }
  kickoff(m)
  m.events = []
  return m
}

export const speedOf = (car: Car) => Math.hypot(car.vx, car.vy)
export const isSupersonic = (car: Car) => speedOf(car) >= SUPERSONIC

/** The car's body axes: x (cos a, sin a) and up (sin a, -cos a). */
export function axes(car: Car) {
  const c = Math.cos(car.a)
  const s = Math.sin(car.a)
  return { xx: c, xy: s, ux: s, uy: -c }
}

/**
 * Advances the match by `dt` seconds of real time, in fixed steps, with the player's input for Blue;
 * the bot drives Orange. Events from this call are in m.events.
 */
export function stepMatch(m: Match, input: Input, dt: number) {
  m.events = []
  m.carry = Math.min(m.carry + dt, 0.25)
  while (m.carry >= STEP) {
    m.carry -= STEP
    tick(m, input, botInput(m, 1, STEP, m.mind))
  }
}

/** One fixed step. Exported for tests, which drive both cars themselves. */
export function tick(m: Match, blue: Input, orange: Input) {
  const dt = STEP
  m.time += dt
  switch (m.phase) {
    case 'ended':
      return
    case 'countdown': {
      const before = Math.ceil(m.phaseT)
      m.phaseT -= dt
      const after = Math.ceil(m.phaseT)
      if (m.phaseT <= 0) {
        m.phase = 'play'
        m.events.push({ type: 'go' })
      } else if (after !== before) m.events.push({ type: 'countdown', n: after })
      // Cars wait on the line; holding keys during the countdown does nothing.
      return
    }
    case 'goal':
      m.phaseT -= dt
      if (m.phaseT <= 0) {
        if (m.winner !== null) finish(m)
        else kickoff(m)
        return
      }
      break
    case 'play':
      if (m.overtime) m.clock += dt
      else {
        m.clock = Math.max(0, m.clock - dt)
        if (m.clock === 0) {
          if (m.score[0] === m.score[1]) {
            m.overtime = true
            m.events.push({ type: 'overtime' })
          } else {
            m.winner = m.score[0] > m.score[1] ? 0 : 1
            finish(m)
            return
          }
        }
      }
  }

  const inputs = [blue, orange]
  m.cars.forEach((car, i) => {
    if (car.demoT > 0) {
      car.demoT = Math.max(0, car.demoT - dt)
      if (car.demoT === 0) {
        place(car, car.team ? ARENA_W - 160 : 160)
        car.boost = BOOST_START
      }
      return
    }
    drive(m, car, inputs[i], dt)
  })
  if (m.ball.live) stepBall(m, dt)
  bump(m)
  if (m.ball.live) for (const car of m.cars) if (!car.demoT) touch(m, car)
  if (m.ball.live) checkGoal(m)
}

function finish(m: Match) {
  m.phase = 'ended'
  m.winner ??= m.score[0] >= m.score[1] ? 0 : 1
  m.events.push({ type: 'end', winner: m.winner })
}

function drive(m: Match, car: Car, input: Input, dt: number) {
  const jumpPressed = input.jump && !car.jumpHeld
  car.jumpHeld = input.jump
  car.noStick = Math.max(0, car.noStick - dt)
  car.hitCd = Math.max(0, car.hitCd - dt)

  // Boost needs a little in the tank to start, and refills only while the button is let go.
  const wantsBoost = input.boost && (car.boosting ? car.boost > 0 : car.boost >= 5)
  if (wantsBoost !== car.boosting) m.events.push({ type: 'boost', team: car.team, on: wantsBoost })
  car.boosting = wantsBoost
  if (wantsBoost) car.boost = Math.max(0, car.boost - BOOST_DRAIN * dt)
  else if (!input.boost) car.boost = Math.min(100, car.boost + BOOST_REGEN * dt)

  if (car.ground) groundStep(m, car, input, jumpPressed, dt)
  else airStep(m, car, input, jumpPressed, dt)
}

function groundStep(m: Match, car: Car, input: Input, jumpPressed: boolean, dt: number) {
  const [nx, ny] = arenaNormal(car.x, car.y)
  const ux = -nx
  const uy = -ny
  const [xx, xy] = axisOf(ux, uy)
  let vt = car.vx * xx + car.vy * xy

  if (jumpPressed) {
    car.ground = false
    car.vx = xx * vt + ux * JUMP
    car.vy = xy * vt + uy * JUMP
    car.airT = 0
    car.secondUsed = false
    car.noStick = 0.2
    m.events.push({ type: 'jump', team: car.team })
    return
  }

  if (input.dir) {
    car.face = input.dir
    const against = vt !== 0 && sign(vt) !== input.dir
    vt += input.dir * (against ? BRAKE : ACCEL) * car.power * dt
  } else {
    vt -= sign(vt) * Math.min(Math.abs(vt), COAST * dt)
  }
  if (car.boosting) vt += car.face * BOOST_ACCEL * car.power * dt
  // Gravity along the surface: climbing slows a car down, coming down speeds it up.
  vt += G_CAR * xy * dt
  if (!car.boosting && Math.abs(vt) > MAX_DRIVE) vt -= sign(vt) * Math.min(Math.abs(vt) - MAX_DRIVE, 1200 * dt)
  vt = clamp(vt, -MAX_SPEED, MAX_SPEED)

  const floorish = uy < -0.6
  if (!floorish && Math.abs(vt) < STICK_SPEED) {
    // Too slow to hold on: it drops off the wall or ceiling.
    detach(car, xx * vt, xy * vt)
    return
  }

  const x = car.x + xx * vt * dt
  const y = car.y + xy * vt * dt
  const d = arenaDistance(x, y)
  if (d < -(CAR_HH + 24)) {
    // The surface fell away under it.
    car.x = x
    car.y = y
    detach(car, xx * vt, xy * vt)
    return
  }
  const [mx, my] = arenaNormal(x, y)
  car.x = x - mx * (d + CAR_HH)
  car.y = y - my * (d + CAR_HH)
  car.a = angleOf(-mx, -my)
  const [ax, ay] = axisOf(-mx, -my)
  car.vx = ax * vt
  car.vy = ay * vt
}

function detach(car: Car, vx: number, vy: number) {
  car.ground = false
  car.vx = vx
  car.vy = vy
  car.airT = 0
  car.secondUsed = false
  car.noStick = 0.15
}

function airStep(m: Match, car: Car, input: Input, jumpPressed: boolean, dt: number) {
  if (car.airT >= 0) car.airT += dt
  if (jumpPressed && car.airT >= 0 && car.airT <= FLIP_WINDOW && !car.secondUsed) {
    car.secondUsed = true
    if (input.dir) {
      // A flip: a dodge sideways and a full turn, and a harder hit on the ball while it lasts.
      car.vx += input.dir * DODGE
      car.vy = Math.min(car.vy, 0) - 160
      car.flipT = FLIP_S
      car.spin = (input.dir * Math.PI * 2) / FLIP_S
      m.events.push({ type: 'flip', team: car.team })
    } else {
      const { ux, uy } = axes(car)
      car.vx += ux * JUMP * 0.75
      car.vy += uy * JUMP * 0.75
      m.events.push({ type: 'jump', team: car.team })
    }
  }
  if (car.flipT > 0) {
    car.flipT = Math.max(0, car.flipT - dt)
    car.a += car.spin * dt
  } else if (input.dir) car.a += input.dir * AIR_ROT * dt
  if (car.boosting) {
    const { xx, xy } = axes(car)
    car.vx += car.face * xx * BOOST_ACCEL * car.power * dt
    car.vy += car.face * xy * BOOST_ACCEL * car.power * dt
  }
  car.vy += G_CAR * dt
  const v = speedOf(car)
  if (v > MAX_SPEED) {
    car.vx *= MAX_SPEED / v
    car.vy *= MAX_SPEED / v
  }
  car.x += car.vx * dt
  car.y += car.vy * dt

  // The body against the arena: its middle, nose and tail, each as round as the car is high.
  const { xx, xy } = axes(car)
  for (const k of [0, 0.8, -0.8]) {
    const px = car.x + xx * CAR_HL * k
    const py = car.y + xy * CAR_HL * k
    const d = arenaDistance(px, py)
    if (d <= -CAR_HH) continue
    const [nx, ny] = arenaNormal(px, py)
    car.x -= nx * (d + CAR_HH)
    car.y -= ny * (d + CAR_HH)
    const vn = car.vx * nx + car.vy * ny
    if (vn <= 0) continue
    const [sx, sy] = axisOf(-nx, -ny)
    const vt = car.vx * sx + car.vy * sy
    const floorish = -ny < -0.6
    if (car.noStick <= 0 && (floorish || Math.abs(vt) >= STICK_SPEED * 0.8)) {
      // Lands on its wheels, whichever way it was turned.
      car.ground = true
      car.a = angleOf(-nx, -ny)
      car.vx = sx * vt
      car.vy = sy * vt
      car.x = px - xx * CAR_HL * k
      car.y = py - xy * CAR_HL * k
      const d2 = arenaDistance(car.x, car.y)
      car.x -= nx * (d2 + CAR_HH)
      car.y -= ny * (d2 + CAR_HH)
      if (input.dir) car.face = input.dir
      car.airT = -1
      car.flipT = 0
      m.events.push({ type: 'land', team: car.team })
      return
    }
    car.vx -= 1.4 * vn * nx
    car.vy -= 1.4 * vn * ny
  }
}

function stepBall(m: Match, dt: number) {
  const b = m.ball
  b.vy += G_BALL * dt
  const v = Math.hypot(b.vx, b.vy)
  if (v > MAX_BALL) {
    b.vx *= MAX_BALL / v
    b.vy *= MAX_BALL / v
  }
  b.x += b.vx * dt
  b.y += b.vy * dt
  const d = arenaDistance(b.x, b.y)
  if (d > -BALL_R) {
    const [nx, ny] = arenaNormal(b.x, b.y)
    b.x -= nx * (d + BALL_R)
    b.y -= ny * (d + BALL_R)
    const vn = b.vx * nx + b.vy * ny
    if (vn > 0) {
      // Bounces lose some speed; rolling along a surface loses a little to friction.
      const e = vn > 120 ? 0.7 : 0
      b.vx -= (1 + e) * vn * nx
      b.vy -= (1 + e) * vn * ny
      b.vx *= 1 - 0.4 * dt
      b.vy *= 1 - 0.4 * dt
    }
    // Rolls: the turn follows the speed along the surface.
    b.rot += ((b.vx * -ny + b.vy * nx) / BALL_R) * dt
  } else {
    b.rot += (b.vx / BALL_R) * dt * 0.3
  }
}

/** The ball against a car's body box: a bounce, plus the push a car gives it. */
function touch(m: Match, car: Car) {
  const b = m.ball
  const { xx, xy, ux, uy } = axes(car)
  const dx = b.x - car.x
  const dy = b.y - car.y
  const lx = clamp(dx * xx + dy * xy, -CAR_HL, CAR_HL)
  const ly = clamp(dx * ux + dy * uy, -CAR_HH, CAR_HH)
  const cx = car.x + xx * lx + ux * ly
  const cy = car.y + xy * lx + uy * ly
  let nx = b.x - cx
  let ny = b.y - cy
  const dist = Math.hypot(nx, ny)
  if (dist >= BALL_R) return
  if (dist < 1e-6) {
    nx = ux
    ny = uy
  } else {
    nx /= dist
    ny /= dist
  }
  // Out of the car first, so it never sticks inside.
  b.x = cx + nx * BALL_R
  b.y = cy + ny * BALL_R
  if (car.hitCd > 0) return
  const rvx = b.vx - car.vx
  const rvy = b.vy - car.vy
  const vn = rvx * nx + rvy * ny
  if (vn >= 0) return
  // The car is three times the ball's mass.
  const j = -1.5 * vn
  b.vx += nx * j * 0.6 + nx * (HIT_BONUS + (car.flipT > 0 ? FLIP_BONUS : 0))
  b.vy += ny * j * 0.6 + ny * (HIT_BONUS + (car.flipT > 0 ? FLIP_BONUS : 0))
  car.vx -= nx * j * 0.25
  car.vy -= ny * j * 0.25
  car.hitCd = 0.1
  m.touched[car.team] = m.time
  const other = m.touched[car.team === 0 ? 1 : 0]
  if (other >= 0 && m.time - other < SQUEEZE_S) {
    // Squeezed between both cars, the ball pops up rather than flying at either goal.
    b.vx *= 0.25
    b.vy = -Math.max(700, Math.abs(b.vy))
  }
  const power = clamp(-vn / 1600 + (car.flipT > 0 ? 0.4 : 0), 0.1, 1)
  m.events.push({ type: 'hit', team: car.team, power, x: cx, y: cy })

  // A touch on a shot at its own goal is a save; a touch that sends it at the other goal is a shot.
  if (m.threat === car.team) m.stats[car.team].saves++
  const target: Team = car.team === 0 ? 1 : 0
  m.threat = headingIn(b, target) ? target : null
  if (m.threat !== null) m.stats[car.team].shots++
}

/** Whether the ball, on its current flight, would cross into `team`'s goal mouth within two seconds. */
function headingIn(b: Ball, team: Team) {
  const goalX = team === 0 ? 0 : ARENA_W
  if (sign(goalX - b.x) !== sign(b.vx) || Math.abs(b.vx) < 300) return false
  const t = Math.abs(goalX - b.x) / Math.abs(b.vx)
  if (t > 2) return false
  const y = b.y + b.vy * t + 0.5 * G_BALL * t * t
  return y > ARENA_H - GOAL_H - BALL_R
}

/** The two cars against each other: a supersonic car demolishes the one it runs into, otherwise they bump. */
function bump(m: Match) {
  const [a, b] = m.cars
  if (a.demoT || b.demoT) return
  const dx = b.x - a.x
  const dy = b.y - a.y
  const d = Math.hypot(dx, dy)
  const reach = CAR_HL + CAR_HH
  if (d >= reach || d < 1e-6) return
  const nx = dx / d
  const ny = dy / d
  for (const [hitter, victim, toward] of [[a, b, 1], [b, a, -1]] as const) {
    const closing = (hitter.vx * nx + hitter.vy * ny) * toward
    // Two supersonic cars meeting head-on just bounce off each other.
    const headOn = isSupersonic(victim) && (victim.vx * nx + victim.vy * ny) * toward < -300
    if (isSupersonic(hitter) && closing > 700 && !headOn) {
      victim.demoT = DEMO_S
      m.stats[hitter.team].demos++
      m.events.push({ type: 'demo', team: victim.team, x: victim.x, y: victim.y })
      return
    }
  }
  const push = (reach - d) / 2
  a.x -= nx * push
  a.y -= ny * push
  b.x += nx * push
  b.y += ny * push
  const rel = (a.vx - b.vx) * nx + (a.vy - b.vy) * ny
  if (rel <= 0) return
  const j = rel * 0.75
  a.vx -= nx * j
  a.vy -= ny * j
  b.vx += nx * j
  b.vy += ny * j
}

function checkGoal(m: Match) {
  const b = m.ball
  const scorer: Team | null = b.x < -BALL_R ? 1 : b.x > ARENA_W + BALL_R ? 0 : null
  if (scorer === null) return
  m.score[scorer]++
  m.stats[scorer].goals++
  m.events.push({ type: 'goal', team: scorer, x: b.x, y: b.y })
  b.live = false
  m.threat = null
  m.phase = 'goal'
  m.phaseT = GOAL_PAUSE_S
  // In overtime the next goal wins.
  if (m.overtime) m.winner = scorer
}

/** Wraps an angle to -pi..pi. */
const wrap = (a: number) => Math.atan2(Math.sin(a), Math.cos(a))

/**
 * The bot. It decides afresh every so often (more often the better it is): defend when a shot is
 * coming and it is out of position, get round to the right side of the ball when it is not, and
 * otherwise drive at the ball, jumping and flipping into it when it is up in the air. `mind` is its
 * memory between calls; the match keeps Orange's.
 */
export function botInput(m: Match, team: Team, dt: number, mind: Mind): Input {
  const level = BOT[m.difficulty]
  mind.hold = Math.max(0, mind.hold - dt)
  mind.t -= dt
  const car = m.cars[team]
  if (m.phase === 'countdown' && !mind.planned) {
    // Most kickoffs it rushes at full boost; a weaker bot now and then hesitates.
    mind.planned = true
    mind.wait = m.rnd() < level.hesitate ? 0.3 + m.rnd() * 0.6 : 0
    mind.rush = mind.wait ? 0 : 1.2
  }
  if (m.phase !== 'play' && m.phase !== 'goal') return NO_INPUT
  mind.planned = false
  if (mind.wait > 0) {
    mind.wait -= dt
    return NO_INPUT
  }
  mind.rush = Math.max(0, mind.rush - dt)
  // A kickoff is a fair race; a gentler bot only eases off once the ball is in play.
  car.power = mind.rush > 0 ? 1 : level.power
  if (car.demoT) return NO_INPUT

  // A planned flip goes off on time, whatever else it is thinking.
  if (mind.flipIn >= 0) {
    mind.flipIn -= dt
    if (mind.flipIn < 0 && !car.ground) {
      mind.hold = 0.08
      mind.input = { dir: mind.flipDir, jump: true, boost: false }
      return mind.input
    }
  }
  if (mind.t > 0) return { ...mind.input, jump: mind.hold > 0 }
  mind.t = level.think
  mind.aim = (m.rnd() - 0.5) * 2 * level.aim

  const b = m.ball
  const attack = team === 0 ? 1 : -1
  const ownGoal = team === 0 ? 0 : ARENA_W
  const dx = b.x - car.x
  const height = ARENA_H - b.y
  const goodSide = dx * attack > 0
  let input: Input

  if (!car.ground) {
    // Level out for landing, or keep the nose on the ball in an aerial.
    const toBall = Math.atan2(b.y - car.y, b.x - car.x)
    const aerial = level.aerials && Math.hypot(dx, b.y - car.y) < 500 && b.y < car.y
    const nose = car.face === 1 ? car.a : car.a + Math.PI
    const want = aerial ? toBall : car.face === 1 ? 0 : Math.PI
    const off = wrap(want - nose)
    input = { dir: Math.abs(off) > 0.2 ? (off > 0 ? 1 : -1) : 0, jump: false, boost: aerial && Math.abs(off) < 0.6 }
  } else if (axes(car).uy > -0.6) {
    // On a wall or the ceiling: let go and drop back down.
    input = NO_INPUT
  } else if (!goodSide && b.live && (b.vx * -attack > 300 || Math.abs(b.x - ownGoal) < ARENA_W * 0.3)) {
    // Out of position with the ball near its goal: race back to defend.
    const target = ownGoal + attack * 120
    const dir = sign(target - car.x) as -1 | 0 | 1
    input = { dir, jump: false, boost: Math.abs(target - car.x) > 300 && m.rnd() < level.boost }
    if (Math.abs(dx) < 220 && height < 180 && m.rnd() < 0.5) input = { ...input, jump: true }
  } else if (!goodSide) {
    // Get round to the right side of the ball, hopping over it if it is in the way.
    const target = b.x - attack * 380
    input = { dir: sign(target - car.x) as -1 | 0 | 1, jump: Math.abs(dx) < 200 && height < 150, boost: false }
  } else {
    const target = b.x - attack * (BALL_R + 20) + mind.aim
    const dir = (sign(target - car.x) || attack) as -1 | 1
    const far = Math.abs(dx) > 450
    input = { dir, jump: false, boost: (mind.rush > 0 && level.boost > 0.3) || (far && m.rnd() < level.boost && car.boost > 15) }
    const up = height > BALL_R * 2.2
    if (Math.abs(dx) < 170 + height * 0.3 && up && height < (level.aerials ? 700 : 380)) {
      input = { ...input, jump: true, boost: level.aerials && height > 380 }
      if (level.flips && height < 300) {
        mind.flipIn = 0.12
        mind.flipDir = attack
      }
    } else if (level.flips && Math.abs(dx) < 140 && !up && m.rnd() < 0.5) {
      // A flip into a ball on the ground.
      input = { ...input, jump: true }
      mind.flipIn = 0.08
      mind.flipDir = attack
    }
  }
  if (input.jump) mind.hold = 0.08
  mind.input = input
  return { ...input, jump: mind.hold > 0 }
}
