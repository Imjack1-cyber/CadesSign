import { describe, expect, it } from 'vitest'
import {
  ARENA_H, ARENA_W, BALL_R, CAR_HH, COUNTDOWN_S, DEMO_S, GOAL_PAUSE_S, type Input, MATCH_S, NO_INPUT, STEP, STICK_SPEED,
  SUPERSONIC, type Match, arenaDistance, botInput, createMatch, createMind, tick,
} from '../../design/rocketGame'

/** Deterministic PRNG so failures reproduce. */
function seeded(seed: number) {
  return () => {
    seed = (seed * 16807) % 2147483647
    return (seed - 1) / 2147483646
  }
}

/** Runs `seconds` of fixed steps with the given inputs, collecting every event. */
function run(m: Match, seconds: number, blue: Input | (() => Input) = NO_INPUT, orange: Input | (() => Input) = NO_INPUT) {
  const events: Match['events'] = []
  for (let i = 0; i < Math.round(seconds / STEP); i++) {
    m.events = []
    tick(m, typeof blue === 'function' ? blue() : blue, typeof orange === 'function' ? orange() : orange)
    events.push(...m.events)
  }
  return events
}

/** A match already past its kickoff countdown. */
function playing(seed = 1) {
  const m = createMatch('pro', seeded(seed))
  run(m, COUNTDOWN_S + STEP)
  expect(m.phase).toBe('play')
  return m
}

describe('rocket league sideswipe', () => {
  it('kicks off mirrored, counts down and only then lets the cars move', () => {
    const m = createMatch('pro', seeded(1))
    const [blue, orange] = m.cars
    expect(blue.x).toBeCloseTo(ARENA_W - orange.x)
    expect(blue.y).toBe(orange.y)
    expect(blue.face).toBe(1)
    expect(orange.face).toBe(-1)
    expect(m.ball.x).toBe(ARENA_W / 2)
    const events = run(m, COUNTDOWN_S - 0.1, { dir: 1, jump: false, boost: true })
    expect(events.filter(e => e.type === 'countdown').map(e => e.type === 'countdown' && e.n)).toEqual([2, 1])
    expect(blue.x).toBeCloseTo(ARENA_W * 0.25)
    expect(run(m, 0.2).some(e => e.type === 'go')).toBe(true)
    run(m, 0.5, { dir: 1, jump: false, boost: false })
    expect(blue.x).toBeGreaterThan(ARENA_W * 0.25 + 50)
  })

  it('a ball over the goal line scores once, then the next kickoff starts', () => {
    const m = playing()
    Object.assign(m.ball, { x: ARENA_W - 10, y: ARENA_H - BALL_R - 5, vx: 1200, vy: 0 })
    const events = run(m, 1)
    expect(events.filter(e => e.type === 'goal')).toEqual([expect.objectContaining({ type: 'goal', team: 0 })])
    expect(m.score).toEqual([1, 0])
    expect(m.phase).toBe('goal')
    run(m, GOAL_PAUSE_S)
    expect(m.phase).toBe('countdown')
    expect(m.ball).toMatchObject({ x: ARENA_W / 2, live: true })
  })

  it('a ball against the wall above the goal bounces back instead of scoring', () => {
    const m = playing()
    Object.assign(m.ball, { x: 200, y: 300, vx: -1500, vy: 0 })
    const events = run(m, 0.5)
    expect(events.some(e => e.type === 'goal')).toBe(false)
    expect(m.ball.vx).toBeGreaterThan(0)
  })

  it('a tie at full time goes to overtime, where the next goal wins', () => {
    const m = playing()
    m.clock = STEP * 2
    const events = run(m, 0.1)
    expect(events.some(e => e.type === 'overtime')).toBe(true)
    expect(m.overtime).toBe(true)
    expect(m.phase).toBe('play')
    Object.assign(m.ball, { x: 10, y: ARENA_H - BALL_R - 5, vx: -1200, vy: 0 })
    const after = run(m, 1 + GOAL_PAUSE_S)
    expect(after.filter(e => e.type === 'end')).toEqual([{ type: 'end', winner: 1 }])
    expect(m.phase).toBe('ended')
  })

  it('a lead at full time ends the match', () => {
    const m = playing()
    m.score = [2, 1]
    m.clock = STEP
    expect(run(m, 0.05)).toContainEqual({ type: 'end', winner: 0 })
    expect(m.clock).toBe(0)
    expect(MATCH_S).toBe(120)
  })

  it('a car slower than the stick speed on a wall falls off; a fast one holds on', () => {
    for (const [speed, holds] of [[STICK_SPEED * 0.5, false], [STICK_SPEED * 3, true]] as const) {
      const m = playing()
      const car = m.cars[0]
      // On the right wall above the goal, nose up: up points left, into the arena.
      Object.assign(car, { x: ARENA_W - CAR_HH, y: 300, a: -Math.PI / 2, face: 1, ground: true, vx: 0, vy: -speed })
      run(m, 0.05)
      expect(car.ground).toBe(holds)
    }
  })

  it('drives along the floor, into the goal pocket and up its back wall', () => {
    const m = playing()
    const car = m.cars[0]
    m.ball.live = false
    m.cars[1].demoT = 999
    Object.assign(car, { x: ARENA_W * 0.6, face: 1 })
    let climbed = false
    for (let i = 0; i < 240; i++) {
      run(m, STEP, { dir: 1, jump: false, boost: true })
      if (car.ground && car.y < ARENA_H - 100) climbed = true
      expect(arenaDistance(car.x, car.y)).toBeLessThan(0)
    }
    expect(climbed).toBe(true)
  })

  it('jumps off the floor and lands back on its wheels', () => {
    const m = playing()
    const car = m.cars[0]
    m.ball.live = false
    let left = false
    const events = run(m, 1.5, () => {
      const jump = !left
      left = true
      return { dir: 0, jump, boost: false }
    })
    expect(events.map(e => e.type)).toEqual(expect.arrayContaining(['jump', 'land']))
    expect(car.ground).toBe(true)
    expect(car.y).toBeCloseTo(ARENA_H - CAR_HH, 0)
  })

  it('a flip into the ball hits it harder than a plain touch', () => {
    const speeds = [false, true].map(flip => {
      const m = playing()
      const car = m.cars[0]
      m.cars[1].demoT = 999
      // The car hangs in the air just short of the ball, moving gently towards it.
      Object.assign(car, { x: 700, y: 500, vx: 200, vy: 0, a: 0, ground: false, airT: 0.1, secondUsed: false, noStick: 1 })
      Object.assign(m.ball, { x: 700 + 45 + BALL_R + 6, y: 500, vx: 0, vy: 0 })
      run(m, STEP, { dir: flip ? 1 : 0, jump: false, boost: false })
      run(m, 0.15, { dir: flip ? 1 : 0, jump: flip, boost: false })
      return Math.hypot(m.ball.vx, m.ball.vy)
    })
    expect(speeds[1]).toBeGreaterThan(speeds[0] * 1.5)
  })

  it('a supersonic car demolishes the other, which respawns by its goal', () => {
    const m = playing()
    const [blue, orange] = m.cars
    m.ball.live = false
    Object.assign(blue, { x: 900, vx: SUPERSONIC + 100 })
    Object.assign(orange, { x: 990, vx: 0 })
    const events = run(m, 0.1, { dir: 1, jump: false, boost: true })
    expect(events).toContainEqual(expect.objectContaining({ type: 'demo', team: 1 }))
    expect(m.stats[0].demos).toBe(1)
    run(m, DEMO_S)
    expect(orange.demoT).toBe(0)
    expect(orange.x).toBeGreaterThan(ARENA_W - 200)
  })

  it('cars that meet slowly just bump', () => {
    const m = playing()
    const [blue, orange] = m.cars
    m.ball.live = false
    Object.assign(blue, { x: 900, vx: 400 })
    Object.assign(orange, { x: 990, vx: -400 })
    const events = run(m, 0.2)
    expect(events.some(e => e.type === 'demo')).toBe(false)
    expect(orange.x - blue.x).toBeGreaterThan(50)
  })

  it('boost drains while held and comes back slowly, within 0-100', () => {
    const m = playing()
    const car = m.cars[0]
    m.ball.live = false
    m.cars[1].demoT = 999
    const start = car.boost
    run(m, 1, { dir: 1, jump: false, boost: true })
    expect(car.boost).toBeLessThan(start - 25)
    run(m, 30)
    expect(car.boost).toBe(100)
    run(m, 10, { dir: 1, jump: false, boost: true })
    expect(car.boost).toBe(0)
    expect(car.boosting).toBe(false)
  })

  it.each(['rookie', 'pro', 'allstar'] as const)('bots (%s) play a minute without leaving the arena', difficulty => {
    const m = createMatch(difficulty, seeded(7))
    const minds = [createMind(), createMind()]
    let touches = 0
    for (let i = 0; i < 60 / STEP; i++) {
      m.events = []
      tick(m, botInput(m, 0, STEP, minds[0]), botInput(m, 1, STEP, minds[1]))
      touches += m.events.filter(e => e.type === 'hit').length
      for (const thing of [...m.cars, m.ball]) {
        expect(Number.isFinite(thing.x) && Number.isFinite(thing.y)).toBe(true)
        expect(arenaDistance(thing.x, thing.y)).toBeLessThan(1)
      }
    }
    expect(touches).toBeGreaterThan(5)
  })
})
