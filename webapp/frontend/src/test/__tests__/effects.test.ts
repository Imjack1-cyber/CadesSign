import { describe, it, expect } from 'vitest'
import type { EffectKind } from '../../design/designs'
import { MAX_BITS } from '../../design/effects/bits'
import { type KeyKind, PRESETS, scaleCount, type SignalName, type State, type World } from '../../design/effects/presets'
import type { Outcome } from '../../design/signals'
import type { Sound } from '../../design/effects/sound'
import { HUNG_S, IDLE_S } from '../../design/effects/win95'

/** Deterministic PRNG so failures reproduce. */
function seeded(seed: number) {
  return () => {
    seed = (seed * 16807) % 2147483647
    return (seed - 1) / 2147483646
  }
}

function makeWorld(wild: boolean, signals: number[] = [], names: SignalName[] = []): World {
  const world: World = {
    w: 1280, h: 800, t: 0, dt: 1 / 60, wind: 0, wild, rnd: seeded(42), typing: 0,
    pointer: { x: 640, y: 400, vx: 900, vy: -300, active: true },
    signal: (name, ms = 600) => {
      if (ms > 0) {
        signals.push(world.t)
        names.push(name)
      }
    },
  }
  return world
}

const KEYS: KeyKind[] = ['char', 'char', 'space', 'char', 'delete', 'enter', 'tab']
const OUTCOMES: Outcome[] = ['success', 'warning', 'error', 'info']
const box = { left: 400, top: 300, right: 900, bottom: 360 }

/** Steps a preset for `seconds` without any input. */
function idle(kind: EffectKind, state: State, world: World, seconds: number) {
  for (let i = 0; i < seconds * 60; i++) {
    world.t += world.dt
    PRESETS[kind].step(state, world)
  }
}

/**
 * Steps a preset for `seconds`, moving the wind and pointer, clicking, typing, focusing fields and
 * finishing requests now and then, like a busy user.
 */
function run(kind: EffectKind, wild: boolean, seconds: number, signals: number[] = []) {
  const preset = PRESETS[kind]
  const world = makeWorld(wild, signals)
  const state = preset.init(world)
  let peak = 0
  for (let i = 0; i < seconds * 60; i++) {
    world.t += world.dt
    world.wind = Math.sin(world.t * 0.3) * 1.6
    world.pointer.x = 640 + Math.sin(world.t * 2) * 500
    world.pointer.y = 400 + Math.cos(world.t * 3) * 300
    if (i % 90 === 0) preset.burst?.(state, world, world.pointer.x, world.pointer.y)
    if (i % 7 === 0) {
      const { x, y } = world.pointer
      preset.key?.(state, world, { kind: KEYS[(i / 7) % KEYS.length], x, y, size: 14, edge: x + 200, field: true, glyph: 'a' })
    }
    if (i % 120 === 0) preset.focus?.(state, world, box)
    if (i % 300 === 0) preset.busy?.(state, world, (i / 300) % 2 === 0)
    if (i % 400 === 0) preset.outcome?.(state, world, OUTCOMES[(i / 400) % OUTCOMES.length], i % 800 ? box : null)
    world.typing = 4 + 4 * Math.sin(world.t)
    preset.step(state, world)
    peak = Math.max(peak, state.p.length)
  }
  return { state, world, peak }
}

describe.each(Object.keys(PRESETS) as EffectKind[])('effect preset %s', kind => {
  it.each([true, false])('stays within its limits (wild: %s)', wild => {
    const { state, world, peak } = run(kind, wild, 20)
    expect(peak).toBeLessThanOrEqual(state.max)
    expect(state.bits.length).toBeLessThanOrEqual(MAX_BITS)
    for (const q of state.p) {
      expect(Number.isFinite(q.x) && Number.isFinite(q.y)).toBe(true)
      // Particles recycle instead of drifting away for good.
      expect(q.x).toBeGreaterThan(-world.w)
      expect(q.x).toBeLessThan(world.w * 2)
      expect(q.y).toBeGreaterThan(-world.h)
      expect(q.y).toBeLessThan(world.h * 2)
    }
    if (state.H instanceof Float32Array) {
      for (const v of state.H) expect(Number.isFinite(v) && Math.abs(v) <= 3).toBe(true)
    }
    if (state.pile && state.pileCap) {
      expect(Math.max(...state.pile)).toBeLessThanOrEqual(state.pileCap)
    }
  })
})

describe('lightning', () => {
  it('never strikes twice within 3 seconds, and does strike', () => {
    const signals: number[] = []
    run('rain', true, 120, signals)
    expect(signals.length).toBeGreaterThan(3)
    for (let i = 1; i < signals.length; i++) expect(signals[i] - signals[i - 1]).toBeGreaterThanOrEqual(3)
  })
})

describe('particle density', () => {
  it('a phone gets fewer particles than a desktop, never fewer than a handful', () => {
    const desktop = makeWorld(true)
    const phone = { ...makeWorld(true), w: 390, h: 844 }
    expect(PRESETS.snow.init(phone).p.length).toBeLessThan(PRESETS.snow.init(desktop).p.length)
    expect(scaleCount(phone, 320)).toBe(Math.round(320 * 0.35))
    expect(scaleCount({ w: 10, h: 10 }, 10)).toBe(8)
    expect(scaleCount({ w: 2560, h: 1440 }, 100)).toBe(100)
  })
})

describe('vital signs', () => {
  it('typing raises the heart rate, which relaxes again at rest', () => {
    const world = makeWorld(true)
    const state = PRESETS.ecg.init(world)
    world.pointer.active = false
    world.typing = 10
    idle('ecg', state, world, 15)
    expect(state.hr).toBeGreaterThan(110)
    world.typing = 0
    idle('ecg', state, world, 60)
    expect(state.hr).toBeLessThan(70)
  })

  it('an error fibrillates into a flatline; a click shocks it back to sinus rhythm', () => {
    const names: SignalName[] = []
    const world = makeWorld(true, [], names)
    const state = PRESETS.ecg.init(world)
    PRESETS.ecg.outcome!(state, world, 'error', null)
    expect(names).toContain('flatline')
    idle('ecg', state, world, 4)
    expect(state.rhythm).not.toBe(0)
    PRESETS.ecg.burst!(state, world, 100, 100)
    expect(names).toContain('shock')
    expect(state.rhythm).toBe(0)
  })

  it('recovers by itself when nobody shocks it', () => {
    const world = makeWorld(true)
    const state = PRESETS.ecg.init(world)
    PRESETS.ecg.outcome!(state, world, 'error', null)
    idle('ecg', state, world, 12)
    expect(state.rhythm).toBe(0)
  })

  it('deleting causes a premature beat, at most one every two seconds', () => {
    const world = makeWorld(true)
    const state = PRESETS.ecg.init(world)
    const key = { kind: 'delete' as const, x: 0, y: 0, size: 14, edge: 0, field: true }
    PRESETS.ecg.key!(state, world, key)
    expect(state.pvcPending).toBe(1)
    idle('ecg', state, world, 1.5)
    PRESETS.ecg.key!(state, world, key)
    expect(state.pvcPending).toBe(0)
  })
})

describe("notary's desk", () => {
  it('a result stamps the page; an error voids it, and only a signature gets wax', () => {
    const names: SignalName[] = []
    const world = makeWorld(true, [], names)
    const state = PRESETS.ink.init(world)
    PRESETS.ink.outcome!(state, world, 'success', box)
    PRESETS.ink.outcome!(state, world, 'error', box)
    expect(names).toEqual(['stamp', 'void'])
    idle('ink', state, world, 1)
    expect(state.p.some(q => q.type === 4)).toBe(true)
  })

  it('keeps the typed glyph only when the key carries one', () => {
    const world = makeWorld(true)
    const state = PRESETS.ink.init(world)
    const strike = { kind: 'char' as const, x: 10, y: 10, size: 14, edge: 100, field: true }
    PRESETS.ink.key!(state, world, { ...strike, glyph: 'Q' })
    PRESETS.ink.key!(state, world, strike)
    const strikes = state.p.filter(q => q.type === 1)
    expect(strikes.map(q => q.code)).toEqual(['Q'.codePointAt(0), 0])
  })
})

describe('zen garden', () => {
  it('raking changes the sand along the stroke only', () => {
    const world = makeWorld(true)
    const state = PRESETS.sand.init(world)
    const before = Float32Array.from(state.H as Float32Array)
    world.pointer = { x: 100, y: 100, vx: 500, vy: 0, active: true }
    PRESETS.sand.step(state, world)
    world.pointer.x = 300
    PRESETS.sand.step(state, world)
    const H = state.H as Float32Array
    const gw = state.gw as number
    const cell = state.cell as number
    const at = (x: number, y: number) => Math.round(y / cell) * gw + Math.round(x / cell)
    expect(H.some((v, i) => Math.abs(v - before[i]) > 0.1)).toBe(true)
    expect(H[at(1000, 700)]).toBe(before[at(1000, 700)])
  })

  it('typing drops pebbles up to a cap; deleting picks the nearest up again', () => {
    const world = makeWorld(true)
    const state = PRESETS.sand.init(world)
    for (let i = 0; i < 40; i++) {
      PRESETS.sand.key!(state, world, { kind: 'char', x: 200 + i * 10, y: 200, size: 14, edge: 800, field: true })
    }
    expect(state.p.length).toBe(state.max)
    PRESETS.sand.key!(state, world, { kind: 'delete', x: 590, y: 200, size: 14, edge: 800, field: true })
    idle('sand', state, world, 1)
    expect(state.p.length).toBe(state.max - 1)
  })
})

describe('windows 95', () => {
  /** A Sound that records which voices played, in order. */
  function spySound() {
    const calls: string[] = []
    const sound = new Proxy({} as Sound, { get: (_t, name) => () => { calls.push(String(name)) } })
    return { sound, calls }
  }
  const at = { x: 10, y: 10, size: 14, edge: 100, field: true }

  it('backspace in an empty field beeps; in a filled one it only clicks', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.desktop.init(world)
    PRESETS.desktop.key!(state, world, { ...at, kind: 'delete', empty: true })
    PRESETS.desktop.key!(state, world, { ...at, kind: 'delete', empty: false })
    expect(calls).toEqual(['ding', 'click'])
  })

  it('success plays tada; an error plays the chord and shakes the dialog', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.desktop.init(world)
    PRESETS.desktop.outcome!(state, world, 'success', box)
    PRESETS.desktop.outcome!(state, world, 'error', box)
    expect(calls).toEqual(['tada', 'chord'])
    expect(names).toEqual(['tada', 'stop'])
  })

  it('fast typing stops responding for a moment, at most once every 8 seconds', () => {
    const names: SignalName[] = []
    const world = makeWorld(true, [], names)
    const state = PRESETS.desktop.init(world)
    world.typing = 12
    for (let i = 0; i < 100; i++) {
      world.t += 0.1
      PRESETS.desktop.key!(state, world, { ...at, kind: 'char' })
    }
    expect(names.filter(n => n === 'lag')).toHaveLength(2)
  })

  it('a minute without input starts the screensaver; a key ends it', () => {
    const names: SignalName[] = []
    const world = makeWorld(true, [], names)
    world.pointer.active = false
    const state = PRESETS.desktop.init(world)
    idle('desktop', state, world, IDLE_S - 1)
    expect(state.saver).toBe(0)
    idle('desktop', state, world, 2)
    expect(state.saver).toBeGreaterThan(0)
    expect(names).toContain('saver')
    PRESETS.desktop.key!(state, world, { ...at, kind: 'char' })
    expect(state.saver).toBe(0)
  })

  it('a long request stops responding until it ends; no screensaver meanwhile; modem, then disk chatter', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    world.pointer.active = false
    const state = PRESETS.desktop.init(world)
    PRESETS.desktop.busy!(state, world, true)
    expect(names).toEqual(['starting', 'hourglass'])
    expect(calls).toEqual(['modem'])
    idle('desktop', state, world, HUNG_S - 1)
    expect(names).not.toContain('hung')
    idle('desktop', state, world, IDLE_S)
    expect(names.filter(n => n === 'hung')).toHaveLength(1)
    expect(state.saver).toBe(0)
    expect(calls.filter(c => c === 'seek').length).toBeGreaterThan(50)
    PRESETS.desktop.busy!(state, world, false)
    expect(calls[calls.length - 1]).toBe('modem')
    expect(state.hung).toBe(0)
  })

  it('clicking like mad hangs it: further clicks only beep, and the hourglass smears until it repaints', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.desktop.init(world)
    for (let i = 0; i < 7; i++) PRESETS.desktop.burst!(state, world, 10, 10)
    expect(names).toEqual(['lag'])
    calls.length = 0
    PRESETS.desktop.burst!(state, world, 10, 10)
    expect(calls).toEqual(['ding'])

    world.pointer.vx = 0
    world.pointer.vy = 0
    for (let i = 0; i < 30; i++) {
      world.pointer.x = 100 + i * 10
      world.t += world.dt
      PRESETS.desktop.step(state, world)
    }
    const smear = state.smear as unknown[]
    expect(smear.length).toBeGreaterThan(20)
    idle('desktop', state, world, 2)
    expect(smear).toHaveLength(0)
  })

  it('window motions zoom an outline and play their sound', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.desktop.init(world)
    PRESETS.desktop.chrome!(state, world, 'minimize', { from: box, to: { left: 60, top: 774, right: 220, bottom: 798 } })
    PRESETS.desktop.chrome!(state, world, 'close', {})
    expect(calls).toEqual(['minimize', 'recycle'])
    expect(state.p.filter(q => q.type === 1)).toHaveLength(1)
  })
})
