import { beforeEach, describe, it, expect } from 'vitest'
import type { EffectKind } from '../../design/designs'
import { MAX_BITS } from '../../design/effects/bits'
import { type Activity, type Control, type KeyKind, PRESETS, scaleCount, type SignalName, type State, type World } from '../../design/effects/presets'
import type { Outcome } from '../../design/signals'
import type { Sound } from '../../design/effects/sound'
import { controlAt, controlKind, hoverAt, optionIn, optionIndex } from '../../design/effects/engine'
import { BALLOONS_MAX, CONFETTI_MAX, FLY_S, POINTER_IDLE_S, POINTER_SIZE } from '../../design/effects/ios'
import { reloadIosPrefs, setIosPrefs } from '../../design/iosPrefs'
import { PING_S, WHALE_IDLE_S } from '../../design/effects/deepsea'
import { DEGAUSS_COOLDOWN } from '../../design/effects/terminal'
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

/** A Sound that records which voices played, in order. */
function spySound() {
  const calls: string[] = []
  const sound = new Proxy({} as Sound, { get: (_t, name) => () => { calls.push(String(name)) } })
  return { sound, calls }
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

describe('retro terminal', () => {
  const at = { x: 330, y: 200, size: 14, edge: 600, field: true }

  it('a typed character drops into the rain under the caret with a clack; backspace on empty rings the bell', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.matrix.init(world)
    PRESETS.matrix.key!(state, world, { ...at, kind: 'char', glyph: 'Z' })
    const col = state.p[Math.floor(at.x / 16)]
    expect(col).toMatchObject({ on: 1, y: at.y, ch: 'Z'.charCodeAt(0) })
    expect(col.hot).toBeGreaterThan(0)
    PRESETS.matrix.key!(state, world, { ...at, kind: 'delete', empty: true })
    expect(calls).toEqual(['keyclack', 'keyclack', 'beep'])
    expect(names).toEqual(['typing', 'typing'])
  })

  it('a request turns every column on and speeds the rain until it ends', () => {
    const names: SignalName[] = []
    const world = makeWorld(false, [], names)
    const state = PRESETS.matrix.init(world)
    const col = state.p[0]
    const y0 = col.y
    PRESETS.matrix.busy!(state, world, true)
    expect(state.p.every(q => q.on)).toBe(true)
    expect(names).toEqual(['busy'])
    PRESETS.matrix.step(state, world)
    expect(col.y - y0).toBeCloseTo(col.v * 2.5 * world.dt)
    PRESETS.matrix.busy!(state, world, false)
    expect(state.busy).toBe(0)
  })

  it('each result prints its status and sounds the speaker', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.matrix.init(world)
    for (const kind of OUTCOMES) PRESETS.matrix.outcome!(state, world, kind, box)
    expect(names).toEqual(['ok', 'warn', 'fail'])
    expect(calls.length).toBeGreaterThanOrEqual(4)
    expect(new Set(calls)).toEqual(new Set(['beep']))
  })

  it('a click on bare page degausses, at most once per cooldown; a click on a button clicks', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.matrix.init(world)
    world.pointer.bare = false
    world.pointer.control = 'button'
    PRESETS.matrix.burst!(state, world, 100, 100)
    world.pointer.bare = true
    world.pointer.control = undefined
    PRESETS.matrix.burst!(state, world, 100, 100)
    PRESETS.matrix.burst!(state, world, 100, 100)
    world.t += DEGAUSS_COOLDOWN
    PRESETS.matrix.burst!(state, world, 100, 100)
    expect(names).toEqual(['degauss', 'degauss'])
    expect(calls).toEqual(['press', 'degauss', 'degauss'])
  })

  it('each kind of control sounds different; back and next leave it to the move that follows', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.matrix.init(world)
    const controls: Control[] = ['button', 'choice', 'toggle', 'nav', 'field', 'upload', 'download', 'discard', 'back', 'forward', 'disabled']
    for (const control of controls) {
      world.pointer.control = control
      PRESETS.matrix.burst!(state, world, 100, 100)
    }
    expect(calls).toEqual(['press', 'select', 'toggle', 'channel', 'cursor', 'insert', 'write', 'erase', 'deny'])
  })

  it('a command beeps when accepted and buzzes when refused; shutdown darkens and silences until startup', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.matrix.init(world)
    PRESETS.matrix.command!(state, world, true)
    PRESETS.matrix.command!(state, world, false)
    PRESETS.matrix.chrome!(state, world, 'shutdown', {})
    expect(state.off).toBe(1)
    PRESETS.matrix.chrome!(state, world, 'startup', {})
    expect(state.off).toBe(0)
    expect(calls).toEqual(['beep', 'deny', 'poweroff', 'hum', 'poweron', 'hum'])
  })

  it('the About panel opens with a window sweep and a printout, prints again per tab, and closes with a sweep', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.matrix.init(world)
    for (const a of ['panel-open', 'tab', 'panel-close'] as Activity[]) PRESETS.matrix.activity!(state, world, a)
    expect(calls).toEqual(['maximize', 'printout', 'printout', 'minimize'])
    expect(state.p.every(q => q.hot > 0)).toBe(true)
  })

  it('scrolling feeds a line per 40 px, carries the rest over, and leaves the rain alone', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.matrix.init(world)
    const col = state.p[0]
    col.y = 300
    PRESETS.matrix.scroll!(state, world, 30)
    expect(calls).toEqual([])
    PRESETS.matrix.scroll!(state, world, 30)
    expect(calls).toEqual(['linefeed'])
    expect(state.feed).toBe(20)
    expect(col.y).toBe(300)
    PRESETS.matrix.scroll!(state, world, -100000)
    expect(calls).toHaveLength(2)
  })

  it('browsing a list plays a blip per option', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.matrix.init(world)
    PRESETS.matrix.browse!(state, world, 0)
    PRESETS.matrix.browse!(state, world, 1)
    expect(calls).toEqual(['option', 'option'])
  })

  it('moving forward or back, files in and out, and a produced file each have their sound', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.matrix.init(world)
    const activities: Activity[] = ['forward', 'back', 'file-in', 'file-out', 'saved']
    for (const a of activities) PRESETS.matrix.activity!(state, world, a)
    PRESETS.matrix.focus!(state, world, box)
    expect(calls).toEqual(['advance', 'back', 'load', 'erase', 'write', 'cursor'])
  })

  it('moving the pointer ticks the rollers, more often the faster it goes, and only when wild', () => {
    const ticksAt = (wild: boolean, speed: number) => {
      const { sound, calls } = spySound()
      const world = { ...makeWorld(wild), sound }
      world.pointer.vx = speed
      world.pointer.vy = 0
      const state = PRESETS.matrix.init(world)
      for (let i = 0; i < 60; i++) PRESETS.matrix.step(state, world)
      return calls.filter(c => c === 'tick').length
    }
    expect(ticksAt(true, 0)).toBe(0)
    expect(ticksAt(true, 300)).toBeGreaterThan(0)
    expect(ticksAt(true, 1500)).toBeGreaterThan(ticksAt(true, 300))
    expect(ticksAt(false, 1500)).toBe(0)
  })
})

describe('deep sea', () => {
  const at = { x: 330, y: 500, size: 14, edge: 600, field: true }
  type Things = Array<Record<string, number>>
  const still = (world: World) => Object.assign(world.pointer, { vx: 0, vy: 0 })

  it('starts the ocean and keeps its fish on screen while they school', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    still(world)
    const state = PRESETS.plankton.init(world)
    PRESETS.plankton.start!(state, world)
    expect(calls).toEqual(['ocean'])
    idle('plankton', state, world, 30)
    for (const f of state.fish as Things) {
      expect(f.x).toBeGreaterThanOrEqual(0)
      expect(f.x).toBeLessThanOrEqual(world.w)
      expect(f.y).toBeGreaterThanOrEqual(0)
      expect(f.y).toBeLessThanOrEqual(world.h)
      expect(Math.hypot(f.vx, f.vy)).toBeGreaterThan(0)
    }
  })

  it('typing sends bubbles up from the caret; enter sends more, delete pops one', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.plankton.init(world)
    const bubbles = () => (state.bubbles as Things).length
    PRESETS.plankton.key!(state, world, { ...at, kind: 'char', glyph: 'a' })
    expect(bubbles()).toBe(1)
    expect((state.bubbles as Things)[0]).toMatchObject({ x: at.x, y: at.y })
    PRESETS.plankton.key!(state, world, { ...at, kind: 'enter' })
    expect(bubbles()).toBe(6)
    PRESETS.plankton.key!(state, world, { ...at, kind: 'delete' })
    expect(bubbles()).toBe(5)
    PRESETS.plankton.key!(state, world, { ...at, kind: 'tab' })
    // A character, the five bubbles of Enter, one, a little apart so each is heard, and the pop.
    expect(calls).toEqual(Array(7).fill('bubble'))
    // They rise, and pop at the top.
    const y0 = (state.bubbles as Things)[0].y
    idle('plankton', state, world, 1)
    expect((state.bubbles as Things)[0].y).toBeLessThan(y0)
    idle('plankton', state, world, 20)
    expect(bubbles()).toBe(0)
  })

  it('each result has its voice and status', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.plankton.init(world)
    for (const kind of OUTCOMES) PRESETS.plankton.outcome!(state, world, kind, box)
    expect(names).toEqual(['ok', 'warn', 'fail'])
    expect(calls).toEqual(['whale', 'sonar', 'creak', 'creak', 'sonar'])
    expect((state.jelly as Things).every(j => j.alarm === 1)).toBe(true)
  })

  it('a request pings sonar every few seconds until it ends', () => {
    const { sound, calls } = spySound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    still(world)
    const state = PRESETS.plankton.init(world)
    PRESETS.plankton.busy!(state, world, true)
    expect(names).toEqual(['busy'])
    idle('plankton', state, world, PING_S * 3 - 0.1)
    expect(calls.filter(c => c === 'sonar')).toHaveLength(3)
    expect(state.lure).toBeGreaterThan(0)
    PRESETS.plankton.busy!(state, world, false)
    idle('plankton', state, world, PING_S * 3)
    expect(calls.filter(c => c === 'sonar')).toHaveLength(3)
    expect(state.lure).toBe(0)
  })

  it('each kind of control sounds; back and next leave it to the current that follows', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.plankton.init(world)
    const controls: Control[] = ['button', 'choice', 'toggle', 'nav', 'field', 'upload', 'download', 'discard', 'back', 'forward', 'disabled']
    for (const control of controls) {
      world.pointer.control = control
      PRESETS.plankton.burst!(state, world, 100, 100)
    }
    expect(calls).toEqual(['bubble', 'sonar', 'bubble', 'swish', 'sonar', 'bubble', 'sonar', 'bubble', 'deny'])
    calls.length = 0
    PRESETS.plankton.activity!(state, world, 'forward')
    expect(state.current).toBeGreaterThan(0)
    PRESETS.plankton.activity!(state, world, 'back')
    expect(state.current).toBeLessThan(0)
    expect(calls).toEqual(['swish', 'swish'])
  })

  it('a click on bare page lets bubbles go and scatters the fish', () => {
    const world = makeWorld(true)
    still(world)
    const state = PRESETS.plankton.init(world)
    const fish = state.fish as Things
    const f = fish[0]
    world.pointer.bare = true
    PRESETS.plankton.burst!(state, world, f.x + 10, f.y)
    expect((state.bubbles as Things).length).toBeGreaterThan(0)
    expect(f.startle).toBeGreaterThan(0.9)
  })

  it('plankton glow when the pointer stirs the water, and fade again', () => {
    const world = makeWorld(true)
    const state = PRESETS.plankton.init(world)
    const q = state.p[0]
    q.glow = 0
    Object.assign(world.pointer, { x: q.x, y: q.y, vx: 900, vy: 0 })
    PRESETS.plankton.step(state, world)
    expect(q.glow).toBeGreaterThan(0.5)
    still(world)
    world.pointer.x = q.x + 1000
    idle('plankton', state, world, 5)
    expect(q.glow).toBeLessThan(0.05)
  })

  it('a whale passes only after a long while without input', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    still(world)
    const state = PRESETS.plankton.init(world)
    idle('plankton', state, world, WHALE_IDLE_S - 2)
    PRESETS.plankton.key!(state, world, { ...at, kind: 'char' })
    idle('plankton', state, world, WHALE_IDLE_S - 2)
    expect(state.whale).toBe(0)
    idle('plankton', state, world, 3)
    expect(state.whale).toBe(1)
    expect(calls.filter(c => c === 'whale')).toHaveLength(1)
  })

  it('a touch has no beam: fish stay at half-light and a swipe does not scare them', () => {
    const world = makeWorld(true)
    const state = PRESETS.plankton.init(world)
    const f = (state.fish as Things)[0]
    Object.assign(world.pointer, { x: f.x + 5, y: f.y, vx: 3000, vy: 0, touch: true })
    PRESETS.plankton.step(state, world)
    expect(f.startle).toBe(0)
  })

  it('holding a press on bare water keeps blowing bubbles', () => {
    const { sound, calls } = spySound()
    const world = { ...makeWorld(true), sound }
    still(world)
    const state = PRESETS.plankton.init(world)
    Object.assign(world.pointer, { down: true, bare: true })
    idle('plankton', state, world, 1)
    const held = (state.bubbles as Things).length
    expect(held).toBeGreaterThanOrEqual(12)
    expect(calls.filter(c => c === 'bubble').length).toBeGreaterThan(5)
    world.pointer.down = false
    idle('plankton', state, world, 0.5)
    expect((state.bubbles as Things).length).toBeLessThanOrEqual(held)
  })

  it('fish gather in a light held still', () => {
    const world = makeWorld(true)
    still(world)
    Object.assign(world.pointer, { x: 300, y: 300 })
    const state = PRESETS.plankton.init(world)
    const near = () => (state.fish as Things).filter(f => Math.hypot(f.x - 300, f.y - 300) < 200).length
    const before = near()
    idle('plankton', state, world, 8)
    expect(near()).toBeGreaterThan(before)
  })

  it('a request draws the school to the lure; success sends it bolting', () => {
    const world = makeWorld(true)
    still(world)
    world.pointer.active = false
    const state = PRESETS.plankton.init(world)
    const fish = state.fish as Things
    const lure = { x: world.w * 0.8, y: world.h * 0.82 }
    const spread = () => fish.reduce((sum, f) => sum + Math.hypot(f.x - lure.x, f.y - lure.y), 0) / fish.length
    const before = spread()
    PRESETS.plankton.busy!(state, world, true)
    idle('plankton', state, world, 10)
    const busy = spread()
    expect(busy).toBeLessThan(before)
    PRESETS.plankton.outcome!(state, world, 'success', box)
    expect(Math.max(...fish.map(f => f.startle))).toBeGreaterThan(0.5)
  })

  it('a resize keeps a running request and a passing whale', () => {
    const world = makeWorld(true)
    const state = PRESETS.plankton.init(world)
    PRESETS.plankton.busy!(state, world, true)
    state.whale = 1
    state.whaleX = 200
    const resized = PRESETS.plankton.init({ ...world, w: 800 }, state)
    expect(resized).toMatchObject({ busy: 1, whale: 1, whaleX: 200 })
    expect(PRESETS.plankton.init(world)).toMatchObject({ busy: 0, whale: 0 })
  })

  it('calm water still moves but never calls the whale', () => {
    const world = makeWorld(false)
    const state = PRESETS.plankton.init(world)
    const f = (state.fish as Things)[0]
    const x0 = f.x
    idle('plankton', state, world, WHALE_IDLE_S + 5)
    expect(f.x).not.toBe(x0)
    expect(state.whale).toBe(0)
  })
})

describe('controlKind', () => {
  /** An element as the composed path of a press on it: itself, then its ancestors. */
  function pathOf(html: string, selector: string) {
    document.body.innerHTML = html
    const path: Element[] = []
    for (let el: Element | null = document.querySelector(selector); el; el = el.parentElement) path.push(el)
    return path
  }

  it('names the control a press landed on, from IX properties or plain attributes', () => {
    const back = pathOf('<ix-button><span>Back</span></ix-button>', 'span')
    Object.assign(back[1], { icon: 'chevron-left' })
    expect(controlKind(back)).toBe('back')
    const next = pathOf('<ix-button><span>Next</span></ix-button>', 'span')
    Object.assign(next[1], { iconRight: 'chevron-right' })
    expect(controlKind(next)).toBe('forward')
    expect(controlKind(pathOf('<ix-button icon="download">x</ix-button>', 'ix-button'))).toBe('download')
    expect(controlKind(pathOf('<ix-action-card><p>Sign</p></ix-action-card>', 'p'))).toBe('choice')
    expect(controlKind(pathOf('<ix-tab-item>Analytics</ix-tab-item>', 'ix-tab-item'))).toBe('nav')
    expect(controlKind(pathOf('<details><summary>More</summary></details>', 'summary'))).toBe('toggle')
    expect(controlKind(pathOf('<ix-input></ix-input>', 'ix-input'))).toBe('field')
    expect(controlKind(pathOf('<ix-upload></ix-upload>', 'ix-upload'))).toBe('upload')
    expect(controlKind(pathOf('<button disabled>Go</button>', 'button'))).toBe('disabled')
    expect(controlKind(pathOf('<div><p>Just text</p></div>', 'p'))).toBeUndefined()
  })
})

describe('controlAt and hoverAt', () => {
  const pathOf = (selector: string) => {
    const path: Element[] = []
    for (let el: Element | null = document.querySelector(selector); el; el = el.parentElement) path.push(el)
    return path
  }

  it('give the control itself along with its kind, or text the mouse rests on', () => {
    document.body.innerHTML = '<main><ix-button><span>Go</span></ix-button><p>Some <b>text</b></p><div class="page"></div></main>'
    const hit = controlAt(pathOf('span'))!
    expect(hit.el.tagName).toBe('IX-BUTTON')
    expect(hit.kind).toBe('button')
    expect(hoverAt(pathOf('span'))?.el).toBe(hit.el)
    expect(hoverAt(pathOf('b'))).toMatchObject({ kind: 'text' })
    expect(hoverAt(pathOf('p'))).toMatchObject({ kind: 'text' })
    expect(hoverAt(pathOf('.page'))).toBeUndefined()
  })
})

describe('optionIn', () => {
  it('finds the option a pointer is over and its place in the list', () => {
    document.body.innerHTML = '<ix-select><ix-select-item>A</ix-select-item><ix-select-item><b>B</b></ix-select-item></ix-select>'
    const b = document.querySelector('b')!
    const path: Element[] = []
    for (let el: Element | null = b; el; el = el.parentElement) path.push(el)
    const option = optionIn(path)!
    expect(option.textContent).toBe('B')
    expect(optionIndex(option)).toBe(1)
    expect(optionIn(path.slice(2))).toBeUndefined()
  })
})

describe('windows 95', () => {
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

describe('ipados / ios', () => {
  const at = { x: 100, y: 100, size: 14, edge: 300, field: true }
  const button = { box: { left: 600, top: 380, right: 680, bottom: 420 }, radius: 10, kind: 'button' as const, line: 20 }

  beforeEach(() => {
    window.localStorage.clear()
    reloadIosPrefs()
  })

  /** A Sound that records each voice with its arguments. */
  function argSound() {
    const calls: unknown[][] = []
    const sound = new Proxy({} as Sound, { get: (_t, name) => (...args: unknown[]) => { calls.push([String(name), ...args]) } })
    return { sound, calls, voices: () => calls.map(c => c[0]) }
  }

  /** A world with the mouse resting at (640, 400), and every signal recorded with its duration. */
  function still(wild = true) {
    const signals: Array<[SignalName, number]> = []
    const world = makeWorld(wild)
    world.pointer = { x: 640, y: 400, vx: 0, vy: 0, active: true }
    world.signal = (name, ms = 600) => { signals.push([name, ms]) }
    return { world, signals }
  }

  const cur = (s: State) => s.cur as Record<string, number>
  /** How long the pointer signal was last set for; 0 when it was taken off. */
  const lastPointer = (signals: Array<[SignalName, number]>) => signals.filter(([n]) => n === 'pointer').slice(-1)[0][1]

  it('key taps sound by kind; with keyboard clicks off they stay silent', () => {
    const { sound, calls } = argSound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.glass.init(world)
    for (const kind of ['char', 'space', 'delete', 'enter', 'tab'] as KeyKind[]) PRESETS.glass.key!(state, world, { ...at, kind })
    expect(calls).toEqual([['keytap', 'char'], ['keytap', 'modifier'], ['keytap', 'delete'], ['keytap', 'modifier'], ['keytap', 'modifier']])
    setIosPrefs({ keyClicks: false })
    PRESETS.glass.key!(state, world, { ...at, kind: 'char' })
    expect(calls).toHaveLength(5)
  })

  it('the pointer follows the mouse, springs into the shape of a button, and stays steady at any frame rate', () => {
    const { world } = still()
    const state = PRESETS.glass.init(world)
    idle('glass', state, world, 0.5)
    expect(cur(state)).toMatchObject({ w: expect.closeTo(POINTER_SIZE, 0), h: expect.closeTo(POINTER_SIZE, 0) })
    expect(cur(state).x).toBeCloseTo(640, 0)
    expect(cur(state).a).toBeGreaterThan(0.95)

    world.hover = button
    idle('glass', state, world, 1)
    // The button's box with a little room around it, its corners rounded to match.
    expect(cur(state).w).toBeCloseTo(86, 0)
    expect(cur(state).h).toBeCloseTo(46, 0)
    expect(cur(state).r).toBeCloseTo(13, 0)
    expect(cur(state).x).toBeCloseTo(640, 0)

    // Long frames (a busy tab) must not throw the spring off.
    world.hover = undefined
    world.dt = 0.05
    for (let i = 0; i < 40; i++) {
      world.pointer.x = i % 2 ? 100 : 1200
      world.t += world.dt
      PRESETS.glass.step(state, world)
      expect(Math.abs(cur(state).x)).toBeLessThan(2000)
    }
  })

  it('leans towards the mouse on a button, turns into a text cursor over fields and text, and stays round over large cards', () => {
    const { world } = still()
    const state = PRESETS.glass.init(world)
    world.pointer.x = 676
    world.hover = button
    idle('glass', state, world, 1)
    // A tenth of the way towards the mouse, at most a few pixels.
    expect(cur(state).x).toBeCloseTo(643.6, 0)
    world.hover = { ...button, kind: 'field' }
    idle('glass', state, world, 1)
    expect(cur(state).w).toBeCloseTo(2.5, 0)
    expect(cur(state).y).toBeCloseTo(400, 0)
    world.hover = { box: { left: 300, top: 100, right: 900, bottom: 300 }, radius: 22, kind: 'choice', line: 20 }
    idle('glass', state, world, 1)
    expect(cur(state).w).toBeCloseTo(POINTER_SIZE, 0)
  })

  it('hides while typing until the mouse moves, and fades when left alone', () => {
    const { world } = still()
    const state = PRESETS.glass.init(world)
    idle('glass', state, world, 0.5)
    PRESETS.glass.key!(state, world, { ...at, kind: 'char' })
    idle('glass', state, world, 0.5)
    expect(cur(state).a).toBeLessThan(0.05)
    world.pointer.x += 20
    idle('glass', state, world, 0.5)
    expect(cur(state).a).toBeGreaterThan(0.95)
    idle('glass', state, world, POINTER_IDLE_S + 3)
    expect(cur(state).a).toBeLessThan(0.05)
  })

  it('takes the place of the cursor only for a mouse, at Wild, with Pointer Control on', () => {
    const { world, signals } = still()
    const state = PRESETS.glass.init(world)
    idle('glass', state, world, 0.1)
    expect(lastPointer(signals)).toBeGreaterThan(0)
    world.pointer.touch = true
    idle('glass', state, world, 0.1)
    expect(lastPointer(signals)).toBe(0)
    expect(cur(state).a).toBeLessThan(0.5)

    world.pointer.touch = false
    setIosPrefs({ pointer: false })
    idle('glass', state, world, 0.5)
    expect(lastPointer(signals)).toBe(0)
    expect(cur(state).a).toBeLessThan(0.05)

    const calm = still(false)
    const quiet = PRESETS.glass.init(calm.world)
    setIosPrefs({ pointer: true })
    idle('glass', quiet, calm.world, 0.5)
    expect(calm.signals.some(([n, ms]) => n === 'pointer' && ms > 0)).toBe(false)
  })

  it('each control sounds its own; back and next leave it to the slide; a finger lights the glass', () => {
    const { sound, voices } = argSound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.glass.init(world)
    const controls: Control[] = ['button', 'choice', 'toggle', 'nav', 'field', 'upload', 'download', 'discard', 'back', 'forward', 'disabled']
    for (const control of controls) {
      world.pointer.control = control
      PRESETS.glass.burst!(state, world, 100, 100)
    }
    expect(voices()).toEqual(['glasstap', 'pickertick', 'switchtick', 'glasstap', 'glasstap', 'glasstap', 'glasstap', 'haptic'])
    expect(state.bits).toHaveLength(0)
    world.pointer.touch = true
    world.pointer.control = 'button'
    PRESETS.glass.burst!(state, world, 100, 100)
    expect(state.bits.length).toBeGreaterThan(0)
  })

  it('a signature gets confetti, a verified one balloons, both within their caps and gone again soon', () => {
    const { sound, voices } = argSound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.glass.init(world)
    const confetti = () => state.p.filter(q => q.flip !== undefined)
    const balloons = () => state.p.filter(q => q.r !== undefined)
    PRESETS.glass.outcome!(state, world, 'success', box, 'sign')
    PRESETS.glass.outcome!(state, world, 'success', box, 'sign')
    idle('glass', state, world, 1.5)
    expect(confetti().length).toBeGreaterThan(50)
    expect(confetti().length).toBeLessThanOrEqual(CONFETTI_MAX)
    for (let i = 0; i < 3; i++) PRESETS.glass.outcome!(state, world, 'success', box, 'verify')
    expect(balloons().length).toBeGreaterThan(0)
    expect(balloons().length).toBeLessThanOrEqual(BALLOONS_MAX)
    expect(voices().filter(v => v !== 'volume')).toEqual(['success', 'popper', 'success', 'popper', 'success', 'triad', 'success', 'triad', 'success', 'triad'])
    expect(names.filter(n => n !== 'pointer')).toEqual(['ok', 'ok', 'ok', 'ok', 'ok'])
    idle('glass', state, world, 7)
    expect(state.p).toHaveLength(0)
  })

  it('warnings, errors and information each have their sound and status', () => {
    const { sound, voices } = argSound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.glass.init(world)
    for (const kind of ['warning', 'error', 'info'] as Outcome[]) PRESETS.glass.outcome!(state, world, kind, box)
    expect(voices()).toEqual(['caution', 'failure', 'notify'])
    expect(names).toEqual(['warn', 'fail'])
  })

  it('a press on a balloon pops it, and only it', () => {
    const { sound, voices } = argSound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.glass.init(world)
    PRESETS.glass.outcome!(state, world, 'success', null, 'verify')
    const count = state.p.length
    const b = state.p[0]
    world.pointer.control = 'button'
    PRESETS.glass.burst!(state, world, b.x, b.y)
    expect(state.p).toHaveLength(count - 1)
    expect(voices().slice(-1)).toEqual(['balloonpop'])
  })

  it('going forward or back slides the step; files in, out and saved each sound', () => {
    const { sound, voices } = argSound()
    const names: SignalName[] = []
    const world = { ...makeWorld(true, [], names), sound }
    const state = PRESETS.glass.init(world)
    for (const a of ['forward', 'back', 'file-in', 'file-out', 'saved'] as Activity[]) PRESETS.glass.activity!(state, world, a)
    expect(names).toEqual(['push', 'pop'])
    expect(voices()).toEqual(['sheet', 'sheet', 'airdrop', 'discard', 'sent'])
  })

  it('the system chrome sounds through the preset: lock, unlock, banners (not under Focus), switches and the camera', () => {
    const { sound, voices } = argSound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.glass.init(world)
    for (const e of ['lock', 'unlock', 'sheet-open', 'sheet-close', 'banner', 'long-press', 'switch', 'charge', 'battery'] as const) {
      PRESETS.glass.chrome!(state, world, e, {})
    }
    expect(voices()).toEqual(['lockclick', 'unlockchime', 'sheet', 'sheet', 'notify', 'haptic', 'switchtick', 'chargechime', 'lowbattery'])
    setIosPrefs({ focus: true, lockSound: false })
    PRESETS.glass.chrome!(state, world, 'banner', {})
    PRESETS.glass.chrome!(state, world, 'lock', {})
    expect(voices()).toHaveLength(9)
    PRESETS.glass.chrome!(state, world, 'camera', {})
    expect(voices().slice(-1)).toEqual(['shutter'])
    expect(state.flash).toBe(1)
  })

  it('a saved file flies to Files and lands', () => {
    const world = makeWorld(true)
    const state = PRESETS.glass.init(world)
    PRESETS.glass.chrome!(state, world, 'fly', { from: box, to: { left: 700, top: 820, right: 750, bottom: 870 } })
    expect(state.fly).toHaveLength(1)
    idle('glass', state, world, FLY_S + 0.1)
    expect(state.fly).toHaveLength(0)
    expect(state.bits.some(b => b.shape === 'ring')).toBe(true)
  })

  it('follows the volume setting, and the volume click plays at the new level', () => {
    const { sound, calls } = argSound()
    const world = { ...makeWorld(true), sound }
    const state = PRESETS.glass.init(world)
    PRESETS.glass.start!(state, world)
    PRESETS.glass.step(state, world)
    setIosPrefs({ volume: 0.3 })
    PRESETS.glass.step(state, world)
    PRESETS.glass.step(state, world)
    expect(calls.filter(c => c[0] === 'volume')).toEqual([['volume', 0.8], ['volume', 0.8], ['volume', 0.3]])
    setIosPrefs({ volume: 0.6 })
    PRESETS.glass.chrome!(state, world, 'volume', {})
    expect(calls.slice(-2)).toEqual([['volume', 0.6], ['keytap', 'modifier']])
  })
})

