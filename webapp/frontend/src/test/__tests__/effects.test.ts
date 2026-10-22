import { describe, it, expect } from 'vitest'
import type { EffectKind } from '../../design/designs'
import { MAX_BITS } from '../../design/effects/bits'
import { type Activity, type Control, type KeyKind, PRESETS, scaleCount, type SignalName, type State, type World } from '../../design/effects/presets'
import type { Outcome } from '../../design/signals'
import type { Sound } from '../../design/effects/sound'
import { controlKind, optionIn, optionIndex } from '../../design/effects/engine'
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
