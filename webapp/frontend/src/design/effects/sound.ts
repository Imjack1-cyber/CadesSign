/**
 * Small synthesized sounds for the theme effects: no files, just oscillators and filtered noise.
 * The AudioContext is created on the first key or pointer press (browsers only allow audio after a
 * gesture); until then every voice is silent. One master gain keeps everything quiet, and each voice
 * is rate-limited so fast typing or a held key cannot pile sounds up.
 */

export interface Sound {
  /** A typewriter key; pitch around 1 varies the key. */
  click(pitch?: number): void
  /** A rubber stamp or defibrillator paddles: a low body blow. */
  thud(): void
  /** The typewriter's end-of-line bell. */
  bell(): void
  /** A monitor beep, optionally delayed by `delay` seconds; 'square' sounds like a PC speaker. */
  beep(freq: number, ms: number, delay?: number, type?: OscillatorType): void
  /** A continuous alarm tone, held until turned off. */
  tone(on: boolean): void
  /** Correction tape or an eraser: a short rasp. */
  rasp(): void
  /** A sheet of paper sliding in. */
  whoosh(): void
  /** A hollow bamboo knock (shishi-odoshi). */
  knock(): void
  /** A pebble dropping into sand. */
  pebble(): void
  /** Three rising notes for a good result. */
  chime(): void
  /** A slow, swelling start-up pad; queued until audio unlocks, for up to STARTUP_WAIT_MS. */
  startup(): void
  /** A falling pad, for shutting down. */
  shutdown(): void
  /** A brass pickup into a held major chord. */
  tada(): void
  /** The critical-stop chord. */
  chord(): void
  /** The default beep. */
  ding(): void
  /** Two falling notes. */
  exclamation(): void
  /** A soft chime for information. */
  asterisk(): void
  /** A short blip for a menu opening or closing. */
  menu(): void
  /** A window shrinking into the taskbar: a falling sweep. */
  minimize(): void
  /** A window opening up: a rising sweep. */
  maximize(): void
  /** Paper crumpling into the Recycle Bin. */
  recycle(): void
  /** A springy two-note pop: the assistant has something to say. */
  pop(): void
  /** A hard disk seeking: a tick and a small thunk. */
  seek(): void
  /** A dial-up modem dialling and handshaking, until turned off. */
  modem(on: boolean): void
  /** A buckling-spring keyboard: a spring ping and the key bottoming out. */
  keyclack(kind?: 'char' | 'space' | 'enter' | 'delete'): void
  /** A CRT's mains hum and faint flyback whine, held until turned off. */
  hum(on: boolean): void
  /** A CRT switching on: relay, degauss and the rising whine; queued like startup(). */
  poweron(): void
  /** The degauss coil: a thump and a dying, wobbling buzz. */
  degauss(): void
  /** A CRT switching off: the whine falls away, a relay clicks and the picture's charge crackles. */
  poweroff(): void
  /** A button pressed: a crisp microswitch click with a faint speaker blip. */
  press(): void
  /** A ball mouse's roller ticking; `level` 0..1 follows the pointer speed. Barely audible. */
  tick(level?: number): void
  /** An option chosen: a quick rising pair of speaker chirps. */
  select(): void
  /** Going back: a falling pair, the reverse of advance(). */
  back(): void
  /** Moving on: a carriage return and three rising blips. */
  advance(): void
  /** Switching pages: a burst of static and a detent thunk, like turning a channel knob. */
  channel(): void
  /** A switch flipped: a relay clunk. */
  toggle(): void
  /** A text field takes the cursor: one soft high blip. */
  cursor(): void
  /** A disabled control pressed: a low refusing buzz. */
  deny(): void
  /** Data read in from disk or tape: a quick warble of tones over drive ticks. */
  load(): void
  /** Data written to disk: the drive whirrs and ticks. */
  write(): void
  /** Something deleted: a falling sweep of noise. */
  erase(): void
  /** A floppy disk sliding into the drive and latching: for opening a file. */
  insert(): void
  /** Browsing a list: a soft blip that climbs a pentatonic scale with the option's `index`. */
  option(index: number): void
  /** A dot-matrix printer running off a page: fast head ticks, then the carriage return. `lines` sets the length. */
  printout(lines?: number): void
  /** The paper advancing `lines` lines: soft low ticks one after another, for scrolling. */
  linefeed(lines?: number): void
  /** The deep sea's ambient bed: a slow, swelling rumble of water, held until turned off. */
  ocean(on: boolean): void
  /**
   * An air bubble: a short rising resonance; `pitch` around 1, higher for smaller bubbles, after
   * `delay` seconds. `pan` (-1 left to 1 right) places it, here and in sonar() and swish().
   */
  bubble(pitch?: number, delay?: number, pan?: number): void
  /** A sonar ping with its echo; `count` pings, a little apart. */
  sonar(count?: number, pan?: number): void
  /** A distant whale call: a slow falling glide that echoes. */
  whale(): void
  /** A ship's hull groaning under pressure; `deep` makes it lower and longer. */
  creak(deep?: boolean): void
  /** Water rushing past: a falling band of noise. */
  swish(pan?: number): void
  /** Sets the overall loudness, 0 to 1, on top of the quiet master level. */
  volume(level: number): void
  /** A touch-screen key: a woody tock for letters, a drier one for delete, a deeper one for space, return and tab. */
  keytap(kind?: 'char' | 'delete' | 'modifier'): void
  /** The side button locking the phone: a crisp click on a small clunk. */
  lockclick(): void
  /** Unlocking: a breath of air and two soft rising notes; queued like startup(). */
  unlockchime(): void
  /** A notification: two mallet notes a fourth apart. */
  notify(): void
  /** A message arriving: three rising mallet notes. */
  triad(): void
  /** A message sent: a rising swoosh. */
  sent(): void
  /** Done: two bells a fifth apart, struck a moment apart. */
  success(): void
  /** Failed: two falling mallet notes and three short haptic buzzes. */
  failure(): void
  /** A warning: a glassy ping and its softer echo. */
  caution(): void
  /** A switch flipping: a tiny tick on a felt thump. */
  switchtick(): void
  /** A picker wheel passing a detent; the pitch shifts a little with `index`. */
  pickertick(index?: number): void
  /** A tap on glass: a soft, high tink. */
  glasstap(): void
  /** A sheet sliding up (or down): a short breath of air. */
  sheet(up?: boolean): void
  /** A camera shutter: two mechanical clicks. */
  shutter(): void
  /** A charger connected: two quick bright notes. */
  chargechime(): void
  /** A file arriving: two rising boops and a shimmer. */
  airdrop(): void
  /** Something thrown away: a falling rush and a small thunk. */
  discard(): void
  /** A haptic tap: a low thump felt more than heard. */
  haptic(): void
  /** A party popper: a crack and a rising whistle. */
  popper(): void
  /** A balloon bursting. */
  balloonpop(): void
  /** The low battery warning: two soft falling tones. */
  lowbattery(): void
  /** A stadium crowd's murmur, held until turned off; queued until audio unlocks like ocean(). */
  crowd(on: boolean): void
  /** The crowd roaring: a swell of noise with whistles on top. */
  cheer(): void
  /** A rocket boost firing: a short roaring burst of noise. */
  boost(pan?: number): void
  /** A car striking the ball: a rubbery thump, harder and brighter as `power` (0 to 1) rises. */
  ballhit(power?: number, pan?: number): void
  /** The goal horn: a long, brassy blast. */
  horn(): void
  /** A demolition: a crack, a low boom and falling debris. */
  demo(pan?: number): void
  /** The ball off the crossbar: a metallic ring. */
  clang(): void
  /** A boost pad picked up: a quick rising zap. */
  pad(): void
  /** A car's engine humming at `level` 0 to 1, held until engine(0). */
  engine(level: number): void
  dispose(): void
}

const MASTER_GAIN = 0.15
/** Minimum seconds between two plays of the same voice. */
const MIN_GAP = 0.03
/** How long a start-up or power-on sound waits for the first gesture before it is dropped. */
const STARTUP_WAIT_MS = 5000
/** Touch-tone pairs (low, high Hz) for the digits the modem dials. */
/** Semitone steps of a major pentatonic scale, for browsing a list. */
const PENTATONIC = [0, 2, 4, 7, 9]
const DTMF: ReadonlyArray<[number, number]> = [[852, 1209], [697, 1336], [770, 1477], [941, 1336], [697, 1209], [852, 1477], [770, 1336]]

const silent: Sound = {
  click() {}, thud() {}, bell() {}, beep() {}, tone() {}, rasp() {}, whoosh() {}, knock() {}, pebble() {}, chime() {},
  startup() {}, shutdown() {}, tada() {}, chord() {}, ding() {}, exclamation() {}, asterisk() {}, menu() {}, minimize() {}, maximize() {}, recycle() {}, pop() {}, seek() {}, modem() {},
  keyclack() {}, hum() {}, poweron() {}, degauss() {}, poweroff() {}, press() {}, tick() {},
  select() {}, back() {}, advance() {}, channel() {}, toggle() {}, cursor() {}, deny() {}, load() {}, write() {}, erase() {},
  insert() {}, option() {}, printout() {}, linefeed() {},
  ocean() {}, bubble() {}, sonar() {}, whale() {}, creak() {}, swish() {},
  volume() {}, keytap() {}, lockclick() {}, unlockchime() {}, notify() {}, triad() {}, sent() {}, success() {}, failure() {},
  caution() {}, switchtick() {}, pickertick() {}, glasstap() {}, sheet() {}, shutter() {}, chargechime() {}, airdrop() {},
  discard() {}, haptic() {}, popper() {}, balloonpop() {}, lowbattery() {},
  crowd() {}, cheer() {}, boost() {}, ballhit() {}, horn() {}, demo() {}, clang() {}, pad() {}, engine() {},
  dispose() {},
}

export function createSound(): Sound {
  if (typeof window === 'undefined' || typeof window.AudioContext === 'undefined') return silent

  let ctx: AudioContext | null = null
  let master: GainNode | null = null
  let noise: AudioBuffer | null = null
  let alarm: { osc: OscillatorNode; gain: GainNode } | null = null
  let line: GainNode | null = null
  let mains: { gain: GainNode; oscs: OscillatorNode[] } | null = null
  let humWanted = false
  let water: { gain: GainNode; sources: AudioScheduledSourceNode[] } | null = null
  let oceanWanted = false
  let stands: { gain: GainNode; sources: AudioScheduledSourceNode[] } | null = null
  let crowdWanted = false
  let motor: { osc: OscillatorNode; gain: GainNode; filter: BiquadFilterNode } | null = null
  /** A feedback delay for sounds that should carry through water; built on first use. */
  let echo: DelayNode | null = null
  /** A start-up voice asked for before audio unlocked, and when. */
  let queued: { voice: 'startup' | 'poweron' | 'unlockchime'; at: number } | null = null
  let level = 1
  const lastPlay = new Map<string, number>()

  const unlock = () => {
    if (!ctx) {
      ctx = new AudioContext()
      master = ctx.createGain()
      master.gain.value = MASTER_GAIN * level
      master.connect(ctx.destination)
      noise = ctx.createBuffer(1, ctx.sampleRate, ctx.sampleRate)
      const data = noise.getChannelData(0)
      for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1
    }
    if (ctx.state === 'suspended') void ctx.resume().then(playQueued)
    else playQueued()
  }
  const playQueued = () => {
    if (humWanted) voices.hum(true)
    if (oceanWanted) voices.ocean(true)
    if (crowdWanted) voices.crowd(true)
    if (!queued) return
    const { voice, at } = queued
    queued = null
    if (performance.now() - at < STARTUP_WAIT_MS) voices[voice]()
  }
  window.addEventListener('pointerdown', unlock, true)
  window.addEventListener('keydown', unlock, true)

  /**
   * The context, if audio is unlocked and this voice is not already playing within `gap` seconds of
   * when it would start, `delay` seconds from now.
   */
  const ready = (voice: string, gap = MIN_GAP, delay = 0) => {
    if (!ctx || !master || ctx.state !== 'running') return null
    const at = ctx.currentTime + delay
    const last = lastPlay.get(voice) ?? -1
    if (Math.abs(at - last) < gap) return null
    lastPlay.set(voice, at)
    return ctx
  }

  /** Where a placed sound goes: through a stereo panner to the master, or straight there. */
  const panned = (c: AudioContext, pan?: number): AudioNode => {
    if (pan === undefined || !c.createStereoPanner) return master!
    const p = c.createStereoPanner()
    p.pan.value = Math.max(-1, Math.min(1, pan))
    p.connect(master!)
    return p
  }

  /** A gain envelope: fast attack to `peak`, exponential decay over `decay` seconds. */
  const envelope = (c: AudioContext, at: number, peak: number, decay: number, out: AudioNode = master!) => {
    const g = c.createGain()
    g.gain.setValueAtTime(0.0001, at)
    g.gain.exponentialRampToValueAtTime(peak, at + 0.004)
    g.gain.exponentialRampToValueAtTime(0.0001, at + decay)
    g.connect(out)
    return g
  }

  const burst = (
    c: AudioContext, at: number, filter: BiquadFilterType, freq: number, q: number, peak: number, decay: number, out?: AudioNode,
  ) => {
    const src = c.createBufferSource()
    src.buffer = noise
    src.playbackRate.value = 0.8 + Math.random() * 0.4
    const f = c.createBiquadFilter()
    f.type = filter
    f.frequency.value = freq
    f.Q.value = q
    src.connect(f).connect(envelope(c, at, peak, decay, out))
    src.start(at, Math.random() * 0.5, decay + 0.05)
    return f
  }

  const sine = (
    c: AudioContext, at: number, freq: number, peak: number, decay: number, type: OscillatorType = 'sine', endFreq?: number,
    out?: AudioNode,
  ) => {
    const osc = c.createOscillator()
    osc.type = type
    osc.frequency.setValueAtTime(freq, at)
    if (endFreq) osc.frequency.exponentialRampToValueAtTime(endFreq, at + decay)
    osc.connect(envelope(c, at, peak, decay, out))
    osc.start(at)
    osc.stop(at + decay + 0.05)
  }

  /**
   * A soft pad: detuned voices through a lowpass, swelling in over `attack`, holding, then fading over
   * `release`. `glide` bends every voice by that factor over the whole sound.
   */
  const pad = (c: AudioContext, at: number, freqs: number[], peak: number, attack: number, hold: number, release: number, glide = 1) => {
    const end = at + attack + hold + release
    const g = c.createGain()
    g.gain.setValueAtTime(0.0001, at)
    g.gain.exponentialRampToValueAtTime(peak, at + attack)
    g.gain.setValueAtTime(peak, at + attack + hold)
    g.gain.exponentialRampToValueAtTime(0.0001, end)
    const f = c.createBiquadFilter()
    f.type = 'lowpass'
    f.frequency.setValueAtTime(600, at)
    f.frequency.exponentialRampToValueAtTime(2400, at + attack)
    f.connect(g).connect(master!)
    for (const freq of freqs) {
      for (const detune of [-7, 7]) {
        const osc = c.createOscillator()
        osc.type = 'sawtooth'
        osc.detune.value = detune
        osc.frequency.setValueAtTime(freq, at)
        if (glide !== 1) osc.frequency.exponentialRampToValueAtTime(freq * glide, end)
        osc.connect(f)
        osc.start(at)
        osc.stop(end + 0.05)
      }
    }
  }

  /** A brassy note: a sawtooth whose lowpass opens on the attack, like a horn. */
  const brass = (c: AudioContext, at: number, freq: number, peak: number, dur: number) => {
    const osc = c.createOscillator()
    osc.type = 'sawtooth'
    osc.frequency.value = freq
    const f = c.createBiquadFilter()
    f.type = 'lowpass'
    f.Q.value = 2
    f.frequency.setValueAtTime(400, at)
    f.frequency.exponentialRampToValueAtTime(freq * 5, at + 0.05)
    f.frequency.exponentialRampToValueAtTime(freq * 2, at + dur)
    osc.connect(f).connect(envelope(c, at, peak, dur))
    osc.start(at)
    osc.stop(at + dur + 0.05)
  }

  /** The shared echo: about a third of a second, each repeat darker and quieter, mixed in under the dry sound. */
  const echoBus = (c: AudioContext) => {
    if (echo) return echo
    echo = c.createDelay(1)
    echo.delayTime.value = 0.34
    const tone = c.createBiquadFilter()
    tone.type = 'lowpass'
    tone.frequency.value = 1400
    const feedback = c.createGain()
    feedback.gain.value = 0.42
    const wet = c.createGain()
    wet.gain.value = 0.5
    echo.connect(tone).connect(feedback).connect(echo)
    tone.connect(wet).connect(master!)
    return echo
  }

  /** A tone of `ms` with flat sustain, routed into `out`; the modem builds its call from these. */
  const flat = (c: AudioContext, out: AudioNode, at: number, freq: number, ms: number, peak: number, type: OscillatorType = 'sine') => {
    const osc = c.createOscillator()
    osc.type = type
    osc.frequency.value = freq
    const g = c.createGain()
    g.gain.setValueAtTime(0.0001, at)
    g.gain.exponentialRampToValueAtTime(peak, at + 0.005)
    g.gain.setValueAtTime(peak, at + ms / 1000)
    g.gain.exponentialRampToValueAtTime(0.0001, at + ms / 1000 + 0.01)
    osc.connect(g).connect(out)
    osc.start(at)
    osc.stop(at + ms / 1000 + 0.03)
    return osc
  }

  /** Short square-wave notes one after another, like a PC speaker playing a tune. */
  const blips = (c: AudioContext, at: number, freqs: number[], ms: number, peak = 0.12) => {
    freqs.forEach((f, i) => flat(c, master!, at + (i * ms) / 1000, f, ms * 0.8, peak, 'square'))
  }

  /** A struck wooden bar: the fundamental, its tuned overtone two octaves up, and the mallet's click. */
  const marimba = (c: AudioContext, at: number, freq: number, peak: number, decay = 0.5) => {
    sine(c, at, freq, peak, decay)
    sine(c, at, freq * 4, peak * 0.22, decay * 0.18)
    burst(c, at, 'bandpass', Math.min(9000, freq * 6), 2, peak * 0.15, 0.008)
  }

  /** A small bell: three inharmonic partials dying away at different rates. */
  const bellAt = (c: AudioContext, at: number, freq: number, peak: number, decay = 1) => {
    sine(c, at, freq, peak, decay)
    sine(c, at, freq * 2.76, peak * 0.3, decay * 0.45)
    sine(c, at, freq * 5.4, peak * 0.12, decay * 0.2)
  }

  /** A band of noise sweeping from one frequency to another over `dur` seconds. */
  const sweep = (c: AudioContext, at: number, from: number, to: number, peak: number, dur: number, q = 1) => {
    const f = burst(c, at, 'bandpass', from, q, peak, dur)
    f.frequency.exponentialRampToValueAtTime(to, at + dur * 0.9)
    return f
  }

  const voices: Sound = {
    click(pitch = 1) {
      const c = ready('click')
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'bandpass', 2600 * pitch, 2.5, 0.9, 0.04)
      sine(c, at, 160 * pitch, 0.5, 0.05, 'triangle', 90)
    },
    thud() {
      const c = ready('thud', 0.15)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 110, 1, 0.22, 'sine', 40)
      burst(c, at, 'lowpass', 600, 0.7, 0.6, 0.12)
    },
    bell() {
      const c = ready('bell', 0.3)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 2093, 0.45, 1.4)
      sine(c, at, 2093 * 2.76, 0.18, 0.7)
      sine(c, at, 2093 * 5.4, 0.08, 0.35)
    },
    beep(freq, ms, delay = 0, type = 'sine') {
      const c = ready(`beep${delay}`, 0.05)
      if (!c) return
      const at = c.currentTime + delay
      const osc = c.createOscillator()
      osc.type = type
      osc.frequency.value = freq
      const g = c.createGain()
      g.gain.setValueAtTime(0.0001, at)
      g.gain.exponentialRampToValueAtTime(0.35, at + 0.006)
      g.gain.setValueAtTime(0.35, at + ms / 1000)
      g.gain.exponentialRampToValueAtTime(0.0001, at + ms / 1000 + 0.02)
      osc.connect(g).connect(master!)
      osc.start(at)
      osc.stop(at + ms / 1000 + 0.05)
    },
    tone(on) {
      if (!on) {
        if (alarm && ctx) {
          alarm.gain.gain.setTargetAtTime(0.0001, ctx.currentTime, 0.03)
          alarm.osc.stop(ctx.currentTime + 0.2)
        }
        alarm = null
        return
      }
      if (alarm || !ctx || !master || ctx.state !== 'running') return
      const osc = ctx.createOscillator()
      osc.frequency.value = 960
      const gain = ctx.createGain()
      gain.gain.setValueAtTime(0.0001, ctx.currentTime)
      gain.gain.setTargetAtTime(0.2, ctx.currentTime, 0.02)
      osc.connect(gain).connect(master)
      osc.start()
      alarm = { osc, gain }
    },
    rasp() {
      const c = ready('rasp', 0.06)
      if (!c) return
      const f = burst(c, c.currentTime, 'bandpass', 900, 1.2, 0.5, 0.11)
      f.frequency.exponentialRampToValueAtTime(2200, c.currentTime + 0.1)
    },
    whoosh() {
      const c = ready('whoosh', 0.2)
      if (!c) return
      const f = burst(c, c.currentTime, 'lowpass', 300, 0.5, 0.35, 0.28)
      f.frequency.exponentialRampToValueAtTime(2400, c.currentTime + 0.25)
    },
    knock() {
      const c = ready('knock', 0.2)
      if (!c) return
      const at = c.currentTime
      // The bamboo hits the stone: a hollow tube resonance plus the click of contact.
      sine(c, at, 420, 0.9, 0.18, 'sine', 380)
      sine(c, at, 1260, 0.25, 0.06)
      burst(c, at, 'bandpass', 1800, 4, 0.4, 0.03)
    },
    pebble() {
      const c = ready('pebble', 0.05)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'lowpass', 900 + Math.random() * 500, 0.8, 0.5, 0.07)
      sine(c, at, 240 + Math.random() * 80, 0.25, 0.05, 'triangle')
    },
    chime() {
      const c = ready('chime', 0.5)
      if (!c) return
      const at = c.currentTime
      ;[880, 1108.7, 1318.5].forEach((f, i) => sine(c, at + i * 0.12, f, 0.35, 0.9))
    },
    startup() {
      const c = ready('startup', 5)
      if (!c) {
        queued = { voice: 'startup', at: performance.now() }
        return
      }
      const at = c.currentTime
      // A swelling Eb major add9 pad, with a slow bright arpeggio sparkling over it.
      pad(c, at, [155.6, 233.1, 311.1, 392, 466.2], 0.12, 1.4, 1.2, 1.6)
      ;[622.3, 932.3, 1244.5, 1568, 1864.7, 2489].forEach((f, i) => sine(c, at + 0.5 + i * 0.28, f, 0.12, 1.4))
      sine(c, at + 2.3, 77.8, 0.35, 2.2)
    },
    shutdown() {
      const c = ready('shutdown', 2)
      if (!c) return
      const at = c.currentTime
      pad(c, at, [392, 466.2, 587.3, 784], 0.1, 0.2, 0.6, 1.4, 0.5)
      ;[1568, 1174.7, 932.3, 784].forEach((f, i) => sine(c, at + i * 0.22, f, 0.12, 0.9))
    },
    tada() {
      const c = ready('tada', 1)
      if (!c) return
      const at = c.currentTime
      brass(c, at, 392, 0.3, 0.12)
      brass(c, at + 0.13, 523.3, 0.3, 0.12)
      for (const f of [261.6, 523.3, 659.3, 784]) brass(c, at + 0.28, f, 0.22, 1.3)
      sine(c, at + 0.28, 1046.5, 0.12, 1.2)
    },
    chord() {
      const c = ready('chord', 0.4)
      if (!c) return
      const at = c.currentTime
      // A firm piano-like chord, struck slightly unevenly.
      ;[220, 277.2, 329.6, 440, 554.4].forEach((f, i) => {
        sine(c, at + i * 0.008, f, 0.3, 1.1, 'triangle')
        sine(c, at + i * 0.008, f * 2, 0.08, 0.4)
      })
      burst(c, at, 'lowpass', 1200, 0.7, 0.3, 0.05)
    },
    ding() {
      const c = ready('ding', 0.12)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 1046.5, 0.4, 0.7)
      sine(c, at, 1046.5 * 2.4, 0.12, 0.3)
      sine(c, at, 523.3, 0.15, 0.4, 'triangle')
    },
    exclamation() {
      const c = ready('exclamation', 0.4)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 987.8, 0.35, 0.35, 'triangle')
      sine(c, at + 0.14, 740, 0.35, 0.6, 'triangle')
    },
    asterisk() {
      const c = ready('asterisk', 0.4)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 1318.5, 0.25, 1)
      sine(c, at + 0.06, 1975.5, 0.12, 0.8)
    },
    menu() {
      const c = ready('menu', 0.06)
      if (!c) return
      sine(c, c.currentTime, 1500, 0.18, 0.05, 'sine', 1900)
    },
    minimize() {
      const c = ready('minimize', 0.1)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 1400, 0.16, 0.16, 'triangle', 500)
      const f = burst(c, at, 'bandpass', 2400, 1.5, 0.12, 0.16)
      f.frequency.exponentialRampToValueAtTime(600, at + 0.15)
    },
    maximize() {
      const c = ready('maximize', 0.1)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 500, 0.16, 0.16, 'triangle', 1400)
      const f = burst(c, at, 'bandpass', 600, 1.5, 0.12, 0.16)
      f.frequency.exponentialRampToValueAtTime(2400, at + 0.15)
    },
    recycle() {
      const c = ready('recycle', 0.3)
      if (!c) return
      const at = c.currentTime
      // A handful of uneven paper crackles, then the lid.
      for (let i = 0; i < 7; i++) {
        burst(c, at + i * 0.035 + Math.random() * 0.02, 'highpass', 1500 + Math.random() * 2500, 0.8, 0.4, 0.03)
      }
      sine(c, at + 0.3, 180, 0.3, 0.08, 'triangle', 120)
    },
    pop() {
      const c = ready('pop', 0.3)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 660, 0.25, 0.12, 'sine', 990)
      sine(c, at + 0.09, 1320, 0.2, 0.25, 'triangle', 1180)
    },
    seek() {
      const c = ready('seek', 0.08)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'bandpass', 2400 + Math.random() * 1600, 3, 0.35, 0.02)
      sine(c, at, 70 + Math.random() * 30, 0.4, 0.05)
    },
    modem(on) {
      if (!on) {
        if (line && ctx) {
          line.gain.setTargetAtTime(0.0001, ctx.currentTime, 0.02)
          const old = line
          window.setTimeout(() => old.disconnect(), 200)
        }
        line = null
        return
      }
      if (line) return
      const c = ready('modem', 1)
      if (!c) return
      line = c.createGain()
      line.gain.value = 0.6
      line.connect(master!)
      const out = line
      let at = c.currentTime + 0.05
      // Dial tone, then touch-tone digits.
      flat(c, out, at, 350, 450, 0.18)
      flat(c, out, at, 440, 450, 0.18)
      at += 0.55
      for (const [lo, hi] of DTMF) {
        flat(c, out, at, lo, 70, 0.2)
        flat(c, out, at, hi, 70, 0.2)
        at += 0.12
      }
      // The far end answers, then both sides chirp and hiss while they agree on a speed.
      at += 0.2
      flat(c, out, at, 2100, 600, 0.16)
      at += 0.65
      for (let i = 0; i < 10; i++) {
        flat(c, out, at, i % 2 ? 2400 : 1200, 60, 0.1, 'square')
        flat(c, out, at + 0.07, 980 + i * 60, 50, 0.08)
        at += 0.13
      }
      const hiss = c.createBufferSource()
      hiss.buffer = noise
      hiss.loop = true
      const f = c.createBiquadFilter()
      f.type = 'bandpass'
      f.frequency.value = 1800
      f.Q.value = 0.6
      const g = c.createGain()
      g.gain.setValueAtTime(0.0001, at)
      g.gain.exponentialRampToValueAtTime(0.25, at + 0.05)
      g.gain.setValueAtTime(0.25, at + 1.2)
      g.gain.exponentialRampToValueAtTime(0.0001, at + 1.4)
      hiss.connect(f).connect(g).connect(out)
      hiss.start(at)
      hiss.stop(at + 1.5)
    },
    keyclack(kind = 'char') {
      const c = ready('keyclack')
      if (!c) return
      const at = c.currentTime
      const big = kind === 'space' || kind === 'enter'
      // The buckling spring snaps with a metallic ping, then the keycap bottoms out on the plate.
      burst(c, at, 'bandpass', (big ? 2800 : 3600) + Math.random() * 600, 6, 0.7, 0.015)
      sine(c, at + 0.004, 2900 + Math.random() * 400, 0.08, 0.06)
      sine(c, at + 0.012, big ? 95 : 130 + Math.random() * 30, big ? 0.7 : 0.5, big ? 0.09 : 0.06, 'triangle', 70)
      burst(c, at + 0.012, 'lowpass', big ? 900 : 1400, 0.7, big ? 0.6 : 0.4, 0.035)
      // Enter comes back up with a second clack.
      if (kind === 'enter') burst(c, at + 0.09, 'bandpass', 3000, 5, 0.4, 0.015)
      if (kind === 'delete') sine(c, at + 0.012, 180, 0.15, 0.04, 'square')
    },
    hum(on) {
      humWanted = on
      if (!on) {
        if (mains && ctx) {
          mains.gain.gain.setTargetAtTime(0.0001, ctx.currentTime, 0.1)
          for (const osc of mains.oscs) osc.stop(ctx.currentTime + 0.6)
        }
        mains = null
        return
      }
      if (mains || !ctx || !master || ctx.state !== 'running') return
      const gain = ctx.createGain()
      gain.gain.setValueAtTime(0.0001, ctx.currentTime)
      gain.gain.setTargetAtTime(1, ctx.currentTime, 0.8)
      gain.connect(master)
      // Mains hum and its first harmonic, and the 15.7 kHz line-scan whine barely above silence.
      const oscs = ([[60, 0.05, 'sine'], [120, 0.03, 'triangle'], [15734, 0.004, 'sine']] as const).map(([freq, level, type]) => {
        const osc = ctx!.createOscillator()
        osc.type = type
        osc.frequency.value = freq
        const g = ctx!.createGain()
        g.gain.value = level
        osc.connect(g).connect(gain)
        osc.start()
        return osc
      })
      mains = { gain, oscs }
    },
    poweron() {
      const c = ready('poweron', 2)
      if (!c) {
        queued = { voice: 'poweron', at: performance.now() }
        return
      }
      const at = c.currentTime
      // The power relay clunks, the degauss coil thrums, then the flyback whine climbs into place.
      burst(c, at, 'bandpass', 2200, 3, 0.6, 0.02)
      sine(c, at, 90, 0.6, 0.15, 'sine', 50)
      voices.degauss()
      sine(c, at + 0.4, 6000, 0.03, 1.2, 'sine', 15734)
    },
    poweroff() {
      const c = ready('poweroff', 1)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 15734, 0.03, 0.9, 'sine', 3000)
      burst(c, at, 'bandpass', 2000, 3, 0.5, 0.02)
      sine(c, at, 80, 0.5, 0.2, 'sine', 40)
      for (let i = 0; i < 5; i++) burst(c, at + 0.1 + Math.random() * 0.5, 'highpass', 5000, 1, 0.15, 0.01)
    },
    degauss() {
      const c = ready('degauss', 1)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 70, 0.8, 0.3, 'sine', 45)
      const osc = c.createOscillator()
      osc.type = 'sawtooth'
      osc.frequency.setValueAtTime(60, at)
      const wobble = c.createOscillator()
      wobble.frequency.value = 7
      const depth = c.createGain()
      depth.gain.value = 6
      wobble.connect(depth).connect(osc.frequency)
      const f = c.createBiquadFilter()
      f.type = 'lowpass'
      f.frequency.setValueAtTime(900, at)
      f.frequency.exponentialRampToValueAtTime(200, at + 0.9)
      osc.connect(f).connect(envelope(c, at, 0.35, 0.95))
      osc.start(at)
      wobble.start(at)
      osc.stop(at + 1)
      wobble.stop(at + 1)
    },
    press() {
      const c = ready('press', 0.05)
      if (!c) return
      const at = c.currentTime
      // The switch snaps down and back: two tight clicks, and the speaker answers with a blip.
      burst(c, at, 'highpass', 3800, 1, 0.55, 0.01)
      burst(c, at + 0.045, 'highpass', 4600, 1, 0.3, 0.008)
      sine(c, at, 1700, 0.12, 0.02, 'triangle')
      sine(c, at + 0.01, 1000, 0.06, 0.025, 'square')
    },
    tick(level = 0.5) {
      const c = ready('tick')
      if (!c) return
      burst(c, c.currentTime, 'bandpass', 4500 + Math.random() * 2500, 8, 0.04 + 0.08 * level, 0.006)
    },
    select() {
      const c = ready('select', 0.06)
      if (!c) return
      blips(c, c.currentTime, [988, 1480], 35)
    },
    back() {
      const c = ready('back', 0.15)
      if (!c) return
      const at = c.currentTime
      blips(c, at, [1480, 988, 659], 45, 0.1)
      sine(c, at, 900, 0.08, 0.15, 'triangle', 300)
    },
    advance() {
      const c = ready('advance', 0.15)
      if (!c) return
      const at = c.currentTime
      voices.keyclack('enter')
      blips(c, at + 0.06, [659, 880, 1319], 35, 0.1)
    },
    channel() {
      const c = ready('channel', 0.2)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'bandpass', 3000, 0.4, 0.3, 0.14)
      burst(c, at + 0.14, 'lowpass', 500, 0.7, 0.5, 0.04)
      sine(c, at + 0.14, 140, 0.35, 0.06, 'triangle', 90)
    },
    toggle() {
      const c = ready('toggle', 0.06)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'bandpass', 1600, 2, 0.6, 0.02)
      sine(c, at + 0.005, 220, 0.3, 0.05, 'square', 160)
    },
    cursor() {
      const c = ready('cursor', 0.1)
      if (!c) return
      sine(c, c.currentTime, 2400, 0.08, 0.04)
    },
    deny() {
      const c = ready('deny', 0.2)
      if (!c) return
      const at = c.currentTime
      flat(c, master!, at, 98, 140, 0.18, 'square')
      flat(c, master!, at, 104, 140, 0.12, 'square')
    },
    load() {
      const c = ready('load', 0.5)
      if (!c) return
      const at = c.currentTime
      for (let i = 0; i < 10; i++) {
        flat(c, master!, at + i * 0.04, 800 + Math.random() * 1800, 28, 0.06, 'square')
        if (i % 3 === 0) burst(c, at + i * 0.04, 'bandpass', 2600, 3, 0.3, 0.02)
      }
      blips(c, at + 0.45, [1319, 1760], 40, 0.08)
    },
    write() {
      const c = ready('write', 0.5)
      if (!c) return
      const at = c.currentTime
      // The motor spins up and back down while the head ticks along the tracks.
      const osc = c.createOscillator()
      osc.type = 'sawtooth'
      osc.frequency.setValueAtTime(60, at)
      osc.frequency.exponentialRampToValueAtTime(110, at + 0.25)
      osc.frequency.exponentialRampToValueAtTime(70, at + 0.6)
      const f = c.createBiquadFilter()
      f.type = 'lowpass'
      f.frequency.value = 400
      osc.connect(f).connect(envelope(c, at, 0.18, 0.65))
      osc.start(at)
      osc.stop(at + 0.7)
      for (let i = 0; i < 6; i++) burst(c, at + 0.08 + i * 0.08 + Math.random() * 0.02, 'bandpass', 2200 + Math.random() * 1200, 3, 0.3, 0.02)
    },
    erase() {
      const c = ready('erase', 0.15)
      if (!c) return
      const at = c.currentTime
      const f = burst(c, at, 'bandpass', 4000, 1.5, 0.35, 0.22)
      f.frequency.exponentialRampToValueAtTime(400, at + 0.2)
      sine(c, at + 0.18, 300, 0.12, 0.06, 'square', 150)
    },
    insert() {
      const c = ready('insert', 0.3)
      if (!c) return
      const at = c.currentTime
      // The disk slides along the guides, the shutter clacks and the drive clamps it with a thunk.
      const f = burst(c, at, 'bandpass', 1200, 1.2, 0.25, 0.14)
      f.frequency.exponentialRampToValueAtTime(2400, at + 0.12)
      burst(c, at + 0.14, 'highpass', 3500, 1, 0.5, 0.012)
      sine(c, at + 0.17, 120, 0.4, 0.07, 'triangle', 80)
    },
    printout(lines = 6) {
      const c = ready('printout', 0.3)
      if (!c) return
      const at = c.currentTime
      // Each line: the head buzzes across in short bursts of needle strikes, then the paper feeds.
      const lineS = 0.11
      for (let l = 0; l < lines; l++) {
        const start = at + l * lineS
        for (let i = 0; i < 9; i++) {
          if (Math.random() < 0.25) continue
          burst(c, start + i * 0.009, 'bandpass', 2800 + Math.random() * 1400, 4, 0.22, 0.006)
        }
        sine(c, start + 0.085, 90, 0.12, 0.03, 'triangle')
      }
      // The carriage swings back with a clunk.
      const end = at + lines * lineS
      const f = burst(c, end, 'bandpass', 600, 1.2, 0.25, 0.12)
      f.frequency.exponentialRampToValueAtTime(1600, end + 0.1)
      sine(c, end + 0.12, 110, 0.3, 0.06, 'triangle', 70)
    },
    linefeed(lines = 1) {
      const c = ready('linefeed', 0.05)
      if (!c) return
      for (let i = 0; i < lines; i++) {
        const at = c.currentTime + i * 0.035
        burst(c, at, 'lowpass', 700, 0.8, 0.18, 0.025)
        sine(c, at, 85, 0.1, 0.03, 'triangle')
      }
    },
    option(index) {
      const c = ready('option', 0.04)
      if (!c) return
      const step = PENTATONIC[index % PENTATONIC.length] + 12 * Math.floor(index / PENTATONIC.length)
      flat(c, master!, c.currentTime, 784 * 2 ** (step / 12), 22, 0.06, 'square')
    },
    ocean(on) {
      oceanWanted = on
      if (!on) {
        if (water && ctx) {
          water.gain.gain.setTargetAtTime(0.0001, ctx.currentTime, 0.4)
          for (const src of water.sources) src.stop(ctx.currentTime + 2)
        }
        water = null
        return
      }
      if (water || !ctx || !master || !noise || ctx.state !== 'running') return
      const now = ctx.currentTime
      const gain = ctx.createGain()
      gain.gain.setValueAtTime(0.0001, now)
      gain.gain.setTargetAtTime(1, now, 1.5)
      gain.connect(master)
      // Water: looped noise far down a lowpass, swelling slowly like a current moving past.
      const rush = ctx.createBufferSource()
      rush.buffer = noise
      rush.loop = true
      const low = ctx.createBiquadFilter()
      low.type = 'lowpass'
      low.frequency.value = 260
      low.Q.value = 0.5
      const swell = ctx.createGain()
      swell.gain.value = 0.22
      const lfo = ctx.createOscillator()
      lfo.frequency.value = 0.07
      const depth = ctx.createGain()
      depth.gain.value = 0.14
      lfo.connect(depth).connect(swell.gain)
      rush.connect(low).connect(swell).connect(gain)
      // And a rumble below it, felt more than heard.
      const rumble = ctx.createOscillator()
      rumble.frequency.value = 40
      const rumbleGain = ctx.createGain()
      rumbleGain.gain.value = 0.05
      rumble.connect(rumbleGain).connect(gain)
      rush.start()
      lfo.start()
      rumble.start()
      water = { gain, sources: [rush, lfo, rumble] }
    },
    bubble(pitch = 1, delay = 0, pan) {
      const c = ready('bubble', 0.04, delay)
      if (!c) return
      const at = c.currentTime + delay
      const out = panned(c, pan)
      // A bubble's resonance climbs as it leaves the water; a tiny click where it breaks free.
      const f = (380 + Math.random() * 160) * pitch
      sine(c, at, f, 0.32, 0.07, 'sine', f * 3.4, out)
      burst(c, at, 'bandpass', 2400, 3, 0.05, 0.01, out)
    },
    sonar(count = 1, pan) {
      const c = ready('sonar', 0.3)
      if (!c) return
      const out = echoBus(c)
      const dry = panned(c, pan)
      for (let i = 0; i < count; i++) {
        const at = c.currentTime + i * 0.4
        // A clean ping with a long tail, sent into the echo as well.
        const osc = c.createOscillator()
        osc.frequency.setValueAtTime(1120, at)
        osc.frequency.exponentialRampToValueAtTime(1080, at + 1.2)
        const g = envelope(c, at, 0.28, 1.2, dry)
        g.connect(out)
        osc.connect(g)
        osc.start(at)
        osc.stop(at + 1.25)
      }
    },
    whale() {
      const c = ready('whale', 2)
      if (!c) return
      const at = c.currentTime
      const dur = 1.8
      const out = echoBus(c)
      // A slow falling moan with a vibrato that widens as it goes, through a soft lowpass.
      const osc = c.createOscillator()
      osc.type = 'triangle'
      osc.frequency.setValueAtTime(190, at)
      osc.frequency.exponentialRampToValueAtTime(260, at + 0.5)
      osc.frequency.exponentialRampToValueAtTime(95, at + dur)
      const vib = c.createOscillator()
      vib.frequency.value = 5
      const vibDepth = c.createGain()
      vibDepth.gain.setValueAtTime(2, at)
      vibDepth.gain.linearRampToValueAtTime(12, at + dur)
      vib.connect(vibDepth).connect(osc.frequency)
      const f = c.createBiquadFilter()
      f.type = 'lowpass'
      f.frequency.value = 700
      const g = c.createGain()
      g.gain.setValueAtTime(0.0001, at)
      g.gain.exponentialRampToValueAtTime(0.35, at + 0.4)
      g.gain.setValueAtTime(0.35, at + dur - 0.5)
      g.gain.exponentialRampToValueAtTime(0.0001, at + dur)
      osc.connect(f).connect(g)
      g.connect(master!)
      g.connect(out)
      osc.start(at)
      vib.start(at)
      osc.stop(at + dur + 0.05)
      vib.stop(at + dur + 0.05)
    },
    creak(deep = false) {
      const c = ready('creak', 0.5)
      if (!c) return
      const at = c.currentTime
      const dur = deep ? 1.3 : 0.8
      // Steel groaning: a sawtooth that sticks and slips in small pitch steps, through a narrow band.
      const osc = c.createOscillator()
      osc.type = 'sawtooth'
      let freq = deep ? 62 : 110
      osc.frequency.setValueAtTime(freq, at)
      for (let t = 0.08; t < dur; t += 0.06 + Math.random() * 0.08) {
        freq *= 0.93 + Math.random() * 0.12
        osc.frequency.setValueAtTime(freq, at + t)
      }
      const f = c.createBiquadFilter()
      f.type = 'bandpass'
      f.frequency.value = deep ? 220 : 380
      f.Q.value = 4
      const g = c.createGain()
      g.gain.setValueAtTime(0.0001, at)
      g.gain.exponentialRampToValueAtTime(0.5, at + 0.15)
      g.gain.exponentialRampToValueAtTime(0.0001, at + dur)
      osc.connect(f).connect(g).connect(master!)
      osc.start(at)
      osc.stop(at + dur + 0.05)
      if (deep) sine(c, at, 70, 0.5, 0.4, 'sine', 40)
    },
    swish(pan) {
      const c = ready('swish', 0.25)
      if (!c) return
      const at = c.currentTime
      const f = burst(c, at, 'bandpass', 900, 1.4, 0.22, 0.35, panned(c, pan))
      f.frequency.exponentialRampToValueAtTime(250, at + 0.3)
    },
    volume(v) {
      level = Math.max(0, Math.min(1, v))
      if (master && ctx) master.gain.setTargetAtTime(MASTER_GAIN * level, ctx.currentTime, 0.02)
    },
    keytap(kind = 'char') {
      const c = ready('keytap', 0.02)
      if (!c) return
      const at = c.currentTime
      // The glass is struck rather than a key pressed: a short resonant tock, pitched by the key.
      const [freq, body] = kind === 'modifier' ? [760, 210] : kind === 'delete' ? [1120, 320] : [1500 + Math.random() * 160, 430]
      burst(c, at, 'bandpass', freq, kind === 'modifier' ? 4 : 6, 0.6, kind === 'modifier' ? 0.03 : 0.018)
      sine(c, at, body, kind === 'modifier' ? 0.35 : 0.25, kind === 'modifier' ? 0.045 : 0.025, 'triangle', body * 0.72)
    },
    lockclick() {
      const c = ready('lockclick', 0.2)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'highpass', 2600, 1, 0.7, 0.006)
      burst(c, at + 0.012, 'bandpass', 900, 2, 0.5, 0.03)
      sine(c, at + 0.01, 120, 0.5, 0.06, 'sine', 70)
    },
    unlockchime() {
      const c = ready('unlockchime', 1)
      if (!c) {
        queued = { voice: 'unlockchime', at: performance.now() }
        return
      }
      const at = c.currentTime
      const f = burst(c, at, 'lowpass', 400, 0.6, 0.14, 0.3)
      f.frequency.exponentialRampToValueAtTime(3200, at + 0.25)
      sine(c, at + 0.12, 1318.5, 0.12, 0.6)
      sine(c, at + 0.2, 1760, 0.1, 0.7)
    },
    notify() {
      const c = ready('notify', 0.4)
      if (!c) return
      const at = c.currentTime
      marimba(c, at, 880, 0.32)
      marimba(c, at + 0.12, 1174.7, 0.3, 0.7)
    },
    triad() {
      const c = ready('triad', 0.5)
      if (!c) return
      const at = c.currentTime
      ;[1046.5, 1318.5, 1760].forEach((f, i) => marimba(c, at + i * 0.1, f, 0.28, i === 2 ? 0.8 : 0.45))
    },
    sent() {
      const c = ready('sent', 0.3)
      if (!c) return
      const at = c.currentTime
      sweep(c, at, 500, 3500, 0.32, 0.3, 1.2)
      burst(c, at + 0.22, 'lowpass', 1800, 0.7, 0.08, 0.15)
    },
    success() {
      const c = ready('success', 0.6)
      if (!c) return
      const at = c.currentTime
      bellAt(c, at, 1046.5, 0.22, 1.1)
      bellAt(c, at + 0.07, 1568, 0.2, 1.3)
      burst(c, at + 0.07, 'highpass', 7000, 0.7, 0.04, 0.3)
    },
    failure() {
      const c = ready('failure', 0.5)
      if (!c) return
      const at = c.currentTime
      marimba(c, at, 659.3, 0.3, 0.35)
      marimba(c, at + 0.13, 493.9, 0.3, 0.5)
      // The phone buzzes three times in the hand.
      for (let i = 0; i < 3; i++) sine(c, at + 0.32 + i * 0.08, 150, 0.22, 0.05, 'square', 120)
    },
    caution() {
      const c = ready('caution', 0.5)
      if (!c) return
      const at = c.currentTime
      bellAt(c, at, 1975.5, 0.18, 0.5)
      bellAt(c, at + 0.18, 1975.5, 0.08, 0.45)
    },
    switchtick() {
      const c = ready('switchtick', 0.04)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'highpass', 5000, 1, 0.35, 0.004)
      sine(c, at, 70, 0.35, 0.03)
    },
    pickertick(index = 0) {
      const c = ready('pickertick', 0.025)
      if (!c) return
      burst(c, c.currentTime, 'bandpass', 3000 + (index % 12) * 60, 8, 0.3, 0.005)
    },
    glasstap() {
      const c = ready('glasstap', 0.04)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 2600, 0.07, 0.06, 'sine', 2480)
      burst(c, at, 'lowpass', 1200, 0.7, 0.15, 0.015)
    },
    sheet(up = true) {
      const c = ready('sheet', 0.12)
      if (!c) return
      const at = c.currentTime
      const f = burst(c, at, 'lowpass', up ? 300 : 1800, 0.6, 0.16, 0.22)
      f.frequency.exponentialRampToValueAtTime(up ? 1800 : 300, at + 0.2)
    },
    shutter() {
      const c = ready('shutter', 0.3)
      if (!c) return
      const at = c.currentTime
      for (const t of [0, 0.07]) {
        burst(c, at + t, 'highpass', 3000, 1, 0.6, 0.015)
        burst(c, at + t + 0.004, 'bandpass', 1200, 1.5, 0.4, 0.04)
      }
      for (let i = 0; i < 4; i++) burst(c, at + 0.02 + i * 0.012, 'bandpass', 4200, 4, 0.12, 0.006)
    },
    chargechime() {
      const c = ready('chargechime', 1)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 1318.5, 0.18, 0.35)
      sine(c, at + 0.07, 1975.5, 0.18, 0.5)
    },
    airdrop() {
      const c = ready('airdrop', 0.4)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 520, 0.2, 0.12, 'sine', 780)
      sine(c, at + 0.11, 780, 0.2, 0.18, 'sine', 1170)
      burst(c, at + 0.11, 'highpass', 6000, 0.7, 0.05, 0.2)
    },
    discard() {
      const c = ready('discard', 0.2)
      if (!c) return
      const at = c.currentTime
      sweep(c, at, 2500, 300, 0.3, 0.3, 1.5)
      sine(c, at + 0.22, 140, 0.3, 0.06, 'triangle', 90)
    },
    haptic() {
      const c = ready('haptic', 0.05)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 55, 0.6, 0.03)
      sine(c, at, 110, 0.2, 0.02)
    },
    popper() {
      const c = ready('popper', 0.3)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'highpass', 1800, 0.7, 0.8, 0.03)
      sine(c, at + 0.02, 900, 0.12, 0.35, 'sine', 2400)
    },
    balloonpop() {
      const c = ready('balloonpop', 0.05)
      if (!c) return
      const at = c.currentTime
      burst(c, at, 'bandpass', 1500, 0.5, 0.9, 0.04)
      sine(c, at, 160, 0.5, 0.08, 'sine', 60)
    },
    lowbattery() {
      const c = ready('lowbattery', 1)
      if (!c) return
      const at = c.currentTime
      sine(c, at, 880, 0.2, 0.25)
      sine(c, at + 0.2, 659.3, 0.2, 0.35)
    },
    crowd(on) {
      crowdWanted = on
      if (!on) {
        if (stands && ctx) {
          stands.gain.gain.setTargetAtTime(0.0001, ctx.currentTime, 0.4)
          for (const src of stands.sources) src.stop(ctx.currentTime + 2)
        }
        stands = null
        return
      }
      if (stands || !ctx || !master || !noise || ctx.state !== 'running') return
      const now = ctx.currentTime
      const gain = ctx.createGain()
      gain.gain.setValueAtTime(0.0001, now)
      gain.gain.setTargetAtTime(1, now, 1.5)
      gain.connect(master)
      // Thousands of voices: looped noise through a vowel-like band, swelling and ebbing slowly.
      const murmur = ctx.createBufferSource()
      murmur.buffer = noise
      murmur.loop = true
      const band = ctx.createBiquadFilter()
      band.type = 'bandpass'
      band.frequency.value = 650
      band.Q.value = 0.8
      const swell = ctx.createGain()
      swell.gain.value = 0.12
      const lfo = ctx.createOscillator()
      lfo.frequency.value = 0.11
      const depth = ctx.createGain()
      depth.gain.value = 0.06
      lfo.connect(depth).connect(swell.gain)
      murmur.connect(band).connect(swell).connect(gain)
      murmur.start()
      lfo.start()
      stands = { gain, sources: [murmur, lfo] }
    },
    cheer() {
      const c = ready('cheer', 1.5)
      if (!c) return
      const at = c.currentTime
      const f = burst(c, at, 'bandpass', 700, 0.6, 0.5, 2.2)
      f.frequency.linearRampToValueAtTime(1100, at + 0.5)
      for (let i = 0; i < 3; i++) {
        const w = at + 0.2 + i * 0.35 + Math.random() * 0.2
        sine(c, w, 2200 + Math.random() * 600, 0.05, 0.3, 'sine', 3000 + Math.random() * 400)
      }
    },
    boost(pan) {
      const c = ready('boost', 0.12)
      if (!c) return
      const at = c.currentTime
      const out = panned(c, pan)
      const f = burst(c, at, 'lowpass', 500, 1.2, 0.45, 0.4, out)
      f.frequency.exponentialRampToValueAtTime(2200, at + 0.1)
      sine(c, at, 70, 0.3, 0.3, 'sawtooth', 50, out)
    },
    ballhit(power = 0.5, pan) {
      const c = ready('ballhit', 0.05)
      if (!c) return
      const at = c.currentTime
      const p = Math.max(0, Math.min(1, power))
      const out = panned(c, pan)
      sine(c, at, 120 + 120 * p, 0.35 + 0.4 * p, 0.12 + 0.1 * p, 'sine', 60, out)
      burst(c, at, 'bandpass', 900 + 1800 * p, 1.5, 0.3 + 0.4 * p, 0.05, out)
    },
    horn() {
      const c = ready('horn', 2)
      if (!c) return
      const at = c.currentTime
      for (const freq of [116.5, 174.6, 233.1]) brass(c, at, freq, 0.22, 1.6)
      sine(c, at, 58, 0.3, 1.6, 'sawtooth')
    },
    demo(pan) {
      const c = ready('demo', 0.3)
      if (!c) return
      const at = c.currentTime
      const out = panned(c, pan)
      burst(c, at, 'highpass', 1500, 0.7, 0.9, 0.05, out)
      sine(c, at, 90, 0.8, 0.7, 'sine', 30, out)
      burst(c, at, 'lowpass', 400, 0.7, 0.7, 0.9, out)
      for (let i = 0; i < 5; i++) burst(c, at + 0.25 + i * 0.09 + Math.random() * 0.05, 'bandpass', 2500 + Math.random() * 2000, 4, 0.12, 0.03, out)
    },
    clang() {
      const c = ready('clang', 0.3)
      if (!c) return
      bellAt(c, c.currentTime, 620, 0.3, 1.1)
      bellAt(c, c.currentTime, 913, 0.15, 0.8)
    },
    pad() {
      const c = ready('pad', 0.08)
      if (!c) return
      sine(c, c.currentTime, 600, 0.18, 0.15, 'square', 1800)
    },
    engine(level) {
      const v = Math.max(0, Math.min(1, level))
      if (!v) {
        if (motor && ctx) {
          motor.gain.gain.setTargetAtTime(0.0001, ctx.currentTime, 0.05)
          motor.osc.stop(ctx.currentTime + 0.3)
        }
        motor = null
        return
      }
      if (!ctx || !master || ctx.state !== 'running') return
      if (!motor) {
        const osc = ctx.createOscillator()
        osc.type = 'sawtooth'
        const filter = ctx.createBiquadFilter()
        filter.type = 'lowpass'
        const gain = ctx.createGain()
        gain.gain.value = 0.0001
        osc.connect(filter).connect(gain).connect(master)
        osc.start()
        motor = { osc, gain, filter }
      }
      const now = ctx.currentTime
      motor.osc.frequency.setTargetAtTime(45 + 110 * v, now, 0.08)
      motor.filter.frequency.setTargetAtTime(300 + 900 * v, now, 0.08)
      motor.gain.gain.setTargetAtTime(0.05 + 0.1 * v, now, 0.08)
    },
    dispose() {
      window.removeEventListener('pointerdown', unlock, true)
      window.removeEventListener('keydown', unlock, true)
      alarm?.osc.stop()
      alarm = null
      line?.disconnect()
      line = null
      mains?.gain.disconnect()
      mains = null
      humWanted = false
      water?.gain.disconnect()
      water = null
      oceanWanted = false
      stands?.gain.disconnect()
      stands = null
      crowdWanted = false
      motor?.osc.stop()
      motor = null
      echo = null
      void ctx?.close()
      ctx = null
    },
  }
  return voices
}
