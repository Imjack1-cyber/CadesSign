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
  /** A monitor beep, optionally delayed by `delay` seconds. */
  beep(freq: number, ms: number, delay?: number): void
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
  dispose(): void
}

const MASTER_GAIN = 0.15
/** Minimum seconds between two plays of the same voice. */
const MIN_GAP = 0.03
/** How long a start-up sound waits for the first gesture before it is dropped. */
const STARTUP_WAIT_MS = 5000
/** Touch-tone pairs (low, high Hz) for the digits the modem dials. */
const DTMF: ReadonlyArray<[number, number]> = [[852, 1209], [697, 1336], [770, 1477], [941, 1336], [697, 1209], [852, 1477], [770, 1336]]

const silent: Sound = {
  click() {}, thud() {}, bell() {}, beep() {}, tone() {}, rasp() {}, whoosh() {}, knock() {}, pebble() {}, chime() {},
  startup() {}, shutdown() {}, tada() {}, chord() {}, ding() {}, exclamation() {}, asterisk() {}, menu() {}, minimize() {}, maximize() {}, recycle() {}, pop() {}, seek() {}, modem() {},
  dispose() {},
}

export function createSound(): Sound {
  if (typeof window === 'undefined' || typeof window.AudioContext === 'undefined') return silent

  let ctx: AudioContext | null = null
  let master: GainNode | null = null
  let noise: AudioBuffer | null = null
  let alarm: { osc: OscillatorNode; gain: GainNode } | null = null
  let line: GainNode | null = null
  let startupAsked = 0
  const lastPlay = new Map<string, number>()

  const unlock = () => {
    if (!ctx) {
      ctx = new AudioContext()
      master = ctx.createGain()
      master.gain.value = MASTER_GAIN
      master.connect(ctx.destination)
      noise = ctx.createBuffer(1, ctx.sampleRate, ctx.sampleRate)
      const data = noise.getChannelData(0)
      for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1
    }
    if (ctx.state === 'suspended') void ctx.resume().then(playQueued)
    else playQueued()
  }
  const playQueued = () => {
    if (!startupAsked) return
    const fresh = performance.now() - startupAsked < STARTUP_WAIT_MS
    startupAsked = 0
    if (fresh) voices.startup()
  }
  window.addEventListener('pointerdown', unlock, true)
  window.addEventListener('keydown', unlock, true)

  /** The context, if audio is unlocked and this voice did not play a moment ago. */
  const ready = (voice: string, gap = MIN_GAP) => {
    if (!ctx || !master || ctx.state !== 'running') return null
    const last = lastPlay.get(voice) ?? -1
    if (ctx.currentTime - last < gap) return null
    lastPlay.set(voice, ctx.currentTime)
    return ctx
  }

  /** A gain envelope: fast attack to `peak`, exponential decay over `decay` seconds. */
  const envelope = (c: AudioContext, at: number, peak: number, decay: number) => {
    const g = c.createGain()
    g.gain.setValueAtTime(0.0001, at)
    g.gain.exponentialRampToValueAtTime(peak, at + 0.004)
    g.gain.exponentialRampToValueAtTime(0.0001, at + decay)
    g.connect(master!)
    return g
  }

  const burst = (c: AudioContext, at: number, filter: BiquadFilterType, freq: number, q: number, peak: number, decay: number) => {
    const src = c.createBufferSource()
    src.buffer = noise
    src.playbackRate.value = 0.8 + Math.random() * 0.4
    const f = c.createBiquadFilter()
    f.type = filter
    f.frequency.value = freq
    f.Q.value = q
    src.connect(f).connect(envelope(c, at, peak, decay))
    src.start(at, Math.random() * 0.5, decay + 0.05)
    return f
  }

  const sine = (c: AudioContext, at: number, freq: number, peak: number, decay: number, type: OscillatorType = 'sine', endFreq?: number) => {
    const osc = c.createOscillator()
    osc.type = type
    osc.frequency.setValueAtTime(freq, at)
    if (endFreq) osc.frequency.exponentialRampToValueAtTime(endFreq, at + decay)
    osc.connect(envelope(c, at, peak, decay))
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
    beep(freq, ms, delay = 0) {
      const c = ready(`beep${delay}`, 0.05)
      if (!c) return
      const at = c.currentTime + delay
      const osc = c.createOscillator()
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
        startupAsked = performance.now()
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
    dispose() {
      window.removeEventListener('pointerdown', unlock, true)
      window.removeEventListener('keydown', unlock, true)
      alarm?.osc.stop()
      alarm = null
      line?.disconnect()
      line = null
      void ctx?.close()
      ctx = null
    },
  }
  return voices
}
