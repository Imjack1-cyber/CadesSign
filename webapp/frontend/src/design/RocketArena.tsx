import { useCallback, useEffect, useRef, useState } from 'react'
import { RocketGame } from './RocketGame'
import { APP_SIGNAL_EVENT, type AppSignal } from './signals'

/** Typed on the page outside any text field, this word starts a match. */
export const EASTER_EGG = 'kickoff'

/**
 * The Rocket League theme's stadium scoreboard: this session's results as a score (a success is a
 * goal for Blue, a failure one for Orange) under a running clock, and a Free play button that opens
 * the Sideswipe minigame. Typing "kickoff" anywhere outside a text field opens it too.
 */
export function RocketArena() {
  const [score, setScore] = useState<[number, number]>([0, 0])
  const [seconds, setSeconds] = useState(0)
  const [playing, setPlaying] = useState(false)
  const opener = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    const onSignal = (e: Event) => {
      const d = (e as CustomEvent<AppSignal>).detail
      if (d.type !== 'outcome') return
      if (d.kind === 'success') setScore(([b, o]: [number, number]) => [b + 1, o])
      else if (d.kind === 'error') setScore(([b, o]: [number, number]) => [b, o + 1])
    }
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    return () => window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
  }, [])

  useEffect(() => {
    const t = window.setInterval(() => setSeconds((s: number) => s + 1), 1000)
    return () => window.clearInterval(t)
  }, [])

  useEffect(() => {
    if (playing) return
    let typed = ''
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.key.length !== 1) return
      const target = e.composedPath()[0]
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable)) return
      typed = (typed + e.key.toLowerCase()).slice(-EASTER_EGG.length)
      if (typed === EASTER_EGG) {
        typed = ''
        setPlaying(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [playing])

  const close = useCallback(() => {
    setPlaying(false)
    window.setTimeout(() => opener.current?.focus(), 0)
  }, [])

  const clock = `${Math.floor(seconds / 60) % 100}:${String(seconds % 60).padStart(2, '0')}`

  return (
    <>
      <div className="rl-scoreboard" role="group" aria-label="Scoreboard" title="Successful results score for Blue, failed ones for Orange">
        <span className="rl-scoreboard-team rl-scoreboard-team--blue" aria-label={`Blue ${score[0]}`}>
          <small>BLUE</small>
          <b>{score[0]}</b>
        </span>
        <span className="rl-scoreboard-clock" aria-hidden="true">{clock}</span>
        <span className="rl-scoreboard-team rl-scoreboard-team--orange" aria-label={`Orange ${score[1]}`}>
          <b>{score[1]}</b>
          <small>ORANGE</small>
        </span>
        <button
          ref={opener}
          type="button"
          className="rl-scoreboard-play"
          onClick={() => setPlaying(true)}
          aria-haspopup="dialog"
          title={`Play a Sideswipe match (or type "${EASTER_EGG}")`}
        >
          Free play
        </button>
      </div>
      {playing && <RocketGame onClose={close} />}
    </>
  )
}
