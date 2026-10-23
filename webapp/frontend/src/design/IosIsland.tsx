import { useEffect, useState } from 'react'
import { AppIcon, Glyph } from './IosIcons'

/** Something the Island shows for a moment: a result, the ring / silent switch, the charger, the lock. */
export type IslandFlash =
  | { kind: 'ok' | 'warn' | 'fail'; text: string }
  | { kind: 'silent'; on: boolean }
  | { kind: 'charging'; level: number }
  | { kind: 'lock' | 'unlock' }

interface IosIslandProps {
  /** When the request now running started (ms), or null. */
  busySince: number | null
  action: string
  flash: IslandFlash | null
}

const elapsedText = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

/**
 * The Dynamic Island on phones: a black pill around the camera that grows into whatever is going
 * on. While a request runs it is a Live Activity (a spinner and the time it has taken; tap it to
 * expand); a result, the silent switch, the charger and the lock each show in it for a moment. It
 * morphs between shapes on a spring (themes.css). Only the running request is a control; everything
 * it shows is also announced elsewhere, so the rest stays out of the accessibility tree.
 */
export function IosIsland({ busySince, action, flash }: IosIslandProps) {
  // Expanded belongs to one request: the next one starts compact again.
  const [expandedFor, setExpandedFor] = useState<number | null>(null)
  const expanded = busySince !== null && expandedFor === busySince
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (busySince === null) return
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [busySince])

  const state = flash ? 'flash' : busySince !== null ? (expanded ? 'expanded' : 'compact') : 'idle'
  const elapsed = busySince === null ? 0 : Math.max(0, Math.round((now - busySince) / 1000))
  const doing = action === 'verify' ? 'Verifying signature…' : action === 'sign' ? 'Signing document…' : 'Working…'

  return (
    <div className="ios-island" data-state={state} data-flash={flash?.kind}>
      {state === 'flash' && flash && (
        <div className="ios-island-body" aria-hidden="true">
          {(flash.kind === 'ok' || flash.kind === 'warn' || flash.kind === 'fail') && (
            <>
              <span className="ios-island-lead" data-tone={flash.kind}>
                <Glyph name={flash.kind === 'ok' ? 'check-circle' : flash.kind === 'warn' ? 'warn' : 'x-circle'} size={22} />
              </span>
              <span className="ios-island-trail">{flash.text}</span>
            </>
          )}
          {flash.kind === 'silent' && (
            <>
              <span className="ios-island-lead" data-tone={flash.on ? 'silent' : 'ring'}><Glyph name={flash.on ? 'bell-slash' : 'bell'} size={18} /></span>
              <span className="ios-island-trail" data-tone={flash.on ? 'silent' : undefined}>{flash.on ? 'Silent' : 'Ring'}</span>
            </>
          )}
          {flash.kind === 'charging' && (
            <>
              <span className="ios-island-lead">Charging</span>
              <span className="ios-island-trail" data-tone="charging">{Math.round(flash.level * 100)}%</span>
            </>
          )}
          {(flash.kind === 'lock' || flash.kind === 'unlock') && (
            <span className="ios-island-lead ios-island-lock"><Glyph name={flash.kind === 'lock' ? 'lock' : 'lock-open'} size={16} /></span>
          )}
        </div>
      )}
      {state !== 'flash' && busySince !== null && (
        <button
          type="button"
          className="ios-island-body"
          aria-expanded={expanded}
          aria-label={`${doing} ${elapsedText(elapsed)}`}
          onClick={() => setExpandedFor(expanded ? null : busySince)}
        >
          {expanded ? (
            <>
              <AppIcon app={action === 'verify' ? 'verify' : 'sign'} size={44} />
              <span className="ios-island-text">
                <b>{action === 'verify' ? 'Verify' : 'Sign'}</b>
                <span>{doing}</span>
              </span>
              <time className="ios-island-time">{elapsedText(elapsed)}</time>
              <span className="ios-island-progress"><i /></span>
            </>
          ) : (
            <>
              <span className="ios-island-lead"><span className="ios-spinner" /></span>
              <time className="ios-island-trail">{elapsedText(elapsed)}</time>
            </>
          )}
        </button>
      )}
    </div>
  )
}
