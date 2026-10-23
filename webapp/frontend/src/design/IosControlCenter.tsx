import { useRef, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react'
import { themeSwitcher } from '@siemens/ix'
import type { EffectLevel } from './designs'
import { Glyph, type GlyphName } from './IosIcons'
import { type Network, useAppMode } from './iosDevice'
import { MIN_BRIGHTNESS, setIosPrefs, useIosPrefs } from './iosPrefs'
import { emitChrome } from './signals'
import { useDesign } from './useDesign'
import { useIosModal } from './useIosModal'

/** How far each key moves a slider. */
const KEY_STEPS = { ArrowUp: 0.1, ArrowRight: 0.1, ArrowDown: -0.1, ArrowLeft: -0.1, PageUp: 0.25, PageDown: -0.25 }

interface SliderProps {
  label: string
  glyph: GlyphName
  value: number
  min?: number
  onChange: (v: number) => void
  /** The drag or key press that changed it ended. */
  onCommit?: (v: number) => void
}

/** A fat vertical slider, filled from the bottom; drag it, or use the arrow keys. */
function Slider({ label, glyph, value, min = 0, onChange, onCommit }: SliderProps) {
  const ref = useRef<HTMLDivElement>(null)
  const dragging = useRef(false)
  const at = (y: number) => {
    const r = ref.current!.getBoundingClientRect()
    return Math.max(min, Math.min(1, 1 - (y - r.top) / r.height))
  }
  const onDown = (e: ReactPointerEvent) => {
    dragging.current = true
    e.currentTarget.setPointerCapture?.(e.pointerId)
    onChange(at(e.clientY))
  }
  const onMove = (e: ReactPointerEvent) => {
    if (dragging.current) onChange(at(e.clientY))
  }
  const onUp = (e: ReactPointerEvent) => {
    if (!dragging.current) return
    dragging.current = false
    onCommit?.(at(e.clientY))
  }
  const onKey = (e: ReactKeyboardEvent) => {
    const step = (KEY_STEPS as Record<string, number | undefined>)[e.key]
    let next = step === undefined ? null : value + step
    if (e.key === 'Home') next = min
    if (e.key === 'End') next = 1
    if (next === null) return
    e.preventDefault()
    next = Math.max(min, Math.min(1, Math.round(next * 100) / 100))
    onChange(next)
    onCommit?.(next)
  }
  return (
    <div
      ref={ref}
      className="ios-cc-slider ios-cc-tile"
      role="slider"
      tabIndex={0}
      aria-label={label}
      aria-orientation="vertical"
      aria-valuemin={Math.round(min * 100)}
      aria-valuemax={100}
      aria-valuenow={Math.round(value * 100)}
      aria-valuetext={`${Math.round(value * 100)}%`}
      onPointerDown={onDown}
      onPointerMove={onMove}
      onPointerUp={onUp}
      onPointerCancel={onUp}
      onKeyDown={onKey}
      style={{ '--value': value } as React.CSSProperties}
    >
      <span className="ios-cc-slider-fill" />
      <Glyph name={glyph} size={22} />
    </div>
  )
}

function Toggle({ label, detail, glyph, on, wide, onClick, children }: {
  label: string; detail?: string; glyph: GlyphName; on: boolean; wide?: boolean; onClick: () => void; children?: ReactNode
}) {
  return (
    <button type="button" className={`ios-cc-tile ios-cc-toggle${wide ? ' ios-cc-wide' : ''}`} aria-pressed={on} aria-label={label} onClick={onClick}>
      <span className="ios-cc-disc"><Glyph name={glyph} size={wide ? 20 : 24} /></span>
      {wide && <span className="ios-cc-caption"><b>{label}</b>{detail && <span>{detail}</span>}</span>}
      {children}
    </button>
  )
}

const MOTION: Record<EffectLevel, { next: EffectLevel; label: string }> = {
  wild: { next: 'calm', label: 'Wild' },
  calm: { next: 'off', label: 'Calm' },
  off: { next: 'wild', label: 'Off' },
}

interface IosControlCenterProps {
  network: Network
  onSilent: (on: boolean) => void
  onLock: () => void
  onAppearance: () => void
  onSettings: () => void
  onHome: () => void
  onClose: () => void
}

/**
 * Control Center: pulled down from the top right, a grid of glass tiles that really work. Focus (Do
 * Not Disturb), Silent mode, Dark Mode, the animation level and Lock are toggles; brightness and
 * volume are sliders (the volume clicks at its new level, as the buttons do); the network tile shows
 * whether the browser is online. The rest opens Appearance, Settings and the Home Screen.
 */
export function IosControlCenter({ network, onSilent, onLock, onAppearance, onSettings, onHome, onClose }: IosControlCenterProps) {
  const ref = useRef<HTMLDivElement>(null)
  useIosModal(ref, onClose)
  const prefs = useIosPrefs()
  const { soundPick, effectsPick, setEffects } = useDesign()
  const dark = useAppMode() === 'dark'
  const silent = soundPick !== 'on'

  return (
    <div className="ios-scrim ios-scrim--shade" onPointerDown={e => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className="ios-cc" role="dialog" aria-modal="true" aria-label="Control Center" tabIndex={-1}>
        <div className="ios-cc-tile ios-cc-network ios-cc-wide ios-cc-tall" role="group" aria-label="Network">
          <span className="ios-cc-disc" data-on={network.online || undefined}><Glyph name={network.online ? 'wifi' : 'wifi-slash'} size={22} /></span>
          <span className="ios-cc-caption"><b>Wi‑Fi</b><span>{network.online ? 'Connected' : 'Offline'}</span></span>
          <span className="ios-cc-disc" data-on={!prefs.focus || undefined} aria-hidden="true"><Glyph name="bell" size={20} /></span>
          <span className="ios-cc-caption" aria-hidden="true"><b>Notifications</b><span>{prefs.banners ? 'Banners' : 'Quiet'}</span></span>
        </div>
        <Toggle
          label="Focus" detail={prefs.focus ? 'Do Not Disturb' : 'Off'} glyph="moon" on={prefs.focus} wide
          onClick={() => {
            setIosPrefs({ focus: !prefs.focus })
            emitChrome('switch')
          }}
        />
        <Toggle label={silent ? 'Silent Mode on' : 'Silent Mode off'} glyph={silent ? 'bell-slash' : 'bell'} on={silent} onClick={() => onSilent(!silent)} />
        <Toggle
          label="Dark Mode" glyph="contrast" on={dark}
          onClick={() => {
            themeSwitcher.setColorSchema(dark ? 'light' : 'dark')
            emitChrome('switch')
          }}
        />
        <Slider label="Brightness" glyph="sun" min={MIN_BRIGHTNESS} value={prefs.brightness} onChange={v => setIosPrefs({ brightness: v })} />
        <Slider
          label="Volume" glyph={prefs.volume ? 'speaker' : 'speaker-slash'} value={prefs.volume}
          onChange={v => setIosPrefs({ volume: v })}
          onCommit={() => emitChrome('volume')}
        />
        <Toggle
          label={`Animation: ${MOTION[effectsPick].label}`} glyph="sparkles" on={effectsPick === 'wild'}
          onClick={() => setEffects(MOTION[effectsPick].next)}
        />
        <Toggle label="Lock Screen" glyph="lock" on={false} onClick={onLock} />
        <button type="button" className="ios-cc-tile ios-cc-wide ios-cc-button" onClick={onAppearance}>
          <span className="ios-cc-disc"><Glyph name="photo" size={20} /></span>
          <span className="ios-cc-caption"><b>Appearance</b><span>Theme, layout, colors</span></span>
        </button>
        <button type="button" className="ios-cc-tile ios-cc-button" aria-label="Settings" onClick={onSettings}>
          <span className="ios-cc-disc"><Glyph name="gear" size={24} /></span>
        </button>
        <button type="button" className="ios-cc-tile ios-cc-button" aria-label="Home Screen" onClick={onHome}>
          <span className="ios-cc-disc"><Glyph name="home" size={24} /></span>
        </button>
      </div>
    </div>
  )
}
