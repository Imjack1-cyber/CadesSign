import { useEffect, useMemo, useRef } from 'react'
import type { ThemeId } from './designs'
import { runEffect } from './effects/engine'
import { PRESETS } from './effects/presets'
import { useDesign } from './useDesign'

/** Small deterministic PRNG (mulberry32), so decoration lands in the same places on every render. */
function random(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** n spans with randomized --x, --y, --d (duration), --delay and --s (scale) for CSS to animate. */
function scatter(n: number, seed: number) {
  const rnd = random(seed)
  return Array.from({ length: n }, (_, i) => {
    const d = 4 + rnd() * 8
    const style = {
      '--x': `${(rnd() * 100).toFixed(1)}%`,
      '--y': `${(rnd() * 100).toFixed(1)}%`,
      '--d': `${d.toFixed(2)}s`,
      '--delay': `${(-rnd() * d).toFixed(2)}s`,
      '--s': (0.5 + rnd()).toFixed(2),
    } as React.CSSProperties
    return <span key={i} style={style} />
  })
}

const FISH = 'M0 10 Q12 0 26 6 L34 0 L32 10 L34 20 L26 14 Q12 20 0 10 Z'
const JELLY = 'M0 12 Q14 -6 28 12 Q24 12 22 14 Q20 26 18 14 Q14 30 12 14 Q8 26 6 14 Q4 12 0 12 Z'

/**
 * Theme decoration that does not fit a particle system: drips, droplets on the glass, frost, a sun,
 * fish, doodles. It renders for every effect level so the theme looks the same at rest; themes.css
 * only animates it under [data-app-effects=wild].
 */
function ThemeDecor({ theme }: { theme: ThemeId }) {
  const droplets = useMemo(() => scatter(18, 7), [])
  const dots = useMemo(() => scatter(14, 3), [])
  switch (theme) {
    case 'bubblegum':
      return <div className="decor decor-dots">{dots}</div>
    case 'chocolate':
      return <div className="decor decor-drips">{scatter(12, 11)}</div>
    case 'snowing':
      return <><div className="decor decor-frost" /><div className="decor decor-fog" /></>
    case 'raining':
      return <div className="decor decor-glass">{droplets}</div>
    case 'starry':
      return <><div className="decor decor-swirl" /><div className="decor decor-swirl decor-swirl--b" /><div className="decor decor-moon" /></>
    case 'synthwave':
      return <><div className="decor decor-sun" /><div className="decor decor-grid" /><div className="decor decor-vhs" /></>
    case 'terminal':
      return <div className="decor decor-crt" />
    case 'blueprint':
      return (
        <>
          <svg className="decor decor-drafting" viewBox="0 0 1000 600" preserveAspectRatio="xMidYMid slice">
            <path d="M40 520 L960 520 M80 80 L80 560 M80 120 L620 120 L620 480 L80 480" />
            <path d="M700 80 L940 80 L940 300 L700 300 Z M700 190 L940 190 M820 80 L820 300" />
            <circle cx="820" cy="430" r="90" />
            <circle cx="820" cy="430" r="40" />
            <path d="M120 560 L580 560 M120 550 L120 570 M580 550 L580 570" />
            <g className="decor-compass">
              <path d="M820 430 L870 340 M820 430 L770 340 M870 340 L820 300 L770 340" />
            </g>
          </svg>
          <div className="decor decor-crosshair" />
        </>
      )
    case 'notebook':
      return (
        <svg className="decor decor-doodles" viewBox="0 0 80 600" preserveAspectRatio="xMinYMin meet">
          <path d="M40 40 L46 58 L64 58 L50 70 L56 88 L40 76 L24 88 L30 70 L16 58 L34 58 Z" />
          <path d="M20 160 Q40 130 60 160 T60 200 M50 190 L60 200 L68 188" />
          <circle cx="40" cy="280" r="20" />
          <path d="M32 274 L32 276 M48 274 L48 276 M30 288 Q40 298 50 288" />
          <path d="M15 380 Q25 360 40 380 Q55 400 65 380" />
          <path d="M20 470 L60 470 L40 440 Z M40 470 L40 500" />
        </svg>
      )
    case 'sakura':
      return (
        <>
          <svg className="decor decor-branch" viewBox="0 0 400 300">
            <path d="M400 20 Q300 40 240 90 Q190 130 120 140 M300 45 Q280 90 300 130 M240 90 Q220 60 180 50" />
            {[[120, 140], [180, 50], [300, 130], [210, 110], [265, 70]].map(([cx, cy]) => (
              <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r="12" />
            ))}
          </svg>
          <div className="decor decor-pond">{scatter(5, 19)}</div>
        </>
      )
    case 'deepsea':
      return (
        <>
          <svg className="decor decor-fish" viewBox="0 0 1000 600" preserveAspectRatio="none">
            <path className="fish fish--a" d={FISH} />
            <path className="fish fish--b" d={FISH} />
            <path className="fish fish--c" d={FISH} />
            <path className="jelly jelly--a" d={JELLY} />
            <path className="jelly jelly--b" d={JELLY} />
          </svg>
          <div className="decor decor-flashlight" />
        </>
      )
    case 'autumn':
      return <div className="decor decor-firelight" />
    case 'notary':
      return <div className="decor decor-lamp" />
    case 'vitals':
      return <><div className="decor decor-monitor" /><div className="decor decor-alarm" /><div className="decor decor-shock" /></>
    case 'zen':
      return (
        <svg className="decor decor-shishi" viewBox="0 0 160 120">
          <path className="shishi-water" d="M146 18 Q150 30 146 44" />
          <path className="shishi-spout" d="M112 14 L156 18" />
          <path className="shishi-post" d="M72 112 L76 54 M92 112 L88 54" />
          <g className="shishi-arm">
            <path d="M20 66 L146 46" />
            <ellipse cx="146" cy="46" rx="3" ry="7" />
          </g>
          <ellipse className="shishi-stone" cx="26" cy="104" rx="22" ry="12" />
          <ellipse className="shishi-basin" cx="132" cy="108" rx="26" ry="9" />
        </svg>
      )
    case 'win95':
      // The file-copy dialog shown while a request runs (themes.css shows it under .app-hourglass).
      return (
        <div className="decor decor-copy">
          <span className="copy-title">Copying...</span>
          <span className="copy-folder copy-folder--from" />
          <span className="copy-paper" />
          <span className="copy-folder copy-folder--to" />
          <span className="copy-from">From &apos;document&apos; to &apos;Time Stamp Authority&apos;</span>
          <span className="copy-eta" />
          <span className="copy-progress"><i /></span>
        </div>
      )
    default:
      return null
  }
}

/**
 * Decorative layers for themes: a fixed backdrop behind the app (themes.css paints it), the theme's
 * decoration, and for themes with an effect a canvas running its particle system. None of it takes
 * pointer events or is announced.
 */
export function ThemeEffects() {
  const { active, effects, sound } = useDesign()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const theme = active.theme
  const effect = effects !== 'off' ? theme?.effect : undefined

  useEffect(() => {
    if (!effect || !canvasRef.current) return
    return runEffect(canvasRef.current, effect, effects === 'wild', sound)
  }, [effect, effects, sound])

  return (
    <div aria-hidden="true">
      <div className="app-backdrop" />
      {theme && <ThemeDecor theme={theme.id} />}
      {effect && (
        <canvas
          ref={canvasRef}
          className={`app-effects app-effects--${PRESETS[effect].layer}`}
          data-effect={effect}
          data-testid="theme-effects"
        />
      )}
    </div>
  )
}
