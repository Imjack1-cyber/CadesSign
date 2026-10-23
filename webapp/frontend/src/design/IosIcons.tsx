/* oxlint-disable react/only-export-components -- icon data sits next to the icons that draw it */
/**
 * The iPadOS theme's icons, all drawn here: app icons (a gradient on the continuous-corner squircle
 * iOS uses, with a white symbol) and small line glyphs in the manner of SF Symbols. None of Apple's
 * artwork is copied; the shapes only follow the same conventions.
 */
import type { ReactNode } from 'react'
import { fileKind } from './iosFiles'
import type { AppId } from './iosPrefs'

/** A superellipse (n = 5) the size of a 60×60 icon: the continuous corner of iOS app icons. */
export const SQUIRCLE = (() => {
  const n = 5
  const pts: string[] = []
  for (let i = 0; i < 72; i++) {
    const a = (i / 72) * Math.PI * 2
    const c = Math.cos(a)
    const s = Math.sin(a)
    const x = 30 + 30 * Math.sign(c) * Math.abs(c) ** (2 / n)
    const y = 30 + 30 * Math.sign(s) * Math.abs(s) ** (2 / n)
    pts.push(`${x.toFixed(2)} ${y.toFixed(2)}`)
  }
  return `M${pts.join('L')}Z`
})()

interface AppLook {
  label: string
  from: string
  to: string
  /** The symbol, in a 60×60 box; white unless it says otherwise. */
  art: ReactNode
}

export const APP_LOOKS: Record<AppId, AppLook> = {
  sign: {
    label: 'Sign', from: '#3d9bff', to: '#0040dd',
    art: (
      <>
        <path d="M38 13l9 9-19 19-11 3 3-11z" fill="#fff" />
        <path d="M35 16l9 9" stroke="#0a5cf0" strokeWidth="2" />
        <path d="M12 49q5-6 9-1t8-2 7 1 8-3" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" />
      </>
    ),
  },
  verify: {
    label: 'Verify', from: '#5fe07c', to: '#1f9a3e',
    art: (
      <>
        <path d="M30 9l5 4 6-1 2 6 6 3-1 6 4 5-4 5 1 6-6 3-2 6-6-1-5 4-5-4-6 1-2-6-6-3 1-6-4-5 4-5-1-6 6-3 2-6 6 1z" fill="#fff" />
        <path d="M21 31l6 6 12-13" fill="none" stroke="#1f9a3e" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      </>
    ),
  },
  analytics: {
    label: 'Analytics', from: '#8e8cff', to: '#3634a3',
    art: (
      <>
        <rect x="13" y="32" width="8" height="15" rx="2.5" fill="#fff" />
        <rect x="26" y="20" width="8" height="27" rx="2.5" fill="#fff" />
        <rect x="39" y="12" width="8" height="35" rx="2.5" fill="#fff" opacity="0.85" />
      </>
    ),
  },
  files: {
    label: 'Files', from: '#ffffff', to: '#e5e5ea',
    art: (
      <>
        <path d="M10 19a4 4 0 0 1 4-4h10l4 4h18a4 4 0 0 1 4 4v19a4 4 0 0 1-4 4H14a4 4 0 0 1-4-4z" fill="#1a8cff" />
        <path d="M10 25h40v17a4 4 0 0 1-4 4H14a4 4 0 0 1-4-4z" fill="#47a6ff" />
      </>
    ),
  },
  settings: {
    label: 'Settings', from: '#b4b4ba', to: '#636366',
    art: (
      <>
        <circle cx="30" cy="30" r="17" fill="none" stroke="#fff" strokeWidth="6" strokeDasharray="4.45 2.2" />
        <circle cx="30" cy="30" r="12" fill="none" stroke="#fff" strokeWidth="3" />
        <circle cx="30" cy="30" r="5" fill="#fff" />
        <path d="M30 18v7M30 35v7M18 30h7M35 30h7" stroke="#fff" strokeWidth="2" />
      </>
    ),
  },
  about: {
    label: 'About', from: '#ffd94a', to: '#ff9f0a',
    art: (
      <>
        <circle cx="30" cy="30" r="17" fill="#fff" />
        <circle cx="30" cy="22.5" r="2.6" fill="#ff9f0a" />
        <path d="M30 28v12" stroke="#ff9f0a" strokeWidth="5" strokeLinecap="round" />
      </>
    ),
  },
}

/** An app icon: the gradient squircle with its symbol, and an optional red badge. */
export function AppIcon({ app, size = 60, badge }: { app: AppId; size?: number; badge?: number }) {
  const look = APP_LOOKS[app]
  const id = `ios-icon-${app}`
  return (
    <span className="ios-appicon" style={{ width: size, height: size }} data-app={app}>
      <svg viewBox="0 0 60 60" width={size} height={size} aria-hidden="true">
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={look.from} />
            <stop offset="1" stopColor={look.to} />
          </linearGradient>
        </defs>
        <path d={SQUIRCLE} fill={`url(#${id})`} />
        {look.art}
        {/* A faint top sheen, as the glass app icons of iOS 26 catch the light. */}
        <path d={SQUIRCLE} fill="none" stroke="rgba(255,255,255,0.45)" strokeWidth="1" />
      </svg>
      {!!badge && <span className="ios-badge" aria-hidden="true">{badge > 99 ? '99+' : badge}</span>}
    </span>
  )
}

export type GlyphName =
  | 'bell' | 'bell-slash' | 'moon' | 'sun' | 'wifi' | 'wifi-slash' | 'lock' | 'lock-open' | 'flashlight' | 'camera'
  | 'search' | 'gear' | 'folder' | 'doc' | 'doc-text' | 'chart' | 'pen' | 'seal' | 'key' | 'check-circle' | 'x-circle'
  | 'warn' | 'info' | 'chevron-right' | 'chevron-left' | 'trash' | 'share' | 'speaker' | 'speaker-slash' | 'sparkles'
  | 'contrast' | 'home' | 'grid' | 'list' | 'clock' | 'xmark' | 'ellipsis' | 'recover' | 'photo' | 'hand' | 'keyboard'
  | 'eye' | 'sort' | 'person' | 'cursor' | 'iphone'

/** The mark inside a filled glyph (check, cross, !, i), white unless the surface says otherwise. */
const ON_GLYPH = { stroke: 'var(--ios-on-glyph, #fff)' }

const GLYPHS: Record<GlyphName, ReactNode> = {
  bell: <path d="M12 3a6 6 0 0 0-6 6v4l-2 3h16l-2-3V9a6 6 0 0 0-6-6zM10 19a2 2 0 0 0 4 0" />,
  'bell-slash': <path d="M12 3a6 6 0 0 0-6 6v4l-2 3h16l-2-3V9a6 6 0 0 0-6-6zM10 19a2 2 0 0 0 4 0M4 3l16 18" />,
  moon: <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z" fill="currentColor" />,
  sun: <><circle cx="12" cy="12" r="4" fill="currentColor" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  wifi: <><path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.2a9.5 9.5 0 0 1 13 0M8.6 15.4a5 5 0 0 1 6.8 0" /><circle cx="12" cy="19" r="1.5" fill="currentColor" /></>,
  'wifi-slash': <><path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.2a9.5 9.5 0 0 1 13 0M8.6 15.4a5 5 0 0 1 6.8 0M3 3l18 18" /><circle cx="12" cy="19" r="1.5" fill="currentColor" /></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2.5" fill="currentColor" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>,
  'lock-open': <><rect x="5" y="10" width="14" height="11" rx="2.5" fill="currentColor" /><path d="M8 10V7a4 4 0 0 1 8 0" /></>,
  flashlight: <><path d="M8 2h8v4l-2 4v11a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V10L8 6z" /><circle cx="12" cy="14" r="1.2" fill="currentColor" /></>,
  camera: <><path d="M3 8a2 2 0 0 1 2-2h2.5L9 4h6l1.5 2H19a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><circle cx="12" cy="13" r="3.5" /></>,
  search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="M15.5 15.5L21 21" /></>,
  gear: <><circle cx="12" cy="12" r="3" /><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1" /><circle cx="12" cy="12" r="6.5" /></>,
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  doc: <><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4" /></>,
  'doc-text': <><path d="M6 3h8l4 4v14H6z" /><path d="M14 3v4h4M9 12h6M9 15h6M9 18h4" /></>,
  chart: <path d="M5 20V13M10 20V8M15 20v-5M20 20V4" />,
  pen: <><path d="M15 4l5 5L9 20H4v-5z" /><path d="M13 6l5 5" /></>,
  seal: <><path d="M12 2l2.2 2 3-.4.7 2.9 2.7 1.4-1 2.8 1 2.8-2.7 1.4-.7 2.9-3-.4L12 20l-2.2-2-3 .4-.7-2.9L3.4 14l1-2.8-1-2.8 2.7-1.4.7-2.9 3 .4z" /><path d="M8.5 11.5l2.5 2.5 4.5-5" /></>,
  key: <><circle cx="8" cy="14" r="4" /><path d="M11 11l9-9M16 6l3 3M14 8l2 2" /></>,
  'check-circle': <><circle cx="12" cy="12" r="10" fill="currentColor" /><path d="M7.5 12.5l3 3 6-7" style={ON_GLYPH} /></>,
  'x-circle': <><circle cx="12" cy="12" r="10" fill="currentColor" /><path d="M8.5 8.5l7 7M15.5 8.5l-7 7" style={ON_GLYPH} /></>,
  warn: <><path d="M12 3L2 20h20z" fill="currentColor" /><path d="M12 9.5v5M12 17.2v.3" style={ON_GLYPH} /></>,
  info: <><circle cx="12" cy="12" r="10" fill="currentColor" /><path d="M12 11v6M12 7.5v.3" style={ON_GLYPH} /></>,
  'chevron-right': <path d="M9 5l7 7-7 7" />,
  'chevron-left': <path d="M15 5l-7 7 7 7" />,
  trash: <><path d="M4 6h16M9 6V4h6v2M6 6l1 15h10l1-15" /><path d="M10 10v8M14 10v8" /></>,
  share: <><path d="M12 15V3M8 7l4-4 4 4" /><path d="M7 10H5v11h14V10h-2" /></>,
  speaker: <><path d="M3 9h4l5-4v14l-5-4H3z" fill="currentColor" /><path d="M15.5 8.5a5 5 0 0 1 0 7M18.5 5.5a9 9 0 0 1 0 13" /></>,
  'speaker-slash': <><path d="M3 9h4l5-4v14l-5-4H3z" fill="currentColor" /><path d="M16 9l5 6M21 9l-5 6" /></>,
  sparkles: <path d="M10 3l1.8 5.2L17 10l-5.2 1.8L10 17l-1.8-5.2L3 10l5.2-1.8zM18 14l.9 2.1 2.1.9-2.1.9L18 20l-.9-2.1L15 17l2.1-.9z" fill="currentColor" />,
  contrast: <><circle cx="12" cy="12" r="9" /><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" /></>,
  home: <path d="M3 11l9-7 9 7M6 9v11h12V9" />,
  grid: <><rect x="4" y="4" width="7" height="7" rx="2" /><rect x="13" y="4" width="7" height="7" rx="2" /><rect x="4" y="13" width="7" height="7" rx="2" /><rect x="13" y="13" width="7" height="7" rx="2" /></>,
  list: <path d="M9 6h11M9 12h11M9 18h11M4.5 6h.5M4.5 12h.5M4.5 18h.5" />,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  xmark: <path d="M6 6l12 12M18 6L6 18" />,
  ellipsis: <path d="M6 12h.5M12 12h.5M18 12h.5" strokeWidth="3.5" />,
  recover: <><path d="M4 12a8 8 0 1 0 2.3-5.6" /><path d="M4 4v4h4" /></>,
  photo: <><rect x="3" y="5" width="18" height="14" rx="3" /><circle cx="8.5" cy="10" r="1.6" fill="currentColor" /><path d="M4 17l5-5 4 4 3-3 4 4" /></>,
  hand: <><circle cx="12" cy="4.5" r="2" fill="currentColor" /><path d="M5 8.5l7 1.5 7-1.5M12 10v5l-3 6M12 15l3 6" /></>,
  keyboard: <><rect x="2.5" y="6" width="19" height="12" rx="2.5" /><path d="M6 10h.5M9.5 10h.5M13 10h.5M16.5 10h.5M6.5 14h11" /></>,
  eye: <><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>,
  sort: <path d="M7 4v16M3 16l4 4 4-4M17 20V4M13 8l4-4 4 4" />,
  person: <><circle cx="12" cy="8" r="4" fill="currentColor" /><path d="M4 21a8 8 0 0 1 16 0z" fill="currentColor" /></>,
  cursor: <path d="M5 3l14 7-6 2-2 6z" fill="currentColor" />,
  iphone: <><rect x="6" y="2" width="12" height="20" rx="3" /><path d="M10 4.5h4" /></>,
}

/** A line glyph in the current text color, 1em square unless sized. */
export function Glyph({ name, size }: { name: GlyphName; size?: number | string }) {
  return (
    <svg
      className="ios-glyph" viewBox="0 0 24 24" width={size ?? '1em'} height={size ?? '1em'} aria-hidden="true"
      fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
    >
      {GLYPHS[name]}
    </svg>
  )
}

/** A rounded colored tile with a white glyph, as Settings shows beside each row. */
export function RowIcon({ name, color }: { name: GlyphName; color: string }) {
  return (
    <span className="ios-rowicon" style={{ background: color, '--ios-on-glyph': color } as React.CSSProperties} aria-hidden="true">
      <Glyph name={name} />
    </span>
  )
}

/**
 * A file as Files draws it: a page with a folded corner, a hint of what is on it (a seal for a
 * signature, lines of text for a report, a key for a keystore) and its type on a coloured band.
 */
export function FileThumb({ name, size = 60 }: { name: string; size?: number }) {
  const kind = fileKind(name)
  const keystore = kind.badge === 'P12' || kind.badge === 'PFX'
  const signature = kind.label === 'CAdES Signature'
  return (
    <svg className="ios-filethumb" viewBox="0 0 48 60" width={size * 0.8} height={size} aria-hidden="true">
      <path d="M6 1.5h25l13.5 13.5v40a3.5 3.5 0 0 1-3.5 3.5H6A3.5 3.5 0 0 1 2.5 55V5A3.5 3.5 0 0 1 6 1.5z" fill="#fff" stroke="rgba(0,0,0,0.14)" />
      <path d="M31 1.5V12a3 3 0 0 0 3 3h10.5" fill="#ececf1" stroke="rgba(0,0,0,0.14)" />
      {keystore ? (
        <g fill="none" stroke={kind.color} strokeWidth="2.6" strokeLinecap="round">
          <circle cx="18" cy="28" r="6.5" />
          <path d="M23 24l12-12M30 17l4 4M27 20l3 3" />
        </g>
      ) : (
        <g stroke="#c7c7cc" strokeWidth="2" strokeLinecap="round">
          {(signature ? [24, 29, 34] : [12, 17, 22, 27, 32, 37]).map((y, i) => (
            <path key={y} d={`M${signature ? 20 : 9} ${y}H${i % 3 === 2 ? 30 : 38}`} />
          ))}
          {signature && <path d="M13 13l1.6 1.4 2.2-.3.5 2.1 2 1-.8 2 .8 2-2 1-.5 2.1-2.2-.3-1.6 1.4-1.6-1.4-2.2.3-.5-2.1-2-1 .8-2-.8-2 2-1 .5-2.1 2.2.3z" fill={kind.color} stroke="none" />}
          {signature && <path d="M9 41q3-4 5 0t4-1 4 1" stroke={kind.color} strokeWidth="1.6" fill="none" />}
        </g>
      )}
      <rect x="7" y="45.5" width="34" height="9" rx="2.5" fill={kind.color} />
      <text x="24" y="52.6" textAnchor="middle" fill="#fff" fontSize="7" fontWeight="700" fontFamily="-apple-system, system-ui, sans-serif" letterSpacing="0.3">
        {kind.badge}
      </text>
    </svg>
  )
}

/** A folder, light blue with a darker tab, as Files and the Finder draw them. */
export function FolderIcon({ size = 64 }: { size?: number }) {
  return (
    <svg className="ios-foldericon" viewBox="0 0 64 50" width={size} height={size * 0.78} aria-hidden="true">
      <path d="M3 8a5 5 0 0 1 5-5h15l5 5h28a5 5 0 0 1 5 5v31a5 5 0 0 1-5 5H8a5 5 0 0 1-5-5z" fill="#1d8ef5" />
      <path d="M3 15a5 5 0 0 1 5-5h48a5 5 0 0 1 5 5v29a5 5 0 0 1-5 5H8a5 5 0 0 1-5-5z" fill="#5db4ff" />
      <path d="M3 15a5 5 0 0 1 5-5h48a5 5 0 0 1 5 5" fill="none" stroke="rgba(255,255,255,0.55)" />
    </svg>
  )
}
