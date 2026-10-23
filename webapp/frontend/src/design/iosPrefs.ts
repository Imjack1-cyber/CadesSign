/**
 * The iPadOS theme's own settings (its Settings app, Control Center), kept in this browser. A small
 * external store: React reads it with useIosPrefs, the effect preset synchronously with getIosPrefs
 * every frame, so both see a change at once. Stored values are checked one by one; anything unknown
 * or out of range falls back to its default.
 */
import { useSyncExternalStore } from 'react'

export type Wallpaper = 'bloom' | 'tide' | 'graphite'
/** The "apps" on the Home Screen and in the dock. */
export type AppId = 'sign' | 'verify' | 'analytics' | 'files' | 'settings' | 'about'

export interface IosPrefs {
  /** The iPadOS pointer in place of the mouse cursor (Wild only). */
  pointer: boolean
  /** Seconds without input before the screen locks (Wild only); 0 never locks. */
  autoLock: number
  /** Notification banners, and alerts when an operation fails. */
  banners: boolean
  alerts: boolean
  dockHide: boolean
  /** The wallpaper follows the device's tilt (phones). */
  tilt: boolean
  keyClicks: boolean
  lockSound: boolean
  /** A short vibration on taps, where the device can. */
  haptics: boolean
  /** Do Not Disturb: notifications are kept quietly, without banners or their sound. */
  focus: boolean
  /** 0.4 to 1. */
  brightness: number
  /** 0 to 1, on top of the theme's own quiet level. */
  volume: number
  reduceTransparency: boolean
  wallpaper: Wallpaper
  /** The order of the apps on the Home Screen. */
  home: AppId[]
  /** When Files was last opened (epoch ms); newer files are counted on its badge. */
  filesSeenAt: number
}

export const APPS: readonly AppId[] = ['sign', 'verify', 'analytics', 'files', 'settings', 'about']
export const WALLPAPERS: readonly Wallpaper[] = ['bloom', 'tide', 'graphite']
export const AUTO_LOCK: readonly number[] = [0, 60, 120, 300]
export const MIN_BRIGHTNESS = 0.4

export const DEFAULT_PREFS: IosPrefs = {
  pointer: true,
  autoLock: 120,
  banners: true,
  alerts: true,
  dockHide: false,
  tilt: false,
  keyClicks: true,
  lockSound: true,
  haptics: true,
  focus: false,
  brightness: 1,
  volume: 0.8,
  reduceTransparency: false,
  wallpaper: 'bloom',
  home: [...APPS],
  filesSeenAt: 0,
}

const KEY = 'cades-ios-prefs'

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

/** Whatever of `raw` is valid, on top of the defaults. */
export function parsePrefs(raw: string | null): IosPrefs {
  let stored: Record<string, unknown> = {}
  try {
    const parsed: unknown = raw ? JSON.parse(raw) : {}
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) stored = parsed as Record<string, unknown>
  } catch {
    // Not JSON: start over from the defaults.
  }
  const prefs: IosPrefs = { ...DEFAULT_PREFS, home: [...DEFAULT_PREFS.home] }
  const out = prefs as unknown as Record<string, unknown>
  for (const [key, fallback] of Object.entries(DEFAULT_PREFS)) {
    const v = stored[key]
    if (typeof fallback === 'boolean' && typeof v === 'boolean') out[key] = v
    if (typeof fallback === 'number' && typeof v === 'number' && Number.isFinite(v)) out[key] = v
  }
  prefs.autoLock = AUTO_LOCK.includes(prefs.autoLock) ? prefs.autoLock : DEFAULT_PREFS.autoLock
  prefs.brightness = clamp(prefs.brightness, MIN_BRIGHTNESS, 1)
  prefs.volume = clamp(prefs.volume, 0, 1)
  if (WALLPAPERS.includes(stored.wallpaper as Wallpaper)) prefs.wallpaper = stored.wallpaper as Wallpaper
  // The order counts only when it holds every app exactly once.
  const home = stored.home
  if (Array.isArray(home) && home.length === APPS.length && APPS.every(a => home.includes(a))) prefs.home = home as AppId[]
  return prefs
}

function read(): IosPrefs {
  try {
    return parsePrefs(window.localStorage.getItem(KEY))
  } catch {
    return parsePrefs(null)
  }
}

let current: IosPrefs | null = null
const listeners = new Set<() => void>()

export function getIosPrefs(): IosPrefs {
  return (current ??= read())
}

/** Reads the stored settings again, as when the theme starts. */
export function reloadIosPrefs() {
  current = read()
  listeners.forEach(l => l())
}

export function setIosPrefs(patch: Partial<IosPrefs>) {
  current = parsePrefs(JSON.stringify({ ...getIosPrefs(), ...patch }))
  try {
    window.localStorage.setItem(KEY, JSON.stringify(current))
  } catch {
    // Storage blocked: the settings last for this visit only.
  }
  listeners.forEach(l => l())
}

export function subscribeIosPrefs(listener: () => void) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export const useIosPrefs = (): IosPrefs => useSyncExternalStore(subscribeIosPrefs, getIosPrefs)
