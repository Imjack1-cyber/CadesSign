/**
 * The real device behind the iPadOS status bar: the time (ticking on the minute), the battery where
 * the browser tells (Battery Status API) and the network (online, and how fast where it says).
 */
import { useEffect, useRef, useState } from 'react'

/** The current time, updated as each minute starts. */
export function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    let timer = 0
    const tick = () => {
      const d = new Date()
      setNow(d)
      timer = window.setTimeout(tick, 60_000 - (d.getSeconds() * 1000 + d.getMilliseconds()) + 20)
    }
    timer = window.setTimeout(tick, 60_000 - (Date.now() % 60_000) + 20)
    return () => window.clearTimeout(timer)
  }, [])
  return now
}

/** "9:41", without AM/PM, as iOS shows it. */
export const timeText = (d: Date) => d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }).replace(/\s?[AP]\.?M\.?$/i, '')
export const dateText = (d: Date, long = false) =>
  d.toLocaleDateString([], long ? { weekday: 'long', day: 'numeric', month: 'long' } : { weekday: 'short', day: 'numeric', month: 'short' })

/** How long ago, the way notifications say it: "now", "5m ago", "2h ago", then the time. */
export function ago(at: number, now: number) {
  const s = Math.round((now - at) / 1000)
  if (s < 60) return 'now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 6 * 3600) return `${Math.floor(s / 3600)}h ago`
  return timeText(new Date(at))
}

interface BatteryManager extends EventTarget {
  level: number
  charging: boolean
}

export interface Battery {
  /** 0 to 1, or null where the browser does not tell. */
  level: number | null
  charging: boolean
}

/** Below this the battery shows yellow and warns once. */
export const LOW_BATTERY = 0.2

/** The battery; `onChange` hears each change as it happens, with the state before it. */
export function useBattery(onChange?: (now: Battery, before: Battery) => void): Battery {
  const [battery, setBattery] = useState<Battery>({ level: null, charging: false })
  const listener = useRef(onChange)
  useEffect(() => {
    listener.current = onChange
  })
  useEffect(() => {
    const nav = navigator as Navigator & { getBattery?: () => Promise<BatteryManager> }
    if (!nav.getBattery) return
    let manager: BatteryManager | null = null
    let live = true
    let before: Battery = { level: null, charging: false }
    const update = () => {
      if (!live || !manager) return
      const now = { level: manager.level, charging: manager.charging }
      listener.current?.(now, before)
      before = now
      setBattery(now)
    }
    nav.getBattery().then(m => {
      manager = m
      update()
      m.addEventListener('levelchange', update)
      m.addEventListener('chargingchange', update)
    }).catch(() => {})
    return () => {
      live = false
      manager?.removeEventListener('levelchange', update)
      manager?.removeEventListener('chargingchange', update)
    }
  }, [])
  return battery
}

interface Connection extends EventTarget {
  effectiveType?: string
}

export interface Network {
  online: boolean
  /** Signal bars, 1 to 3 (3 where the browser does not say). */
  bars: number
}

const BARS: Record<string, number> = { 'slow-2g': 1, '2g': 1, '3g': 2, '4g': 3 }

export function useNetwork(): Network {
  const read = (): Network => {
    const connection = (navigator as Navigator & { connection?: Connection }).connection
    return { online: navigator.onLine !== false, bars: BARS[connection?.effectiveType ?? ''] ?? 3 }
  }
  const [network, setNetwork] = useState(read)
  useEffect(() => {
    const update = () => setNetwork(read())
    const connection = (navigator as Navigator & { connection?: Connection }).connection
    window.addEventListener('online', update)
    window.addEventListener('offline', update)
    connection?.addEventListener('change', update)
    return () => {
      window.removeEventListener('online', update)
      window.removeEventListener('offline', update)
      connection?.removeEventListener('change', update)
    }
  }, [])
  return network
}

/** The light / dark mode the app is in right now (DesignProvider mirrors it on <html>). */
export function useAppMode(): 'light' | 'dark' {
  const read = () => (document.documentElement.dataset.appMode === 'dark' ? 'dark' : 'light')
  const [mode, setMode] = useState<'light' | 'dark'>(read)
  useEffect(() => {
    const observer = new MutationObserver(() => setMode(read()))
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-app-mode'] })
    return () => observer.disconnect()
  }, [])
  return mode
}
