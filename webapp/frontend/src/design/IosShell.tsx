import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { themeSwitcher } from '@siemens/ix'
import type { View } from '../components/layout/AppShell'
import type { Box } from './effects/presets'
import { FOLDERS, type StoredFile, useGeneratedFiles } from './generatedFiles'
import { type AlertSpec, type Hud, IosAlert, IosHud, IosMenu, type MenuItem } from './IosAlert'
import { IosControlCenter } from './IosControlCenter'
import { LOW_BATTERY, useAppMode, useBattery, useClock, useNetwork } from './iosDevice'
import { IosDock } from './IosDock'
import { IosFiles, IosQuickLook } from './IosFiles'
import { edgeSwipe, type Point } from './iosGestures'
import { IosHome } from './IosHome'
import { type IslandFlash, IosIsland } from './IosIsland'
import { IosLockScreen } from './IosLockScreen'
import { IosBanners, IosNotificationCenter, MAX_BANNERS, type Note } from './IosNotifications'
import { type AppId, getIosPrefs, reloadIosPrefs, setIosPrefs, useIosPrefs } from './iosPrefs'
import type { SearchAction, Surface } from './iosSearch'
import { IosSettings } from './IosSettings'
import { IosShortcuts } from './IosShortcuts'
import { IosSpotlight } from './IosSpotlight'
import { IosStatusBar } from './IosStatusBar'
import { type SwitcherCard, IosSwitcher } from './IosSwitcher'
import { IosTabBar, type TabId } from './IosTabBar'
import { APP_SIGNAL_EVENT, type AppSignal, type CommandReply, emitChrome, emitCommandResult, GENERATED_EVENT, type GeneratedFile } from './signals'
import { useDesign } from './useDesign'
import { anyModalOpen } from './useIosModal'
import { PHONE_QUERY, useMediaQuery } from './useMediaQuery'
import { useWizardCommand } from './useWizardCommand'

interface IosShellProps {
  view: View
  onViewChange: (view: View) => void
  onOpenAppearance: () => void
}

/** The screen dims this long before Auto-Lock locks it, in ms. */
export const DIM_MS = 5000
/** How long a HUD and an Island flash stay. */
const HUD_MS = 1600
const FLASH_MS = 2500
/** Holding Ctrl or ⌘ alone this long shows the keyboard shortcuts. */
const HOLD_MS = 1000
/** How long the launch zoom (themes.css) and the unlock zoom take. */
const LAUNCH_MS = 600
/** The ways input can arrive; any of them keeps the screen awake. */
const INPUT_EVENTS = ['pointermove', 'pointerdown', 'keydown', 'wheel', 'touchstart'] as const

/** Alt+Shift and a letter (by its place on the keyboard, since Option changes the character on a Mac). */
const KEY_TARGETS: Partial<Record<string, Surface | 'lock'>> = {
  KeyH: 'home', KeyS: 'switcher', KeyC: 'control', KeyN: 'notifications', KeyL: 'lock',
}

const box = (r: DOMRect): Box => ({ left: r.left, top: r.top, right: r.right, bottom: r.bottom })
const folderLabel = (id: string) => FOLDERS.find(f => f.id === id)?.label ?? 'Files'

/** The first element matching `selector` that is laid out on screen. */
function shown(selector: string) {
  for (const el of document.querySelectorAll(selector)) {
    const r = el.getBoundingClientRect()
    if (r.width && r.height) return r
  }
  return null
}

/** The iPad's Chromium-based browsers can bend the backdrop with an SVG filter; others get plain glass. */
const lensCapable = () =>
  !!(navigator as Navigator & { userAgentData?: { brands?: Array<{ brand: string }> } }).userAgentData?.brands?.some(b => b.brand === 'Chromium')

/**
 * Everything the iPadOS / iOS theme adds on top of the app: the status bar (and on phones the
 * Dynamic Island), the floating tab bar, the dock, notification banners and Notification Center,
 * Control Center, Spotlight, the Files and Settings apps, the Home Screen with its widgets, the App
 * Switcher, the lock screen with Auto-Lock, alerts, HUDs and context menus, keyboard shortcuts and
 * the system gestures on touch screens. Rendered only while the theme is active; on unmount it
 * takes every attribute and property it set on the page back off. Sounds and the pointer come from
 * the effect preset (effects/ios.ts), which hears about all of this through emitChrome.
 */
export function IosShell({ view, onViewChange, onOpenAppearance }: IosShellProps) {
  const phone = useMediaQuery(PHONE_QUERY)
  const { effects, soundPick, setSound, setTheme } = useDesign()
  const wild = effects === 'wild'
  const prefs = useIosPrefs()
  const files = useGeneratedFiles()
  const now = useClock()
  const network = useNetwork()
  const mode = useAppMode()

  const [surface, setSurfaceState] = useState<Surface | null>(null)
  const [notes, setNotes] = useState<Note[]>([])
  const [banners, setBanners] = useState<string[]>([])
  const [alerts, setAlerts] = useState<Array<AlertSpec & { id: number }>>([])
  const [menu, setMenu] = useState<{ at: Point; title?: string; items: MenuItem[] } | null>(null)
  const [hud, setHud] = useState<Hud | null>(null)
  const [flash, setFlash] = useState<IslandFlash | null>(null)
  /** Quick Look: the files it pages through (by id, so deleted ones drop out) and the one shown. */
  const [quickLook, setQuickLook] = useState<{ ids: string[]; id: string } | null>(null)
  const [shortcuts, setShortcuts] = useState<'held' | 'open' | null>(null)
  const [lock, setLock] = useState<'awake' | 'dim' | 'locked'>('awake')
  const [torch, setTorch] = useState(false)
  const [busySince, setBusySince] = useState<number | null>(null)
  const [wizard, setWizard] = useState({ step: 1, action: '' })
  /** Files and Settings get a card once opened; any card closed in the switcher stays away until opened again. */
  const [opened, setOpened] = useState<Set<TabId>>(() => new Set<TabId>())
  const [closed, setClosed] = useState<Set<TabId>>(() => new Set<TabId>())

  // The settings may have changed since the theme last ran (another tab, a reset); read them afresh.
  useLayoutEffect(reloadIosPrefs, [])

  const setSurface = useCallback((next: Surface | null) => {
    setSurfaceState((current: Surface | null) => {
      if (current === next) return current
      if (next && next !== 'home' && next !== 'switcher') emitChrome('sheet-open')
      else if (current && current !== 'home' && current !== 'switcher') emitChrome('sheet-close')
      return next
    })
    if (next === 'files' || next === 'settings') {
      setOpened((o: Set<TabId>) => new Set([...o, next]))
      setClosed((c: Set<TabId>) => new Set([...c].filter(x => x !== next)))
    }
    if (next === 'files') setIosPrefs({ filesSeenAt: Date.now() })
  }, [])

  const flashTimer = useRef(0)
  const showFlash = useCallback((f: IslandFlash) => {
    setFlash(f)
    window.clearTimeout(flashTimer.current)
    flashTimer.current = window.setTimeout(() => setFlash(null), FLASH_MS)
  }, [])
  const hudTimer = useRef(0)
  const showHud = useCallback((h: Hud) => {
    setHud(h)
    window.clearTimeout(hudTimer.current)
    hudTimer.current = window.setTimeout(() => setHud(null), HUD_MS)
  }, [])
  useEffect(() => () => {
    window.clearTimeout(flashTimer.current)
    window.clearTimeout(hudTimer.current)
  }, [])

  // Appearance is the app's own panel, below the theme's sheets; whatever is open makes way for it.
  const appearance = useCallback(() => {
    setSurface(null)
    setMenu(null)
    onOpenAppearance()
  }, [setSurface, onOpenAppearance])

  const alertId = useRef(0)
  const alert = useCallback((a: AlertSpec) => setAlerts((list: Array<AlertSpec & { id: number }>) => [...list, { ...a, id: ++alertId.current }]), [])
  const dismissBanner = useCallback((id: string) => setBanners((ids: string[]) => ids.filter(x => x !== id)), [])

  const navigate = useCallback((next: View) => {
    setClosed((c: Set<TabId>) => new Set([...c].filter(x => x !== next)))
    if (next !== view) onViewChange(next)
  }, [view, onViewChange])

  const reply = useCallback((r: CommandReply) => {
    emitCommandResult(!r.error)
    if (r.error) showHud({ kind: 'text', text: r.text, error: true })
  }, [showHud])
  const wizardCommand = useWizardCommand(() => onViewChange('wizard'), reply)

  /** A notification arrives: kept for Notification Center, and shown as a banner unless Focus is on. */
  const notify = useCallback((note: Omit<Note, 'id' | 'at'>, sound: boolean) => {
    const full: Note = { ...note, id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, at: Date.now() }
    setNotes((list: Note[]) => [...list, full].slice(-50))
    const p = getIosPrefs()
    if (p.focus || !p.banners) return
    setBanners((ids: string[]) => [full.id, ...ids].slice(0, MAX_BANNERS))
    if (sound) emitChrome('banner')
  }, [])

  const silent = useCallback((on: boolean) => {
    setSound(on ? 'off' : 'on')
    if (phone) showFlash({ kind: 'silent', on })
    else showHud({ kind: 'silent', on })
  }, [phone, setSound, showFlash, showHud])

  const lockNow = useCallback(() => {
    setSurface(null)
    setMenu(null)
    setLock('locked')
    emitChrome('lock')
    showFlash({ kind: 'lock' })
  }, [setSurface, showFlash])

  const unlock = useCallback(() => {
    setLock('awake')
    setTorch(false)
    emitChrome('unlock')
    showFlash({ kind: 'unlock' })
    const root = document.documentElement
    root.classList.add('ios-unlocked')
    window.setTimeout(() => root.classList.remove('ios-unlocked'), LAUNCH_MS)
  }, [showFlash])

  /** Opens an app, zooming the page out of the icon that was pressed. */
  const launch = useCallback((app: AppId, from?: DOMRect) => {
    setMenu(null)
    if (from) {
      const root = document.documentElement
      root.style.setProperty('--ios-launch-x', `${from.left + from.width / 2}px`)
      root.style.setProperty('--ios-launch-y', `${from.top + from.height / 2}px`)
      root.classList.remove('ios-launching')
      void root.offsetWidth
      root.classList.add('ios-launching')
      window.setTimeout(() => root.classList.remove('ios-launching'), LAUNCH_MS)
    }
    switch (app) {
      case 'files':
      case 'settings':
        setSurface(app)
        return
      case 'verify':
        setSurface(null)
        navigate('wizard')
        wizardCommand.send({ type: 'start', action: 'verify' })
        return
      default:
        setSurface(null)
        navigate(app === 'sign' ? 'wizard' : app === 'analytics' ? 'dashboard' : 'about')
    }
  }, [navigate, setSurface, wizardCommand])

  const openFile = useCallback((f: StoredFile, list: StoredFile[] = [f]) => {
    setMenu(null)
    setQuickLook({ ids: list.map(x => x.id), id: f.id })
  }, [])

  const openNote = useCallback((n: Note) => {
    setBanners((ids: string[]) => ids.filter(id => id !== n.id))
    if (n.target === 'files') {
      setSurface('files')
      return
    }
    setSurface(null)
    navigate('wizard')
    window.setTimeout(() => document.querySelector('[data-result]')?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 50)
  }, [navigate, setSurface])

  const showDetails = useCallback(() => {
    const details = document.querySelector<HTMLDetailsElement>('.technical-details')
    if (details) details.open = true
    ;(details ?? document.querySelector('[data-result]'))?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [])

  // The latest values, for the listeners below that stay put.
  const lockRef = useRef(lock)
  const lockNowRef = useRef(lockNow)
  const viewRef = useRef(view)
  const wizardCommandRef = useRef(wizardCommand)
  useEffect(() => {
    lockRef.current = lock
    lockNowRef.current = lockNow
    viewRef.current = view
    wizardCommandRef.current = wizardCommand
  })

  // The wizard's requests, steps and results.
  useEffect(() => {
    const onSignal = (e: Event) => {
      const d = (e as CustomEvent<AppSignal>).detail
      if (d.type === 'busy') setBusySince(d.on ? Date.now() : null)
      else if (d.type === 'step') setWizard({ step: d.step, action: d.action })
      else if (d.type === 'outcome') {
        const verify = d.action === 'verify'
        const title = d.title ?? (d.kind === 'error' ? 'Something Went Wrong' : verify ? 'Verified' : 'Signed')
        // The outcome itself sounds (effects/ios.ts); its banner stays quiet.
        notify({ app: verify ? 'verify' : 'sign', kind: d.kind, title, body: d.message ?? '', target: 'result' }, false)
        if (d.kind !== 'info') {
          showFlash({
            kind: d.kind === 'success' ? 'ok' : d.kind === 'warning' ? 'warn' : 'fail',
            text: d.kind === 'success' ? (verify ? 'Verified' : 'Signed') : d.kind === 'warning' ? 'Warning' : 'Failed',
          })
        }
        if (d.kind === 'error' && getIosPrefs().alerts) {
          alert({
            title, message: d.message, glyph: 'x-circle',
            actions: [{ label: 'Details', run: showDetails }, { label: 'OK', style: 'default' }],
          })
        }
      }
    }
    const onGenerated = (e: Event) => {
      const { folder, name } = (e as CustomEvent<GeneratedFile>).detail
      notify({ app: 'files', kind: 'file', title: 'Saved to Files', body: `“${name}” is in ${folderLabel(folder)}.`, target: 'files' }, true)
      const from = shown('[data-result]') ?? new DOMRect(window.innerWidth / 2 - 20, window.innerHeight / 2 - 20, 40, 40)
      const to = shown('[data-ios-app=files]')
      if (to) emitChrome('fly', { from: box(from), to: box(to) })
    }
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    window.addEventListener(GENERATED_EVENT, onGenerated)
    return () => {
      window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
      window.removeEventListener(GENERATED_EVENT, onGenerated)
    }
  }, [notify, showFlash, alert, showDetails])

  // Keyboard shortcuts, and holding Ctrl or ⌘ to see them.
  useEffect(() => {
    let hold = 0
    const toggle = (s: Surface) => setSurfaceState((current: Surface | null) => {
      emitChrome(current === s ? 'sheet-close' : 'sheet-open')
      return current === s ? null : s
    })
    const onKey = (e: KeyboardEvent) => {
      window.clearTimeout(hold)
      if (lockRef.current === 'locked') return
      if ((e.key === 'Control' || e.key === 'Meta') && !e.repeat) {
        hold = window.setTimeout(() => setShortcuts((s: 'held' | 'open' | null) => s ?? 'held'), HOLD_MS)
        return
      }
      setShortcuts((s: 'held' | 'open' | null) => (s === 'held' ? null : s))
      if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === ' ' || e.key.toLowerCase() === 'k')) {
        e.preventDefault()
        toggle('spotlight')
        return
      }
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return
      const target = KEY_TARGETS[e.code]
      if (!target) return
      e.preventDefault()
      if (target === 'lock') lockNowRef.current()
      else toggle(target)
    }
    const onUp = (e: KeyboardEvent) => {
      if (e.key !== 'Control' && e.key !== 'Meta') return
      window.clearTimeout(hold)
      setShortcuts((s: 'held' | 'open' | null) => (s === 'held' ? null : s))
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('keyup', onUp)
    window.addEventListener('blur', onUp as unknown as EventListener)
    return () => {
      window.clearTimeout(hold)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('keyup', onUp)
      window.removeEventListener('blur', onUp as unknown as EventListener)
    }
  }, [])
  // Auto-Lock: at Wild, after the chosen time without input and never during a request; dims first.
  const autoLocks = wild && prefs.autoLock > 0 && busySince === null
  // Dimming must not restart the countdown, so the effect below hears only locked or not.
  const locked = lock === 'locked'
  const lastInput = useRef(0)
  useEffect(() => {
    const onInput = () => {
      lastInput.current = Date.now()
      if (lockRef.current === 'dim') setLock('awake')
    }
    for (const type of INPUT_EVENTS) window.addEventListener(type, onInput, { passive: true, capture: true })
    return () => {
      for (const type of INPUT_EVENTS) window.removeEventListener(type, onInput, { capture: true })
    }
  }, [])
  useEffect(() => {
    if (!autoLocks || locked) return
    // The countdown starts now at the latest: on the theme starting, a request ending, or unlocking.
    lastInput.current = Math.max(lastInput.current, Date.now() - 1000)
    const id = window.setInterval(() => {
      const idle = Date.now() - lastInput.current
      if (idle >= prefs.autoLock * 1000) lockNowRef.current()
      else if (idle >= prefs.autoLock * 1000 - DIM_MS && lockRef.current === 'awake') {
        setLock('dim')
        emitChrome('dim')
      }
    }, 500)
    return () => window.clearInterval(id)
  }, [autoLocks, prefs.autoLock, locked])

  // The battery: a chime and the Island when the charger goes in, and one warning when it runs low.
  const warned = useRef(false)
  const battery = useBattery((b, before) => {
    if (b.level === null) return
    if (before.level !== null && !before.charging && b.charging) {
      emitChrome('charge')
      if (phone) showFlash({ kind: 'charging', level: b.level })
    }
    if (!b.charging && b.level <= LOW_BATTERY && !warned.current) {
      warned.current = true
      emitChrome('battery')
      alert({ title: 'Low Battery', message: `${Math.round(b.level * 100)}% of battery remaining`, actions: [{ label: 'Close', style: 'cancel' }] })
    }
  })

  // System gestures on touch screens: down from the top corners, up from the bottom, in from the left.
  useEffect(() => {
    let start: (Point & { t: number }) | null = null
    const onDown = (e: PointerEvent) => {
      start = e.pointerType === 'touch' ? { x: e.clientX, y: e.clientY, t: performance.now() } : null
    }
    const onUp = (e: PointerEvent) => {
      if (!start || lockRef.current === 'locked') return
      const swipe = edgeSwipe(start, { x: e.clientX, y: e.clientY }, window.innerWidth, window.innerHeight, performance.now() - start.t)
      start = null
      if (!swipe) return
      if (swipe === 'back') {
        if (!anyModalOpen() && viewRef.current === 'wizard') wizardCommandRef.current.send({ type: 'back' })
        return
      }
      if (anyModalOpen() && swipe !== 'home') return
      setSurface(swipe)
    }
    window.addEventListener('pointerdown', onDown, { passive: true })
    window.addEventListener('pointerup', onUp, { passive: true })
    return () => {
      window.removeEventListener('pointerdown', onDown)
      window.removeEventListener('pointerup', onUp)
    }
  }, [setSurface])

  // Tilt parallax: the wallpaper leans with the phone.
  useEffect(() => {
    if (!prefs.tilt) return
    const root = document.documentElement
    const onTilt = (e: DeviceOrientationEvent) => {
      const clamp = (v: number) => Math.max(-1, Math.min(1, v))
      root.style.setProperty('--ios-tilt-x', clamp((e.gamma ?? 0) / 30).toFixed(3))
      root.style.setProperty('--ios-tilt-y', clamp(((e.beta ?? 45) - 45) / 30).toFixed(3))
    }
    window.addEventListener('deviceorientation', onTilt)
    return () => {
      window.removeEventListener('deviceorientation', onTilt)
      root.style.removeProperty('--ios-tilt-x')
      root.style.removeProperty('--ios-tilt-y')
    }
  }, [prefs.tilt])

  // What the page needs to know for its styles, and what must not be reached behind a full screen.
  const page = phone && (surface === 'files' || surface === 'settings')
  const screen = lock === 'locked' ? 'lock' : surface === 'home' || surface === 'switcher' ? surface : page ? 'page' : null
  useLayoutEffect(() => {
    const root = document.documentElement
    const set = (name: string, value: string | null) => (value === null ? root.removeAttribute(name) : root.setAttribute(name, value))
    set('data-ios-screen', screen)
    set('data-ios-dim', lock === 'dim' && autoLocks ? '' : null)
    set('data-ios-transparency', prefs.reduceTransparency ? 'reduced' : null)
    set('data-ios-lens', lensCapable() ? '' : null)
    root.style.setProperty('--ios-brightness', String(prefs.brightness))
    const app = document.querySelector('ix-application')
    app?.toggleAttribute('inert', screen !== null)
  }, [screen, lock, autoLocks, prefs.reduceTransparency, prefs.brightness])
  useLayoutEffect(() => () => {
    const root = document.documentElement
    for (const name of ['data-ios-screen', 'data-ios-dim', 'data-ios-transparency', 'data-ios-lens']) root.removeAttribute(name)
    for (const prop of ['--ios-brightness', '--ios-launch-x', '--ios-launch-y']) root.style.removeProperty(prop)
    root.classList.remove('ios-launching', 'ios-unlocked')
    document.querySelector('ix-application')?.removeAttribute('inert')
  }, [])

  const quickActions = (app: AppId, at: Point, extra: MenuItem[] = []) => {
    const quick: Record<AppId, MenuItem[]> = {
      sign: [
        { label: 'Sign a Document', glyph: 'pen', run: () => { navigate('wizard'); wizardCommand.send({ type: 'start', action: 'sign' }) } },
        { label: 'Verify a Signature', glyph: 'seal', run: () => launch('verify') },
      ],
      verify: [
        { label: 'Verify a Signature', glyph: 'seal', run: () => launch('verify') },
        { label: 'Start Over', glyph: 'recover', run: () => { navigate('wizard'); wizardCommand.send({ type: 'reset' }) } },
      ],
      analytics: [{ label: 'Open Analytics', glyph: 'chart', run: () => launch('analytics') }],
      files: [
        ...files.files.filter(f => !f.deleted).sort((a, b) => b.created - a.created).slice(0, 3)
          .map((f): MenuItem => ({ label: f.name, glyph: 'doc', run: () => openFile(f) })),
        { label: 'Recently Deleted', glyph: 'trash', run: () => launch('files') },
      ],
      settings: [
        { label: 'Theme & Appearance', glyph: 'photo', run: appearance },
        { label: 'Lock Screen', glyph: 'lock', run: lockNow },
      ],
      about: [
        { label: 'About', glyph: 'info', run: () => launch('about') },
        { label: 'Keyboard Shortcuts', glyph: 'keyboard', run: () => setShortcuts('open') },
      ],
    }
    emitChrome('long-press')
    setMenu({ at, items: [...quick[app], ...extra] })
  }

  const run = (action: SearchAction) => {
    switch (action.type) {
      case 'view': setSurface(null); navigate(action.view); return
      case 'wizard': setSurface(null); navigate('wizard'); wizardCommand.send(action.command); return
      case 'surface': setSurface(action.surface); return
      case 'lock': lockNow(); return
      case 'appearance': appearance(); return
      case 'shortcuts': setShortcuts('open'); return
      case 'leave':
        alert({
          title: 'Leave iPadOS Theme?', message: 'The app goes back to the layout and colors you chose before.',
          actions: [{ label: 'Cancel', style: 'cancel' }, { label: 'Leave', style: 'destructive', run: () => setTheme('none') }],
        })
        return
      case 'file': {
        const f = files.files.find(x => x.id === action.id)
        if (f) openFile(f)
        return
      }
      case 'toggle':
        emitChrome('switch')
        if (action.setting === 'dark') themeSwitcher.setColorSchema(mode === 'dark' ? 'light' : 'dark')
        else if (action.setting === 'sound') silent(soundPick === 'on')
        else if (action.setting === 'focus') setIosPrefs({ focus: !prefs.focus })
        else if (action.setting === 'transparency') setIosPrefs({ reduceTransparency: !prefs.reduceTransparency })
        else setIosPrefs({ pointer: !prefs.pointer })
    }
  }

  const unseen = files.files.filter(f => !f.deleted && f.created > prefs.filesSeenAt).length
  const badges: Partial<Record<AppId, number>> = { files: unseen }
  const recent = files.files.filter(f => !f.deleted).sort((a, b) => b.created - a.created)
  const current: TabId = phone && (surface === 'files' || surface === 'settings') ? surface : phone && view === 'about' ? 'settings' : view
  const switcherCards: SwitcherCard[] = [
    { id: 'wizard' as const, app: wizard.action === 'verify' ? 'verify' as const : 'sign' as const, title: 'Sign / Verify', subtitle: `${wizard.action ? `${wizard.action === 'verify' ? 'Verify' : 'Sign'} · ` : ''}Step ${wizard.step} of 5` },
    { id: 'dashboard' as const, app: 'analytics' as const, title: 'Analytics' },
    { id: 'about' as const, app: 'about' as const, title: 'About' },
    { id: 'files' as const, app: 'files' as const, title: 'Files' },
    { id: 'settings' as const, app: 'settings' as const, title: 'Settings' },
  ].filter(c => (c.id === 'files' || c.id === 'settings' ? opened.has(c.id) : true) && (!closed.has(c.id) || c.id === current))
  const lookFiles = quickLook
    ? quickLook.ids.map(id => files.files.find(f => f.id === id)).filter((f): f is StoredFile => !!f && !f.deleted)
    : []
  const visibleBanners = banners.map(id => notes.find(n => n.id === id)).filter((n): n is Note => !!n)

  return (
    <>
      <svg className="ios-defs" width="0" height="0" aria-hidden="true" focusable="false">
        <filter id="ios-lens" x="0" y="0" width="100%" height="100%" colorInterpolationFilters="sRGB">
          <feTurbulence type="fractalNoise" baseFrequency="0.006 0.009" numOctaves="2" seed="7" result="noise" />
          <feGaussianBlur in="noise" stdDeviation="3" result="soft" />
          <feDisplacementMap in="SourceGraphic" in2="soft" scale="34" xChannelSelector="R" yChannelSelector="G" />
        </filter>
      </svg>
      <IosStatusBar
        phone={phone} now={now} battery={battery} network={network} busy={busySince !== null} focus={prefs.focus}
        silent={soundPick !== 'on'} onNotifications={() => setSurface('notifications')} onControl={() => setSurface('control')}
      />
      {phone && <IosIsland busySince={busySince} action={wizard.action} flash={flash} />}
      <IosTabBar
        phone={phone} current={current} filesBadge={unseen} onSearch={() => setSurface('spotlight')}
        onSelect={tab => {
          if (tab === 'files' || tab === 'settings') setSurface(tab)
          else {
            setSurface(null)
            navigate(tab)
          }
        }}
      />
      {!phone && (
        <IosDock badges={badges} recents={recent.slice(0, 3)} autoHide={prefs.dockHide} onLaunch={launch} onMenu={(app, at) => quickActions(app, at)} onFile={openFile} />
      )}
      <button
        type="button" className="ios-home-indicator" aria-label="Home Screen" aria-keyshortcuts="Alt+Shift+H"
        onClick={() => setSurface(surface === 'home' ? null : 'home')}
        onContextMenu={e => {
          e.preventDefault()
          setSurface('switcher')
        }}
      >
        <i />
      </button>

      {surface === 'files' && (
        <IosFiles
          files={files} phone={phone} presentation={phone ? 'page' : 'sheet'} onClose={() => setSurface(null)}
          onQuickLook={openFile} onMenu={(at, title, items) => setMenu({ at, title, items })} onAlert={alert}
        />
      )}
      {surface === 'settings' && (
        <IosSettings
          phone={phone} presentation={phone ? 'page' : 'sheet'} onClose={() => setSurface(null)} onSilent={silent} onAlert={alert}
          onAppearance={appearance} onShortcuts={() => setShortcuts('open')}
          onAbout={() => {
            setSurface(null)
            navigate('about')
          }}
        />
      )}
      {surface === 'control' && (
        <IosControlCenter
          network={network} onSilent={silent} onLock={lockNow} onClose={() => setSurface(null)}
          onAppearance={appearance}
          onSettings={() => setSurface('settings')} onHome={() => setSurface('home')}
        />
      )}
      {surface === 'notifications' && (
        <IosNotificationCenter
          notes={notes} now={now} onOpen={openNote} onClose={() => setSurface(null)}
          onClear={ids => setNotes((list: Note[]) => list.filter(n => !ids.includes(n.id)))}
          onClearAll={() => alert({
            title: 'Clear All Notifications?', actions: [{ label: 'Cancel', style: 'cancel' }, { label: 'Clear', style: 'destructive', run: () => setNotes([]) }],
          })}
        />
      )}
      {surface === 'spotlight' && <IosSpotlight files={recent} onRun={run} onClose={() => setSurface(null)} />}
      {surface === 'home' && (
        <IosHome
          now={now} recent={recent} last={[...notes].reverse().find(n => n.target === 'result') ?? null} badges={badges}
          onLaunch={launch} onMenu={quickActions} onFile={openFile} onSearch={() => setSurface('spotlight')} onClose={() => setSurface(null)}
        />
      )}
      {surface === 'switcher' && (
        <IosSwitcher
          cards={switcherCards} current={current} onClose={() => setSurface(null)}
          onOpen={id => {
            if (id === 'files' || id === 'settings') setSurface(id)
            else {
              setSurface(null)
              navigate(id)
            }
          }}
          onCloseCard={id => {
            if (id === 'wizard') {
              if (busySince !== null) return false
              wizardCommand.send({ type: 'reset' })
            }
            setClosed((c: Set<TabId>) => new Set([...c, id]))
            return true
          }}
        />
      )}
      {quickLook && lookFiles.length > 0 && (
        <IosQuickLook
          files={lookFiles} id={quickLook.id} onShow={id => setQuickLook({ ...quickLook, id })} onClose={() => setQuickLook(null)}
          onDelete={f => {
            // Deleting moves on to the next file, or the one before when it was the last.
            const i = lookFiles.findIndex(x => x.id === f.id)
            const next = lookFiles[i + 1] ?? lookFiles[i - 1]
            files.setDeleted(f.id, true)
            setQuickLook(next ? { ...quickLook, id: next.id } : null)
          }}
        />
      )}

      <IosBanners notes={visibleBanners} onOpen={openNote} onDismiss={dismissBanner} />
      {hud && <IosHud hud={hud} />}
      {lock === 'locked' && (
        <IosLockScreen
          now={now} notes={notes} busySince={busySince} action={wizard.action} wild={wild} torch={torch}
          onTorch={() => {
            setTorch(!torch)
            emitChrome('switch')
          }}
          onCamera={() => emitChrome('camera')} onUnlock={unlock} onOpenNote={openNote}
        />
      )}
      {torch && <div className="ios-torch" aria-hidden="true" />}
      {menu && <IosMenu at={menu.at} title={menu.title} items={menu.items} onClose={() => setMenu(null)} />}
      {alerts[0] && <IosAlert key={alerts[0].id} alert={alerts[0]} onDone={() => setAlerts((list: Array<AlertSpec & { id: number }>) => list.slice(1))} />}
      {shortcuts && <IosShortcuts held={shortcuts === 'held'} onClose={() => setShortcuts(null)} />}
      <div className="ios-dimmer" aria-hidden="true" />
    </>
  )
}
