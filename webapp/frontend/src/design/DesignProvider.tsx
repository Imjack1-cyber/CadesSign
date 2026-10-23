import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { themeSwitcher, type ThemeVariant } from '@siemens/ix'
import {
  type ColorId, type EffectLevel, type LayoutId, type SoundPick, type ThemeId, type ThemeLayouts,
  DEFAULT_EFFECTS, DEFAULT_SOUND, EFFECT_LEVELS, findColors, findLayout, findTheme, isColorId, isLayoutId, isThemeId,
  resolveDesign,
} from './designs'
import { DesignContext, type DesignPreview } from './useDesign'
import { useMediaQuery } from './useMediaQuery'

const KEYS = {
  layout: 'cades-layout',
  colors: 'cades-colors',
  theme: 'cades-theme',
  /** JSON object of theme id → layout id, for themes the user moved off their own layout. */
  themeLayouts: 'cades-theme-layouts',
  effects: 'cades-effects',
  sound: 'cades-sound',
  /** Single-design key from before layout and colors were split; migrated once, then removed. */
  legacy: 'cades-design',
} as const

function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function writeStored(key: string, value: string | null) {
  try {
    if (value === null) window.localStorage.removeItem(key)
    else window.localStorage.setItem(key, value)
  } catch {
    // Storage can be unavailable (private mode, blocked site data); the choice then lasts for this page only.
  }
}

interface Picks {
  layout: LayoutId
  colors: ColorId
  theme: ThemeId
  themeLayouts: ThemeLayouts
}

/** Keeps only known theme → layout pairs, so a stale or hand-edited value cannot break the page. */
function readThemeLayouts(): ThemeLayouts {
  const result: ThemeLayouts = {}
  try {
    const parsed: unknown = JSON.parse(readStored(KEYS.themeLayouts) ?? '{}')
    if (parsed && typeof parsed === 'object') {
      for (const [theme, layout] of Object.entries(parsed)) {
        if (isThemeId(theme) && theme !== 'none' && typeof layout === 'string' && isLayoutId(layout)) result[theme] = layout
      }
    }
  } catch {
    // Not JSON: every theme keeps its own layout.
  }
  return result
}

function readPicks(): Picks {
  const legacy = readStored(KEYS.legacy)
  if (legacy !== null) {
    writeStored(KEYS.legacy, null)
    if (isLayoutId(legacy)) writeStored(KEYS.layout, legacy)
    if (isColorId(legacy)) writeStored(KEYS.colors, legacy)
  }
  return {
    layout: findLayout(readStored(KEYS.layout)).id,
    colors: findColors(readStored(KEYS.colors)).id,
    theme: findTheme(readStored(KEYS.theme)).id,
    themeLayouts: readThemeLayouts(),
  }
}

function readEffects(): EffectLevel {
  const stored = readStored(KEYS.effects)
  // 'on' is the stored value from when effects were a plain switch.
  if (stored === 'on') return 'wild'
  return EFFECT_LEVELS.find(l => l.id === stored)?.id ?? DEFAULT_EFFECTS
}

const readSound = (): SoundPick => (readStored(KEYS.sound) === 'on' ? 'on' : DEFAULT_SOUND)

const setOrDelete = (root: HTMLElement, name: 'appLayout' | 'appColors' | 'appTheme' | 'appEffects', value: string | undefined) => {
  if (value === undefined) delete root.dataset[name]
  else root.dataset[name] = value
}

/**
 * Applies the chosen design as `data-app-layout`, `data-app-colors` and `data-app-theme` on <html> and
 * mirrors the resolved IX color mode as `data-app-mode`, so design stylesheets need one block per mode
 * even when IX follows the OS ("system"). While a theme is active `data-app-colors` is removed (the
 * theme brings its own palette) and the IX color schema is pinned to the theme's mode, unless the
 * theme is made for both. A preview
 * overrides the picks in all of this until it is cleared or committed, without touching storage.
 */
export function DesignProvider({ children }: { children: ReactNode }) {
  const [picks, setPicks] = useState<Picks>(readPicks)
  const [effectsPick, setEffectsPick] = useState<EffectLevel>(readEffects)
  const [soundPick, setSoundPick] = useState<SoundPick>(readSound)
  // A look being tried on (hovered or focused in the Appearance panel); never stored.
  const [preview, setPreview] = useState<DesignPreview | null>(null)
  const reducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)')
  const effects: EffectLevel = reducedMotion ? 'off' : preview?.effects ?? effectsPick
  const active = useMemo(() => {
    const theme = preview?.theme ?? picks.theme
    // A previewed layout under a theme is tried on as that theme's layout.
    const themeLayouts = preview?.layout ? { ...picks.themeLayouts, [theme]: preview.layout } : picks.themeLayouts
    return resolveDesign(preview?.layout ?? picks.layout, preview?.colors ?? picks.colors, theme, themeLayouts)
  }, [picks, preview])
  const sound = soundPick === 'on' && effects !== 'off' && !!active.theme?.sound
  // The schema the user had before a theme pinned it, restored when the theme is turned off.
  const schemaBeforeTheme = useRef<ThemeVariant | null>(null)

  useLayoutEffect(() => {
    const root = document.documentElement
    delete root.dataset.appDesign
    setOrDelete(root, 'appLayout', active.layout.id)
    setOrDelete(root, 'appColors', active.colors?.id)
    setOrDelete(root, 'appTheme', active.theme?.id ?? 'none')

    // A theme for both modes leaves the user's own light / dark choice alone, like no theme.
    if (active.theme && active.theme.mode !== 'system') {
      schemaBeforeTheme.current ??= themeSwitcher.getColorSchema()
      themeSwitcher.setColorSchema(active.theme.mode)
    } else if (schemaBeforeTheme.current) {
      themeSwitcher.setColorSchema(schemaBeforeTheme.current)
      schemaBeforeTheme.current = null
    }
  }, [active])

  useLayoutEffect(() => {
    // Theme stylesheets gate their UI animation on this, so 'calm' and 'off' keep the page still.
    setOrDelete(document.documentElement, 'appEffects', active.theme ? effects : undefined)
  }, [active, effects])

  useEffect(() => {
    const root = document.documentElement
    root.dataset.appMode = themeSwitcher.getMode()
    const disposable = themeSwitcher.themeChanged.on(({ mode }) => {
      root.dataset.appMode = mode
    })
    return () => disposable?.dispose()
  }, [])

  // Choosing commits exactly what was being previewed, so the preview ends here.
  const pick = <K extends 'layout' | 'colors' | 'theme'>(key: K) => (id: Picks[K]) => {
    writeStored(KEYS[key], id)
    setPicks((p: Picks) => ({ ...p, [key]: id }))
    setPreview(null)
  }

  // Under a theme the layout is remembered for that theme; picking the theme's own layout forgets it again.
  const setLayout = (id: LayoutId) => {
    const { theme } = picks
    if (theme === 'none') return pick('layout')(id)
    const { [theme]: _, ...others } = picks.themeLayouts
    const themeLayouts: ThemeLayouts = id === findTheme(theme).layout ? others : { ...others, [theme]: id }
    writeStored(KEYS.themeLayouts, Object.keys(themeLayouts).length ? JSON.stringify(themeLayouts) : null)
    setPicks((p: Picks) => ({ ...p, themeLayouts }))
    setPreview(null)
  }

  const setEffects = (level: EffectLevel) => {
    writeStored(KEYS.effects, level)
    setEffectsPick(level)
    setPreview(null)
  }

  const setSound = (pick: SoundPick) => {
    writeStored(KEYS.sound, pick)
    setSoundPick(pick)
  }

  return (
    <DesignContext.Provider
      value={{
        ...picks,
        active,
        setLayout,
        setColors: pick('colors'),
        setTheme: pick('theme'),
        effectsPick,
        effects,
        setEffects,
        soundPick,
        sound,
        setSound,
        preview,
        setPreview,
      }}
    >
      {children}
    </DesignContext.Provider>
  )
}
