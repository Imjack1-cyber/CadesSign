import { createContext, useContext } from 'react'
import {
  type ActiveDesign, type ColorId, type EffectLevel, type LayoutId, type SoundPick, type ThemeId,
  DEFAULT_COLORS, DEFAULT_LAYOUT, DEFAULT_THEME, resolveDesign,
} from './designs'

/** Options tried on without choosing them: they apply to the page but are never stored. */
export type DesignPreview = Partial<{ layout: LayoutId; colors: ColorId; theme: ThemeId; effects: EffectLevel }>

export interface DesignContextValue {
  /** The user's picks; layout and colors are kept while a theme overrides them. */
  layout: LayoutId
  colors: ColorId
  theme: ThemeId
  /** What is applied right now, preview included. */
  active: ActiveDesign
  setLayout: (id: LayoutId) => void
  setColors: (id: ColorId) => void
  setTheme: (id: ThemeId) => void
  /** The user's pick for animated theme effects. */
  effectsPick: EffectLevel
  /** What runs: the pick, or 'off' when the OS asks for reduced motion. */
  effects: EffectLevel
  setEffects: (level: EffectLevel) => void
  /** The user's pick for theme sound. */
  soundPick: SoundPick
  /** Whether sound plays: picked, the active theme makes sound, and effects are running. */
  sound: boolean
  setSound: (pick: SoundPick) => void
  /** The look being previewed, if any; `active` and `effects` already include it. */
  preview: DesignPreview | null
  setPreview: (preview: DesignPreview | null) => void
}

export const DesignContext = createContext<DesignContextValue>({
  layout: DEFAULT_LAYOUT,
  colors: DEFAULT_COLORS,
  theme: DEFAULT_THEME,
  active: resolveDesign(DEFAULT_LAYOUT, DEFAULT_COLORS, DEFAULT_THEME),
  setLayout: () => {},
  setColors: () => {},
  setTheme: () => {},
  effectsPick: 'off',
  effects: 'off',
  setEffects: () => {},
  soundPick: 'off',
  sound: false,
  setSound: () => {},
  preview: null,
  setPreview: () => {},
})

export const useDesign = (): DesignContextValue => useContext(DesignContext)
