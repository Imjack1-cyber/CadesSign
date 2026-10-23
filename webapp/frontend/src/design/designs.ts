/**
 * Selectable UI designs, picked on three axes. Layout and colors combine freely; a theme is a complete
 * look (palette, shapes, fonts, backdrop and an optional animated effect) that overrides the colors while
 * active. It starts on its own layout, which the user can change for each theme.
 * Everything keeps Siemens IX "classic" and its components; designs only override IX tokens
 * (see src/styles/designs/) and, for some layouts, the page arrangement.
 */

export type LayoutId = 'standard' | 'compact' | 'comfort' | 'focus'
export type ColorId = 'soft' | 'classic' | 'petrol' | 'slate' | 'sand' | 'contrast'
export type ThemeId =
  | 'none' | 'bubblegum' | 'chocolate' | 'snowing' | 'raining' | 'starry' | 'synthwave'
  | 'terminal' | 'blueprint' | 'notebook' | 'sakura' | 'deepsea' | 'autumn'
  | 'notary' | 'vitals' | 'zen' | 'win95' | 'ios' | 'rocket' | 'minecraft'
export type EffectKind =
  | 'snow' | 'rain' | 'bubbles' | 'sprinkles' | 'petals' | 'stars' | 'plankton' | 'leaves' | 'matrix' | 'sparks'
  | 'ink' | 'ecg' | 'sand' | 'desktop' | 'glass' | 'boost' | 'blocks'
/**
 * 'calm' runs the particles only; 'wild' adds bursts, cursor, keyboard and result reactions and
 * animated theme decoration.
 */
export type EffectLevel = 'off' | 'calm' | 'wild'
export type SoundPick = 'off' | 'on'

export interface LayoutDef {
  id: LayoutId
  label: string
  description: string
  /** 'sidebar' uses the IX application menu; 'topnav' replaces it with tabs below the header. */
  nav: 'sidebar' | 'topnav'
  /** Expand the side menu on start (sidebar layout only). */
  menuStartExpanded?: boolean
  /** Show the wizard steps as a vertical rail beside the step body. */
  stepsVertical?: boolean
}

export interface ColorDef {
  id: ColorId
  label: string
  description: string
}

export interface ThemeDef {
  id: ThemeId
  label: string
  description: string
  /** The layout the theme builds on; the theme's own CSS adds shape and font on top. */
  layout: LayoutId
  /**
   * Most themes are designed for one color mode and pin IX to it while active; 'system' brings a
   * palette for both and follows the user's own light / dark choice instead.
   */
  mode: 'light' | 'dark' | 'system'
  effect?: EffectKind
  /** The effect also makes sound when the user turns it on. */
  sound?: boolean
}

export const LAYOUTS: readonly LayoutDef[] = [
  { id: 'standard', label: 'Standard', description: 'Side menu, default spacing', nav: 'sidebar' },
  { id: 'compact', label: 'Compact', description: 'Dense spacing, wider page', nav: 'sidebar' },
  { id: 'comfort', label: 'Comfort', description: 'Rounded, airy, elevated cards', nav: 'sidebar', menuStartExpanded: true },
  { id: 'focus', label: 'Focus', description: 'Top tabs, vertical step rail', nav: 'topnav', stepsVertical: true },
]

export const COLORS: readonly ColorDef[] = [
  { id: 'soft', label: 'Soft', description: 'Calm, desaturated IX palette' },
  { id: 'classic', label: 'IX Classic', description: 'Stock Siemens IX colors' },
  { id: 'petrol', label: 'Petrol', description: 'Siemens petrol accent' },
  { id: 'slate', label: 'Slate', description: 'Indigo accent, cool neutrals' },
  { id: 'sand', label: 'Sand', description: 'Warm neutrals, copper accent' },
  { id: 'contrast', label: 'High contrast', description: 'Stronger borders, text and focus' },
]

export const THEMES: readonly ThemeDef[] = [
  { id: 'none', label: 'None', description: 'Pick the layout and colors yourself', layout: 'standard', mode: 'dark' },
  { id: 'bubblegum', label: 'Bubblegum', description: 'Jelly cards, rainbow headings, poppable bubbles', layout: 'comfort', mode: 'light', effect: 'bubbles' },
  { id: 'chocolate', label: 'Chocolate', description: 'Melting cards, caramel drips, sprinkle splats', layout: 'comfort', mode: 'dark', effect: 'sprinkles' },
  { id: 'snowing', label: 'Snowing', description: 'Blizzard, creeping frost, drifts and snowballs', layout: 'standard', mode: 'light', effect: 'snow' },
  { id: 'raining', label: 'Raining', description: 'Downpour, droplets on the glass, lightning', layout: 'standard', mode: 'dark', effect: 'rain' },
  { id: 'starry', label: 'Starry Night', description: 'Turning swirls, shooting stars, constellations', layout: 'focus', mode: 'dark', effect: 'stars' },
  { id: 'synthwave', label: 'Synthwave', description: 'Endless neon grid, glitches, VHS tracking', layout: 'focus', mode: 'dark', effect: 'sparks' },
  { id: 'terminal', label: 'Retro Terminal', description: 'Boot log, clacky keys, status line, degauss and matrix rain', layout: 'compact', mode: 'dark', effect: 'matrix', sound: true },
  { id: 'blueprint', label: 'Blueprint', description: 'Self-drawing lines, compasses, crosshair', layout: 'compact', mode: 'dark' },
  { id: 'notebook', label: 'Notebook', description: 'Live margin doodles, swaying taped notes', layout: 'comfort', mode: 'light' },
  { id: 'sakura', label: 'Sakura', description: 'Petal storm, swaying branch, ripple pond', layout: 'comfort', mode: 'light', effect: 'petals' },
  { id: 'deepsea', label: 'Deep Sea', description: 'Sonar pings, schooling fish, plankton that glows when stirred', layout: 'standard', mode: 'dark', effect: 'plankton', sound: true },
  { id: 'autumn', label: 'Autumn', description: 'Gusts, leaf piles, firelight flicker', layout: 'standard', mode: 'light', effect: 'leaves' },
  { id: 'notary', label: "Notary's Desk", description: 'Typewriter keys, correction tape, rubber stamps and wax', layout: 'comfort', mode: 'light', effect: 'ink', sound: true },
  { id: 'vitals', label: 'Vital Signs', description: 'Typing raises the pulse; errors flatline, click to shock', layout: 'focus', mode: 'dark', effect: 'ecg', sound: true },
  { id: 'zen', label: 'Zen Garden', description: 'Rake the sand, drop pebbles as you type, raked rings', layout: 'standard', mode: 'light', effect: 'sand', sound: true },
  { id: 'win95', label: 'Windows 95', description: 'Start menu, beveled everything, dial-up, tada and the chord', layout: 'standard', mode: 'light', effect: 'desktop', sound: true },
  { id: 'ios', label: 'iPadOS / iOS', description: 'Liquid Glass, Dynamic Island, Control Center, lock screen and keyboard clicks', layout: 'focus', mode: 'system', effect: 'glass', sound: true },
  { id: 'rocket', label: 'Rocket League', description: 'Boost trails, goal explosions, demolitions and a Sideswipe match on the scoreboard', layout: 'standard', mode: 'dark', effect: 'boost', sound: true },
  { id: 'minecraft', label: 'Minecraft', description: 'Mine blocks, XP orbs, creepers on errors and two minigames: Mining Run and Creeper Run', layout: 'standard', mode: 'light', effect: 'blocks', sound: true },
]

export const DEFAULT_LAYOUT: LayoutId = 'standard'
export const DEFAULT_COLORS: ColorId = 'soft'
export const DEFAULT_THEME: ThemeId = 'none'
export const DEFAULT_EFFECTS: EffectLevel = 'wild'
export const DEFAULT_SOUND: SoundPick = 'off'

export const EFFECT_LEVELS: ReadonlyArray<{ id: EffectLevel; label: string; description: string }> = [
  { id: 'off', label: 'Effects off', description: 'Static theme, no motion' },
  { id: 'calm', label: 'Calm', description: 'Background particles only' },
  { id: 'wild', label: 'Wild', description: 'Bursts, cursor play, animated decoration' },
]

export const SOUND_LEVELS: ReadonlyArray<{ id: SoundPick; label: string; description: string }> = [
  { id: 'off', label: 'Silent', description: 'No sound' },
  { id: 'on', label: 'Sound', description: 'Clacks, bells and beeps from the theme, made in the browser' },
]

const finder = <T extends { id: string }>(list: readonly T[], fallback: string) =>
  (id: string | null | undefined): T => list.find(d => d.id === id) ?? list.find(d => d.id === fallback)!

export const findLayout = finder(LAYOUTS, DEFAULT_LAYOUT)
export const findColors = finder(COLORS, DEFAULT_COLORS)
export const findTheme = finder(THEMES, DEFAULT_THEME)

export const isLayoutId = (id: string | null): id is LayoutId => LAYOUTS.some(d => d.id === id)
export const isColorId = (id: string | null): id is ColorId => COLORS.some(d => d.id === id)
export const isThemeId = (id: string | null): id is ThemeId => THEMES.some(d => d.id === id)

/** Layouts the user picked for individual themes, in place of the theme's own. */
export type ThemeLayouts = Partial<Record<ThemeId, LayoutId>>

/**
 * What is actually applied: a theme's layout (the user's pick for that theme, else its own) replaces the
 * picked one, and its palette replaces the colors.
 */
export interface ActiveDesign {
  layout: LayoutDef
  colors: ColorDef | null
  theme: ThemeDef | null
}

export function resolveDesign(layout: LayoutId, colors: ColorId, theme: ThemeId, themeLayouts: ThemeLayouts = {}): ActiveDesign {
  const t = findTheme(theme)
  return t.id === 'none'
    ? { layout: findLayout(layout), colors: findColors(colors), theme: null }
    : { layout: findLayout(themeLayouts[t.id] ?? t.layout), colors: null, theme: t }
}
