import { useEffect, useId, useRef, type ReactNode } from 'react'
import { IxIconButton, IxTypography } from '@siemens/ix-react'
import { COLORS, EFFECT_LEVELS, LAYOUTS, SOUND_LEVELS, THEMES, findTheme } from './designs'
import { Thumbnail } from './Thumbnail'
import { useDesign, type DesignPreview } from './useDesign'
import { usePreviewIntent, type PreviewIntent } from './usePreviewIntent'

type Option<T extends string> = { id: T; label: string; description: string }

interface OptionGroupProps<T extends string> {
  label: string
  /** Which part of the design these options set; also the key previewed on hover or focus. Without it, nothing is previewed. */
  part?: keyof DesignPreview
  options: ReadonlyArray<Option<T>>
  value: T | null
  onChange: (id: T) => void
  /** Draws a preview card for an option; without it the options are compact chips. */
  thumbnail?: (id: T) => ReactNode
  disabled?: boolean
  hint?: string
  intent: PreviewIntent
}

/**
 * A labelled radio group. Resting on an option (pointer or keyboard focus) tries it on the whole
 * page without storing it, leaving puts the current choice back, and clicking keeps it; see
 * usePreviewIntent for the timing. The description under the label follows whatever is shown.
 */
function OptionGroup<T extends string>({ label, part, options, value, onChange, thumbnail, disabled, hint, intent }: OptionGroupProps<T>) {
  const { preview } = useDesign()
  const id = useId()
  const previewed = part ? preview?.[part] as T | undefined : undefined
  const previews = !disabled && part
  const shown = options.find(o => o.id === (previewed ?? value))

  return (
    <section className="sheet-section">
      <IxTypography format="h5" id={id}>{label}</IxTypography>
      <IxTypography className="sheet-description" format="label-sm" textColor="soft">
        {disabled && hint ? hint : shown?.description ?? '\u00a0'}
      </IxTypography>
      <div className={thumbnail ? 'preview-grid' : 'chips'} role="radiogroup" aria-labelledby={id}>
        {options.map(o => (
          <button
            key={o.id}
            type="button"
            role="radio"
            className={thumbnail ? 'preview-card' : 'chip'}
            aria-checked={o.id === value}
            disabled={disabled}
            title={o.description}
            onClick={() => {
              intent.cancel()
              onChange(o.id)
            }}
            onMouseEnter={e => previews && intent.enter(e, { [previews]: o.id })}
            onMouseLeave={e => previews && intent.leave(e)}
            onFocus={() => previews && intent.focus({ [previews]: o.id })}
            onBlur={() => previews && intent.blur()}
          >
            {thumbnail?.(o.id)}
            <span className="preview-label">{o.label}</span>
          </button>
        ))}
      </div>
    </section>
  )
}

interface AppearanceSheetProps {
  open: boolean
  onClose: () => void
}

/**
 * Every appearance choice in one place: theme, animation, layout and colors, each option with a
 * miniature of the app in that look and a live preview on hover or focus. On phones it is a bottom
 * sheet; on wider screens a panel under the header's Appearance button. While a theme is active,
 * colors are disabled because the theme brings its own, and the layout is chosen for that theme.
 */
export function AppearanceSheet({ open, onClose }: AppearanceSheetProps) {
  const {
    layout, colors, theme, themeLayouts, setLayout, setColors, setTheme, effectsPick, setEffects, soundPick, setSound,
    setPreview,
  } = useDesign()
  const sheetRef = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const intent = usePreviewIntent(setPreview, open)

  useEffect(() => {
    if (!open) return
    const previous = document.activeElement as HTMLElement | null
    sheetRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      // A preview never outlives the panel.
      setPreview(null)
      if (previous?.isConnected) previous.focus()
    }
  }, [open, onClose, setPreview])

  if (!open) return null
  // Everything below describes what is chosen, not what is being previewed.
  const chosenTheme = THEMES.find(t => t.id === theme)
  const themed = theme !== 'none'
  const chosenLayout = themed ? themeLayouts[theme] ?? findTheme(theme).layout : layout
  // Under a theme, its own layout is marked so the user can find the way back to it.
  const layouts = themed
    ? LAYOUTS.map(l => (l.id === chosenTheme?.layout ? { ...l, label: `${l.label} (theme)` } : l))
    : LAYOUTS
  const hint = 'Set Theme to None to choose this yourself.'
  const soundHint = !chosenTheme?.sound
    ? `Only ${THEMES.filter(t => t.sound).map(t => t.label).join(', ')} make sound.`
    : 'Turn Animation on to hear the theme.'
  // Layout thumbnails show the user's colors, or the chosen theme's look while one is on.
  const look = themed ? { theme } : { colors }

  return (
    <div className="sheet-backdrop" onClick={onClose}>
      <div
        ref={sheetRef}
        className="sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onClick={e => e.stopPropagation()}
      >
        <div className="sheet-head">
          <IxTypography format="h4" id={titleId}>Appearance</IxTypography>
          <IxIconButton icon="close" variant="subtle-tertiary" aria-label="Close" title="Close" onClick={onClose} />
        </div>
        <OptionGroup intent={intent}
          label="Theme" part="theme" options={THEMES} value={theme} onChange={setTheme}
          thumbnail={id => {
            const def = THEMES.find(t => t.id === id)
            return id === 'none'
              ? <Thumbnail layout={layout} colors={colors} />
              : <Thumbnail layout={themeLayouts[id] ?? def?.layout ?? 'standard'} theme={id} />
          }}
        />
        <OptionGroup intent={intent} label="Animation" part="effects" options={EFFECT_LEVELS} value={effectsPick} onChange={setEffects} />
        <OptionGroup intent={intent}
          label="Sound" options={SOUND_LEVELS} value={soundPick} onChange={setSound}
          disabled={!chosenTheme?.sound || effectsPick === 'off'} hint={soundHint}
        />
        <OptionGroup intent={intent}
          label="Layout" part="layout" options={layouts} value={chosenLayout} onChange={setLayout}
          thumbnail={id => <Thumbnail layout={id} {...look} />}
        />
        <OptionGroup intent={intent}
          label="Colors" part="colors" options={COLORS} value={themed ? null : colors} onChange={setColors}
          thumbnail={id => <Thumbnail layout={chosenLayout} colors={id} />}
          disabled={themed} hint={hint}
        />
      </div>
    </div>
  )
}
