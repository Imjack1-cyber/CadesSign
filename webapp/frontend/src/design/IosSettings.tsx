import { useId, useState, type ReactNode } from 'react'
import { themeSwitcher, type ThemeVariant } from '@siemens/ix'
import { EFFECT_LEVELS } from './designs'
import type { AlertSpec } from './IosAlert'
import { AppIcon, Glyph, type GlyphName, RowIcon } from './IosIcons'
import { useAppMode } from './iosDevice'
import { APPS, AUTO_LOCK, MIN_BRIGHTNESS, setIosPrefs, useIosPrefs, type Wallpaper, WALLPAPERS } from './iosPrefs'
import { IosSheet } from './IosSheet'
import { emitChrome } from './signals'
import { useDesign } from './useDesign'

type Page = 'root' | 'focus' | 'notifications' | 'sounds' | 'display' | 'autolock' | 'wallpaper' | 'home' | 'accessibility' | 'general'

const TITLES: Record<Page, string> = {
  root: 'Settings', focus: 'Focus', notifications: 'Notifications', sounds: 'Sounds & Haptics', display: 'Display & Brightness',
  autolock: 'Auto-Lock', wallpaper: 'Wallpaper', home: 'Home Screen & Dock', accessibility: 'Accessibility', general: 'General',
}

const ROOT_ROWS: ReadonlyArray<ReadonlyArray<{ page: Page; glyph: GlyphName; color: string }>> = [
  [{ page: 'focus', glyph: 'moon', color: '#5e5ce6' }, { page: 'notifications', glyph: 'bell', color: '#ff3b30' }, { page: 'sounds', glyph: 'speaker', color: '#ff2d55' }],
  [
    { page: 'display', glyph: 'sun', color: '#007aff' }, { page: 'wallpaper', glyph: 'photo', color: '#32ade6' },
    { page: 'home', glyph: 'grid', color: '#5856d6' }, { page: 'accessibility', glyph: 'hand', color: '#007aff' },
  ],
  [{ page: 'general', glyph: 'gear', color: '#8e8e93' }],
]

const WALLPAPER_NAMES: Record<Wallpaper, string> = { bloom: 'Bloom', tide: 'Tide', graphite: 'Graphite' }
const lockText = (s: number) => (s ? `${s / 60} Minute${s > 60 ? 's' : ''}` : 'Never')

function Group({ header, footer, children }: { header?: string; footer?: ReactNode; children: ReactNode }) {
  const id = useId()
  return (
    <section className="ios-group" aria-labelledby={header ? id : undefined}>
      {header && <h3 id={id}>{header}</h3>}
      <ul className="ios-inset-group">{children}</ul>
      {footer && <p className="ios-group-foot">{footer}</p>}
    </section>
  )
}

function LinkRow({ glyph, color, label, value, onClick, current }: { glyph?: GlyphName; color?: string; label: string; value?: string; onClick: () => void; current?: boolean }) {
  return (
    <li>
      <button type="button" className="ios-row" onClick={onClick} aria-current={current ? 'page' : undefined}>
        {glyph && <RowIcon name={glyph} color={color ?? '#8e8e93'} />}
        <span className="ios-row-label">{label}</span>
        {value && <span className="ios-row-value">{value}</span>}
        <Glyph name="chevron-right" size={14} />
      </button>
    </li>
  )
}

/** A row with a UISwitch; it ticks as it flips. */
function SwitchRow({ label, checked, onChange, disabled }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <li>
      <button
        type="button" role="switch" aria-checked={checked} disabled={disabled} className="ios-row"
        onClick={() => {
          onChange(!checked)
          emitChrome('switch')
        }}
      >
        <span className="ios-row-label">{label}</span>
        <span className="ios-switch" aria-hidden="true"><i /></span>
      </button>
    </li>
  )
}

/** One choice of a list that picks one, ticked when chosen. */
function ChoiceRow({ label, selected, onClick }: { label: string; selected: boolean; onClick: () => void }) {
  return (
    <button type="button" role="radio" aria-checked={selected} className="ios-row" onClick={onClick}>
      <span className="ios-row-label">{label}</span>
      {selected && <span className="ios-row-check" aria-hidden="true">✓</span>}
    </button>
  )
}

/** Rows of which one is chosen. */
function Choices({ label, className, children }: { label: string; className?: string; children: ReactNode }) {
  return <li className={className ?? 'ios-radio-list'}><div role="radiogroup" aria-label={label}>{children}</div></li>
}

function SliderRow({ label, value, min, onChange, low, high }: { label: string; value: number; min: number; onChange: (v: number) => void; low: GlyphName; high: GlyphName }) {
  return (
    <li className="ios-row ios-row--slider">
      <Glyph name={low} size={16} />
      <input
        type="range" className="ios-range" aria-label={label} min={Math.round(min * 100)} max={100} value={Math.round(value * 100)}
        style={{ '--value': (value - min) / (1 - min) } as React.CSSProperties}
        onChange={e => onChange(Number(e.target.value) / 100)}
      />
      <Glyph name={high} size={20} />
    </li>
  )
}

interface IosSettingsProps {
  phone: boolean
  presentation: 'sheet' | 'page'
  onClose: () => void
  onAppearance: () => void
  onAbout: () => void
  onShortcuts: () => void
  onSilent: (on: boolean) => void
  onAlert: (alert: AlertSpec) => void
}

/** Asks for the motion sensors where the browser wants permission first (iOS Safari), from the tap that turns tilt on. */
async function allowTilt(): Promise<boolean> {
  const D = (window as Window & { DeviceOrientationEvent?: { requestPermission?: () => Promise<string> } }).DeviceOrientationEvent
  if (!D) return false
  if (!D.requestPermission) return true
  try {
    return (await D.requestPermission()) === 'granted'
  } catch {
    return false
  }
}

/**
 * The Settings app: everything the iPadOS theme lets you choose, in grouped inset lists. Each row
 * pushes its page (with a back button to where you were); on iPad the list stays as a sidebar
 * beside the page. It also holds the way out: Leave iPadOS Theme.
 */
export function IosSettings({ phone, presentation, onClose, onAppearance, onAbout, onShortcuts, onSilent, onAlert }: IosSettingsProps) {
  const [stack, setStack] = useState<Page[]>(phone ? ['root'] : ['root', 'general'])
  const prefs = useIosPrefs()
  const { soundPick, effects, effectsPick, setEffects, setTheme } = useDesign()
  const mode = useAppMode()
  const [schema, setSchema] = useState<ThemeVariant>(() => themeSwitcher.getColorSchema())
  const page = stack[stack.length - 1]
  const push = (p: Page) => setStack(phone ? [...stack, p] : ['root', p])
  const back = () => setStack(stack.slice(0, -1))

  const setSchemaTo = (v: ThemeVariant) => {
    themeSwitcher.setColorSchema(v)
    setSchema(v)
  }

  const leave = () => onAlert({
    title: 'Leave iPadOS Theme?', message: 'The app goes back to the layout and colors you chose before. You can come back any time from Appearance.',
    actions: [{ label: 'Cancel', style: 'cancel' }, { label: 'Leave', style: 'destructive', run: () => setTheme('none') }],
  })

  const root = (
    <>
      <div className="ios-profile">
        <AppIcon app="sign" size={58} />
        <span><b>CAdES B-LT</b><span>Signer &amp; Verifier · iPadOS theme</span></span>
      </div>
      {ROOT_ROWS.map((rows, i) => (
        <Group key={i}>
          {rows.map(r => (
            <LinkRow
              key={r.page} glyph={r.glyph} color={r.color} label={TITLES[r.page]} current={!phone && page === r.page}
              value={r.page === 'focus' ? (prefs.focus ? 'On' : '') : undefined} onClick={() => push(r.page)}
            />
          ))}
        </Group>
      ))}
      <Group>
        <li><button type="button" className="ios-row ios-row--action" data-destructive onClick={leave}>Leave iPadOS Theme</button></li>
      </Group>
    </>
  )

  const pages: Record<Exclude<Page, 'root'>, ReactNode> = {
    focus: (
      <Group footer="While on, notifications are kept quietly in Notification Center, without banners or their sound. The moon shows in the status bar.">
        <SwitchRow label="Do Not Disturb" checked={prefs.focus} onChange={v => setIosPrefs({ focus: v })} />
      </Group>
    ),
    notifications: (
      <Group footer="Banners drop in from the top when a signature is made or checked, or a file is saved. Alerts ask for your attention when something fails.">
        <SwitchRow label="Show Banners" checked={prefs.banners} onChange={v => setIosPrefs({ banners: v })} />
        <SwitchRow label="Alerts for Failures" checked={prefs.alerts} onChange={v => setIosPrefs({ alerts: v })} />
      </Group>
    ),
    sounds: (
      <>
        <Group footer={effects === 'off' ? 'Sound plays only while animation is on (see Accessibility).' : 'Every sound is made in the browser as it plays.'}>
          <SwitchRow label="Sound" checked={soundPick === 'on'} onChange={v => onSilent(!v)} />
          <SliderRow label="Volume" value={prefs.volume} min={0} low="speaker-slash" high="speaker" onChange={v => setIosPrefs({ volume: v })} />
        </Group>
        <Group header="System Sounds & Haptics" footer="Haptics are short vibrations on taps, on devices that can.">
          <SwitchRow label="Keyboard Clicks" checked={prefs.keyClicks} onChange={v => setIosPrefs({ keyClicks: v })} />
          <SwitchRow label="Lock Sound" checked={prefs.lockSound} onChange={v => setIosPrefs({ lockSound: v })} />
          <SwitchRow label="Haptics" checked={prefs.haptics} onChange={v => setIosPrefs({ haptics: v })} />
        </Group>
      </>
    ),
    display: (
      <>
        <Group header="Appearance">
          <Choices label="Appearance" className="ios-appearance-pick">
            {(['light', 'dark'] as const).map(m => (
              <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setSchemaTo(m)}>
                <span className="ios-mini-phone" data-mode={m} aria-hidden="true"><i /><i /><i /></span>
                <span>{m === 'light' ? 'Light' : 'Dark'}</span>
                <span className="ios-radio" aria-hidden="true" />
              </button>
            ))}
          </Choices>
          <SwitchRow label="Automatic" checked={schema === 'system'} onChange={v => setSchemaTo(v ? 'system' : mode)} />
        </Group>
        <Group header="Brightness">
          <SliderRow label="Brightness" value={prefs.brightness} min={MIN_BRIGHTNESS} low="sun" high="sun" onChange={v => setIosPrefs({ brightness: v })} />
        </Group>
        <Group>
          <LinkRow label="Auto-Lock" value={lockText(prefs.autoLock)} onClick={() => setStack([...stack, 'autolock'])} />
        </Group>
      </>
    ),
    autolock: (
      <Group footer="The screen locks only at the Wild animation level, and never while signing or verifying. It dims a few seconds before.">
        <Choices label="Auto-Lock">
          {AUTO_LOCK.map(s => <ChoiceRow key={s} label={lockText(s)} selected={prefs.autoLock === s} onClick={() => setIosPrefs({ autoLock: s })} />)}
        </Choices>
      </Group>
    ),
    wallpaper: (
      <Group footer="The wallpaper shows through the glass, and fully on the Home and Lock Screens.">
        <Choices label="Wallpaper" className="ios-wallpaper-pick">
          {WALLPAPERS.map(w => (
            <button key={w} type="button" role="radio" aria-checked={prefs.wallpaper === w} onClick={() => setIosPrefs({ wallpaper: w })}>
              <span className="ios-wallpaper-swatch" data-wallpaper={w} aria-hidden="true" />
              <span>{WALLPAPER_NAMES[w]}</span>
            </button>
          ))}
        </Choices>
      </Group>
    ),
    home: (
      <>
        <Group footer={phone ? 'The dock is on iPad only.' : 'The dock slides away while you work, and comes back when the pointer reaches the bottom edge.'}>
          <SwitchRow label="Automatically Hide Dock" checked={prefs.dockHide} disabled={phone} onChange={v => setIosPrefs({ dockHide: v })} />
        </Group>
        <Group>
          <li>
            <button
              type="button" className="ios-row ios-row--action"
              onClick={() => onAlert({
                title: 'Reset Home Screen?', message: 'The Home Screen goes back to its original layout.',
                actions: [{ label: 'Cancel', style: 'cancel' }, { label: 'Reset', style: 'destructive', run: () => setIosPrefs({ home: [...APPS] }) }],
              })}
            >
              Reset Home Screen Layout
            </button>
          </li>
        </Group>
      </>
    ),
    accessibility: (
      <>
        <Group header="Motion" footer="Reduce Motion keeps the backgrounds moving but stops the bursts, slides and springs.">
          <SwitchRow label="Reduce Motion" checked={effectsPick !== 'wild'} onChange={v => setEffects(v ? 'calm' : 'wild')} />
          <Choices label="Animation">
            {EFFECT_LEVELS.map(l => <ChoiceRow key={l.id} label={l.id === 'off' ? 'Off' : l.label} selected={effectsPick === l.id} onClick={() => setEffects(l.id)} />)}
          </Choices>
        </Group>
        <Group header="Vision" footer="Reduce Transparency makes the glass solid, for more contrast.">
          <SwitchRow label="Reduce Transparency" checked={prefs.reduceTransparency} onChange={v => setIosPrefs({ reduceTransparency: v })} />
        </Group>
        <Group header="Pointer & Motion" footer="Pointer Control shows the round iPadOS pointer in place of the mouse cursor. Tilt Parallax moves the wallpaper as you tilt a phone.">
          <SwitchRow label="Pointer Control" checked={prefs.pointer} onChange={v => setIosPrefs({ pointer: v })} />
          <SwitchRow
            label="Tilt Parallax" checked={prefs.tilt}
            onChange={v => {
              if (!v) {
                setIosPrefs({ tilt: false })
                return
              }
              void allowTilt().then(ok => {
                if (ok) setIosPrefs({ tilt: true })
                else onAlert({ title: 'Motion Not Available', message: 'This browser did not allow access to the motion sensors.', actions: [{ label: 'OK' }] })
              })
            }}
          />
        </Group>
      </>
    ),
    general: (
      <>
        <Group>
          <LinkRow glyph="info" color="#ff9f0a" label="About" onClick={onAbout} />
          <LinkRow glyph="keyboard" color="#8e8e93" label="Keyboard Shortcuts" onClick={onShortcuts} />
        </Group>
        <Group footer="Theme, animation, layout and colors of the whole app.">
          <LinkRow glyph="photo" color="#af52de" label="Theme & Appearance" value="iPadOS / iOS" onClick={onAppearance} />
        </Group>
      </>
    ),
  }

  const header = (p: Page, i: number) => (
    <header className="ios-navbar">
      {i > (phone ? 0 : 1) && (
        <button type="button" className="ios-back" onClick={back}>
          <Glyph name="chevron-left" size={18} />
          {TITLES[stack[i - 1]]}
        </button>
      )}
      {presentation === 'sheet' && p === page && <button type="button" className="ios-text-button ios-navbar-done" onClick={onClose}>Done</button>}
      <h2 className="ios-large-title">{TITLES[p]}</h2>
    </header>
  )

  return (
    <IosSheet label="Settings" onClose={onClose} presentation={presentation} className="ios-settings">
      {phone ? (
        <div className="ios-settings-page" key={page} data-depth={stack.length}>
          {header(page, stack.length - 1)}
          {page === 'root' ? root : pages[page]}
        </div>
      ) : (
        <>
          <div className="ios-settings-side">
            {header('root', 0)}
            {root}
          </div>
          <div className="ios-settings-page" key={page}>
            {header(page, stack.length - 1)}
            {page !== 'root' && pages[page]}
          </div>
        </>
      )}
    </IosSheet>
  )
}
