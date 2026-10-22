import { useCallback, useRef, useState, type ReactNode } from 'react'
import {
  IxApplication,
  IxApplicationHeader,
  IxButton,
  IxContent,
  IxDropdownItem,
  IxIconButton,
  IxMenu,
  IxMenuAbout,
  IxMenuItem,
  IxTabItem,
  IxTabs,
} from '@siemens/ix-react'
import { themeSwitcher } from '@siemens/ix'
import { AboutContent } from './AboutContent'
import { AppearanceSheet } from '../../design/AppearanceSheet'
import { ThemeEffects } from '../../design/ThemeEffects'
import { Win95Shell } from '../../design/Win95Shell'
import { useDesign } from '../../design/useDesign'
import { PHONE_QUERY, useMediaQuery } from '../../design/useMediaQuery'

export type View = 'wizard' | 'dashboard' | 'about'

interface AppShellProps {
  view: View
  onViewChange: (view: View) => void
  children: ReactNode
}

const TOP_NAV: Array<{ view: View; label: string; icon: string }> = [
  { view: 'wizard', label: 'Sign / Verify', icon: 'ink-pen' },
  { view: 'dashboard', label: 'Analytics', icon: 'chart-diagrams' },
  { view: 'about', label: 'About', icon: 'about' },
]

export function AppShell({ view, onViewChange, children }: AppShellProps) {
  const { active } = useDesign()
  const phone = useMediaQuery(PHONE_QUERY)
  const [sheetOpen, setSheetOpen] = useState(false)
  const closeSheet = useCallback(() => setSheetOpen(false), [])
  const menuRef = useRef<HTMLIxMenuElement>(null)
  const topNav = active.layout.nav === 'topnav'
  const modePinned = active.theme !== null
  const modeTitle = modePinned ? 'The theme sets light or dark mode' : 'Toggle light / dark theme'
  // What the one Appearance control shows: the theme, or the layout and colors combined.
  const summary = active.theme ? active.theme.label : `${active.layout.label} · ${active.colors?.label}`

  return (
    <>
      <ThemeEffects />
      <AppearanceSheet open={sheetOpen} onClose={closeSheet} />
      {active.theme?.id === 'win95' && (
        <Win95Shell
          view={view}
          onViewChange={onViewChange}
          onOpenAppearance={() => setSheetOpen(true)}
          // About is a page in the top-nav layout and an overlay of the side menu otherwise.
          onOpenAbout={() => (topNav ? onViewChange('about') : void menuRef.current?.toggleAbout(true))}
        />
      )}
      {/* Remounting on a layout change lets IxApplication re-detect whether it has a menu. */}
      <IxApplication key={active.layout.nav}>
        <IxApplicationHeader name="CAdES B-LT Signer & Verifier">
          {/* Layout, colors, theme and animation are all chosen in one Appearance panel. On phones IX
              folds the header into its "…" menu, where labelled items read better than buttons. */}
          {phone ? (
            <>
              <IxDropdownItem icon="palette" label="Appearance…" onClick={() => setSheetOpen(true)} />
              <IxDropdownItem
                icon="light-dark"
                label="Light / dark mode"
                title={modeTitle}
                disabled={modePinned}
                onClick={() => themeSwitcher.toggleMode()}
              />
            </>
          ) : (
            <>
              <IxButton
                variant="subtle-tertiary"
                icon="palette"
                aria-label={`Appearance: ${summary}`}
                title="Appearance: layout, colors and theme"
                aria-haspopup="dialog"
                aria-expanded={sheetOpen}
                onClick={() => setSheetOpen(true)}
              >
                {summary}
              </IxButton>
              <IxIconButton
                icon="light-dark"
                variant="subtle-tertiary"
                aria-label="Toggle light / dark theme"
                title={modeTitle}
                disabled={modePinned}
                onClick={() => themeSwitcher.toggleMode()}
              />
            </>
          )}
        </IxApplicationHeader>

        {!topNav && (
          <IxMenu
            ref={menuRef}
            applicationName="CAdES B-LT"
            applicationDescription="Sign and verify CAdES Baseline documents"
            startExpanded={active.layout.menuStartExpanded}
          >
            <IxMenuItem icon="ink-pen" active={view === 'wizard'} onClick={() => onViewChange('wizard')}>
              Sign / Verify
            </IxMenuItem>
            <IxMenuItem icon="chart-diagrams" active={view === 'dashboard'} onClick={() => onViewChange('dashboard')}>
              Analytics
            </IxMenuItem>

            <IxMenuAbout label="About" activeTabKey="overview">
              <AboutContent />
            </IxMenuAbout>
          </IxMenu>
        )}

        <IxContent>
          {topNav && (
            <nav className="top-nav" aria-label="Main">
              <IxTabs activeTabKey={view}>
                {/* Icons only on phones, so all three tabs fit without IX's overflow menu. */}
                {TOP_NAV.map(t => (
                  <IxTabItem
                    key={t.view} tabKey={t.view} icon={t.icon} aria-label={t.label} title={t.label}
                    onClick={() => onViewChange(t.view)}
                  >
                    {phone ? null : t.label}
                  </IxTabItem>
                ))}
              </IxTabs>
            </nav>
          )}
          {children}
        </IxContent>
      </IxApplication>
    </>
  )
}
