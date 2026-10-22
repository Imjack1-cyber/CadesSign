import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, render, screen, fireEvent, within } from '@testing-library/react'
import { themeSwitcher } from '@siemens/ix'
import App from '../../App'
import { Wizard } from '../../components/wizard'
import { DesignProvider } from '../../design/DesignProvider'
import { PREVIEW_DELAY_MS, REVERT_DELAY_MS } from '../../design/usePreviewIntent'
import { SHUTDOWN_TIMES } from '../../design/win95Timing'
import { COLORS, EFFECT_LEVELS, LAYOUTS, THEMES } from '../../design/designs'

type Group = 'Theme' | 'Animation' | 'Sound' | 'Layout' | 'Colors'

/** Opens the Appearance panel (if it is not open yet) and returns it. */
const appearance = () => {
  if (!screen.queryByRole('dialog', { name: 'Appearance' })) {
    fireEvent.click(screen.getByRole('button', { name: /^Appearance/ }))
  }
  return screen.getByRole('dialog', { name: 'Appearance' })
}
const group = (name: Group) => within(appearance()).getByRole('radiogroup', { name })
const chip = (name: Group, label: string) => within(group(name)).getByRole('radio', { name: label })
const choose = (name: Group, label: string) => fireEvent.click(chip(name, label))
const root = () => document.documentElement.dataset

beforeEach(() => {
  window.localStorage.clear()
  window.history.replaceState(null, '', '#wizard')
  for (const key of ['appLayout', 'appColors', 'appTheme', 'appEffects', 'appDesign']) delete root()[key]
  vi.mocked(themeSwitcher.setColorSchema).mockClear()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('Appearance', () => {
  it('applies the defaults; one control holds every theme, animation level, layout and color', () => {
    render(<App />)
    expect(root().appLayout).toBe('standard')
    expect(root().appColors).toBe('soft')
    expect(root().appTheme).toBe('none')
    expect(root().appMode).toBe('light')
    expect(screen.queryAllByRole('menu')).toHaveLength(0)
    expect(screen.getByRole('button', { name: 'Appearance: Standard · Soft' })).toBeInTheDocument()

    expect(within(group('Theme')).getAllByRole('radio')).toHaveLength(THEMES.length)
    expect(within(group('Animation')).getAllByRole('radio')).toHaveLength(EFFECT_LEVELS.length)
    expect(within(group('Layout')).getAllByRole('radio')).toHaveLength(LAYOUTS.length)
    expect(within(group('Colors')).getAllByRole('radio')).toHaveLength(COLORS.length)
    expect(chip('Colors', 'Soft')).toHaveAttribute('aria-checked', 'true')
  })

  it('combines layout and colors independently and remembers both', () => {
    const { unmount } = render(<App />)
    choose('Layout', 'Compact')
    choose('Colors', 'Petrol')
    expect(root().appLayout).toBe('compact')
    expect(root().appColors).toBe('petrol')
    expect(window.localStorage.getItem('cades-layout')).toBe('compact')
    expect(window.localStorage.getItem('cades-colors')).toBe('petrol')

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Appearance: Compact · Petrol' })).toBeInTheDocument()

    unmount()
    render(<App />)
    expect(root().appLayout).toBe('compact')
    expect(root().appColors).toBe('petrol')
  })

  it('a theme overrides layout, colors and mode, and None restores them', () => {
    render(<App />)
    choose('Colors', 'Sand')
    choose('Theme', 'Starry Night')

    expect(root().appTheme).toBe('starry')
    expect(root().appLayout).toBe('focus')
    expect(root().appColors).toBeUndefined()
    expect(themeSwitcher.setColorSchema).toHaveBeenLastCalledWith('dark')
    expect(chip('Layout', 'Focus')).toHaveAttribute('aria-checked', 'true')
    expect(chip('Layout', 'Standard')).toBeDisabled()
    expect(chip('Colors', 'Sand')).toBeDisabled()
    expect(within(appearance()).getAllByText('Set Theme to None to choose this yourself.')).toHaveLength(2)
    expect(screen.getByRole('button', { name: 'Toggle light / dark theme' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Appearance: Starry Night' })).toBeInTheDocument()

    choose('Theme', 'None')
    expect(root().appTheme).toBe('none')
    expect(root().appLayout).toBe('standard')
    expect(root().appColors).toBe('sand')
    expect(themeSwitcher.setColorSchema).toHaveBeenLastCalledWith('system')
    expect(chip('Layout', 'Standard')).toBeEnabled()
  })

  it('a theme with an effect runs it on a canvas; the animation level picks how much', () => {
    render(<App />)
    choose('Theme', 'Snowing')
    const canvas = screen.getByTestId('theme-effects')
    expect(canvas.tagName).toBe('CANVAS')
    expect(canvas).toHaveAttribute('data-effect', 'snow')
    expect(root().appEffects).toBe('wild')

    choose('Animation', 'Calm')
    expect(screen.getByTestId('theme-effects')).toBeInTheDocument()
    expect(root().appEffects).toBe('calm')

    choose('Animation', 'Effects off')
    expect(screen.queryByTestId('theme-effects')).not.toBeInTheDocument()
    expect(root().appEffects).toBe('off')
    expect(window.localStorage.getItem('cades-effects')).toBe('off')

    choose('Theme', 'None')
    expect(root().appEffects).toBeUndefined()
  })

  describe('previews', () => {
    it('every theme, layout and color option shows a miniature in its own look', () => {
      render(<App />)
      for (const t of THEMES.filter(t => t.id !== 'none')) {
        const thumb = chip('Theme', t.label).querySelector('.thumb')
        expect(thumb).toHaveAttribute('data-theme', t.id)
        expect(thumb).toHaveAttribute('data-layout', t.layout)
      }
      expect(chip('Theme', 'None').querySelector('.thumb')).toHaveAttribute('data-colors', 'soft')
      for (const l of LAYOUTS) expect(chip('Layout', l.label).querySelector('.thumb')).toHaveAttribute('data-layout', l.id)
      for (const c of COLORS) expect(chip('Colors', c.label).querySelector('.thumb')).toHaveAttribute('data-colors', c.id)
      expect(within(group('Animation')).getAllByRole('radio').every(r => !r.querySelector('.thumb'))).toBe(true)
    })

    // Previews start after the pointer rests and end a moment after it leaves (usePreviewIntent).
    const wait = (ms: number) => act(() => { vi.advanceTimersByTime(ms) })
    const at = (x: number, y = 10) => ({ clientX: x, clientY: y })

    it('resting on a theme tries it on without choosing it; leaving puts everything back', () => {
      vi.useFakeTimers()
      render(<App />)
      choose('Colors', 'Sand')
      fireEvent.mouseEnter(chip('Theme', 'Synthwave'), at(10))
      wait(PREVIEW_DELAY_MS - 50)
      expect(root().appTheme).toBe('none')
      wait(50)
      expect(root().appTheme).toBe('synthwave')
      expect(root().appLayout).toBe('focus')
      expect(themeSwitcher.setColorSchema).toHaveBeenLastCalledWith('dark')
      expect(window.localStorage.getItem('cades-theme')).toBeNull()
      expect(within(appearance()).getByText('Endless neon grid, glitches, VHS tracking')).toBeInTheDocument()
      // The chosen theme is still None; only the page shows Synthwave.
      expect(chip('Theme', 'None')).toHaveAttribute('aria-checked', 'true')

      fireEvent.mouseLeave(chip('Theme', 'Synthwave'), at(400, 400))
      wait(REVERT_DELAY_MS)
      expect(root().appTheme).toBe('none')
      expect(root().appLayout).toBe('standard')
      expect(root().appColors).toBe('sand')
      expect(themeSwitcher.setColorSchema).toHaveBeenLastCalledWith('system')
    })

    it('sweeping across cards only previews the one the pointer stops on', () => {
      vi.useFakeTimers()
      render(<App />)
      fireEvent.mouseEnter(chip('Theme', 'Bubblegum'), at(10))
      wait(100)
      fireEvent.mouseLeave(chip('Theme', 'Bubblegum'), at(60))
      fireEvent.mouseEnter(chip('Theme', 'Chocolate'), at(60))
      wait(100)
      expect(root().appTheme).toBe('none')
      wait(PREVIEW_DELAY_MS)
      expect(root().appTheme).toBe('chocolate')
    })

    it('a layout change under a still pointer cannot switch to another theme', () => {
      vi.useFakeTimers()
      render(<App />)
      fireEvent.mouseMove(window, at(10))
      fireEvent.mouseEnter(chip('Theme', 'Synthwave'), at(10))
      wait(PREVIEW_DELAY_MS)
      expect(root().appTheme).toBe('synthwave')

      // The page reflowed and another card slid under the pointer, which has not moved.
      fireEvent.mouseLeave(chip('Theme', 'Synthwave'), at(10))
      fireEvent.mouseEnter(chip('Theme', 'Retro Terminal'), at(10))
      wait(PREVIEW_DELAY_MS + REVERT_DELAY_MS)
      expect(root().appTheme).toBe('synthwave')

      // Moving the pointer for real does switch.
      fireEvent.mouseMove(window, at(80))
      fireEvent.mouseEnter(chip('Theme', 'Retro Terminal'), at(80))
      wait(PREVIEW_DELAY_MS)
      expect(root().appTheme).toBe('terminal')
    })

    it('focusing previews too, and clicking keeps the previewed option', () => {
      vi.useFakeTimers()
      const { unmount } = render(<App />)
      fireEvent.focus(chip('Colors', 'Slate'))
      wait(PREVIEW_DELAY_MS)
      expect(root().appColors).toBe('slate')
      fireEvent.blur(chip('Colors', 'Slate'))
      wait(REVERT_DELAY_MS)
      expect(root().appColors).toBe('soft')

      fireEvent.focus(chip('Colors', 'Petrol'))
      wait(PREVIEW_DELAY_MS)
      fireEvent.click(chip('Colors', 'Petrol'))
      fireEvent.blur(chip('Colors', 'Petrol'))
      wait(REVERT_DELAY_MS)
      expect(root().appColors).toBe('petrol')
      unmount()
      render(<App />)
      expect(root().appColors).toBe('petrol')
    })

    it('disabled options do not preview, and closing the panel ends a preview', () => {
      vi.useFakeTimers()
      window.localStorage.setItem('cades-theme', 'sakura')
      render(<App />)
      fireEvent.mouseEnter(chip('Layout', 'Compact'), at(10))
      wait(PREVIEW_DELAY_MS)
      expect(root().appLayout).toBe('comfort')

      fireEvent.mouseEnter(chip('Theme', 'Raining'), at(50))
      wait(PREVIEW_DELAY_MS)
      expect(root().appTheme).toBe('raining')
      fireEvent.keyDown(window, { key: 'Escape' })
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      expect(root().appTheme).toBe('sakura')
    })
  })

  it('sound is off by default, only for themes that make it, and remembered', () => {
    render(<App />)
    expect(chip('Sound', 'Silent')).toHaveAttribute('aria-checked', 'true')
    expect(chip('Sound', 'Sound')).toBeDisabled()

    choose('Theme', 'Vital Signs')
    expect(chip('Sound', 'Sound')).toBeEnabled()
    choose('Sound', 'Sound')
    expect(window.localStorage.getItem('cades-sound')).toBe('on')
    expect(chip('Sound', 'Sound')).toHaveAttribute('aria-checked', 'true')

    choose('Animation', 'Effects off')
    expect(chip('Sound', 'Sound')).toBeDisabled()
    choose('Animation', 'Wild')
    choose('Theme', 'Sakura')
    expect(chip('Sound', 'Sound')).toBeDisabled()
  })

  it('a theme without particles still gets its decoration', () => {
    window.localStorage.setItem('cades-theme', 'blueprint')
    const { container } = render(<App />)
    expect(screen.queryByTestId('theme-effects')).not.toBeInTheDocument()
    expect(container.querySelector('.decor-drafting')).not.toBeNull()
  })

  it('no effects when the OS asks for reduced motion', () => {
    window.localStorage.setItem('cades-theme', 'raining')
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('reduce'), media: query, addEventListener: () => {}, removeEventListener: () => {},
    }))
    render(<App />)
    expect(root().appTheme).toBe('raining')
    expect(root().appEffects).toBe('off')
    expect(screen.queryByTestId('theme-effects')).not.toBeInTheDocument()
  })

  it('the old on/off effects switch maps "on" to wild', () => {
    window.localStorage.setItem('cades-effects', 'on')
    window.localStorage.setItem('cades-theme', 'starry')
    render(<App />)
    expect(root().appEffects).toBe('wild')
  })

  it.each([
    ['focus', 'focus', 'soft'],
    ['petrol', 'standard', 'petrol'],
  ])('migrates the old single design %s', (legacy, layout, colors) => {
    window.localStorage.setItem('cades-design', legacy)
    render(<App />)
    expect(root().appLayout).toBe(layout)
    expect(root().appColors).toBe(colors)
    expect(window.localStorage.getItem('cades-design')).toBeNull()
  })

  it('falls back to the defaults for unknown stored values', () => {
    window.localStorage.setItem('cades-layout', 'nope')
    window.localStorage.setItem('cades-colors', 'nope')
    window.localStorage.setItem('cades-theme', 'nope')
    render(<App />)
    expect(root().appLayout).toBe('standard')
    expect(root().appColors).toBe('soft')
    expect(root().appTheme).toBe('none')
  })

  it('Focus replaces the side menu with top tabs, including an About page', async () => {
    render(<App />)
    expect(screen.getByTestId('IxMenu')).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()

    choose('Layout', 'Focus')
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByTestId('IxMenu')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'About' }))
    expect(await screen.findByRole('heading', { name: 'About' })).toBeInTheDocument()
    expect(screen.getByRole('tabpanel', { name: 'Overview' })).toBeInTheDocument()
  })

  it('the About hash falls back to the wizard in sidebar layouts', () => {
    window.history.replaceState(null, '', '#about')
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Choose Action' })).toBeInTheDocument()
  })

  it('the wizard uses a vertical step rail in Focus on wide screens and still advances', () => {
    window.localStorage.setItem('cades-layout', 'focus')
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: !query.includes('reduce'), media: query, addEventListener: () => {}, removeEventListener: () => {},
    }))
    const { container } = render(<DesignProvider><Wizard /></DesignProvider>)
    expect(container.querySelector('.wizard-layout--vertical')).not.toBeNull()

    fireEvent.click(screen.getByRole('radio', { name: /Sign a document/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(screen.getByRole('heading', { name: 'Select Files' })).toBeInTheDocument()
  })

  describe('on a phone', () => {
    const stubPhone = () => vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('max-width: 40rem'), media: query, addEventListener: () => {}, removeEventListener: () => {},
    }))

    it('puts Appearance and light / dark as labelled items in the header menu', () => {
      stubPhone()
      render(<App />)
      expect(screen.queryByRole('button', { name: /^Appearance: / })).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Appearance…' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Light / dark mode' })).toBeEnabled()
    })

    it('the Appearance sheet sets the theme, disables layout and colors, and closes on Escape', () => {
      stubPhone()
      render(<App />)
      choose('Layout', 'Compact')
      expect(root().appLayout).toBe('compact')

      choose('Theme', 'Sakura')
      expect(root().appTheme).toBe('sakura')
      expect(chip('Theme', 'Sakura')).toHaveAttribute('aria-checked', 'true')
      expect(chip('Layout', 'Compact')).toBeDisabled()
      expect(chip('Colors', 'Soft')).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Light / dark mode' })).toBeDisabled()

      fireEvent.keyDown(window, { key: 'Escape' })
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    it('Focus tabs show icons only but keep their names', () => {
      stubPhone()
      window.localStorage.setItem('cades-layout', 'focus')
      render(<App />)
      const about = screen.getByRole('tab', { name: 'About' })
      expect(about).toBeEmptyDOMElement()
    })
  })
})

describe('Windows 95 taskbar', () => {
  const start = () => screen.getByRole('button', { name: 'Start' })
  const startMenu = () => screen.queryByRole('menu', { name: 'Start' })
  const win95 = () => {
    window.localStorage.setItem('cades-theme', 'win95')
    return render(<App />)
  }

  it('shows only with the theme, and goes away with None', () => {
    render(<App />)
    expect(screen.queryByRole('toolbar', { name: 'Taskbar' })).not.toBeInTheDocument()
    choose('Theme', 'Windows 95')
    expect(screen.getByRole('toolbar', { name: 'Taskbar' })).toBeInTheDocument()
    choose('Theme', 'None')
    expect(screen.queryByRole('toolbar', { name: 'Taskbar' })).not.toBeInTheDocument()
  })

  it('Start opens a keyboard menu; Escape closes it and returns to Start', () => {
    win95()
    fireEvent.click(start())
    expect(start()).toHaveAttribute('aria-expanded', 'true')
    expect(document.activeElement).toHaveAccessibleName('Sign / Verify')
    fireEvent.keyDown(startMenu()!, { key: 'ArrowDown' })
    expect(document.activeElement).toHaveAccessibleName('Analytics')
    fireEvent.keyDown(startMenu()!, { key: 'End' })
    expect(document.activeElement).toHaveAccessibleName('Shut Down…')
    fireEvent.keyDown(startMenu()!, { key: 'Escape' })
    expect(startMenu()).not.toBeInTheDocument()
    expect(document.activeElement).toBe(start())
  })

  it('Ctrl+Esc opens Start, and its items navigate and open Settings', () => {
    win95()
    fireEvent.keyDown(window, { key: 'Escape', ctrlKey: true })
    expect(startMenu()).toBeInTheDocument()
    fireEvent.click(screen.getByRole('menuitem', { name: 'Analytics' }))
    expect(window.location.hash).toBe('#dashboard')
    expect(startMenu()).not.toBeInTheDocument()

    fireEvent.click(start())
    fireEvent.keyDown(startMenu()!, { key: 's' })
    expect(screen.getByRole('dialog', { name: 'Appearance' })).toBeInTheDocument()
  })

  it('the tray speaker turns sound on and off', () => {
    win95()
    const speaker = screen.getByRole('button', { name: 'Sound' })
    expect(speaker).toHaveAttribute('aria-pressed', 'false')
    fireEvent.click(speaker)
    expect(window.localStorage.getItem('cades-sound')).toBe('on')
    expect(speaker).toHaveAttribute('aria-pressed', 'true')
  })

  const shutDown = () => {
    fireEvent.click(start())
    fireEvent.click(screen.getByRole('menuitem', { name: 'Shut Down…' }))
    return screen.getByRole('dialog', { name: 'Shut Down Windows' })
  }
  const wait = (ms: number) => act(() => { vi.advanceTimersByTime(ms) })

  it('Shut Down asks first; No, or Escape, goes back to the desktop', () => {
    win95()
    const dialog = shutDown()
    expect(within(dialog).getByRole('radio', { name: 'Shut down the computer?' })).toHaveFocus()
    fireEvent.keyDown(dialog, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Shut Down Windows' })).not.toBeInTheDocument()
    expect(start()).toHaveFocus()
    fireEvent.click(within(shutDown()).getByRole('button', { name: 'No' }))
    expect(screen.queryByRole('dialog', { name: 'Shut Down Windows' })).not.toBeInTheDocument()
  })

  it('shutting down waits on the safe-to-turn-off screen, and a key starts the theme again', () => {
    vi.useFakeTimers()
    win95()
    fireEvent.click(within(shutDown()).getByRole('button', { name: 'Yes' }))
    expect(screen.getByRole('status')).toHaveTextContent(/shuts down/)
    wait(SHUTDOWN_TIMES.shutting)
    expect(screen.getByRole('status')).toHaveTextContent(/safe to turn off/)
    wait(10_000)
    expect(screen.getByRole('status')).toHaveTextContent(/safe to turn off/)
    fireEvent.keyDown(window, { key: 'x' })
    expect(screen.getByRole('status')).toHaveTextContent('Starting CAdES 95')
    wait(SHUTDOWN_TIMES.post)
    expect(screen.getByRole('status', { name: 'Starting CAdES 95' })).toBeInTheDocument()
    wait(SHUTDOWN_TIMES.splash)
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(root().appTheme).toBe('win95')
  })

  it('the third choice leaves the theme', () => {
    vi.useFakeTimers()
    win95()
    const dialog = shutDown()
    fireEvent.click(within(dialog).getByRole('radio', { name: 'Leave the Windows 95 theme?' }))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Yes' }))
    wait(SHUTDOWN_TIMES.shutting)
    expect(root().appTheme).toBe('none')
    expect(screen.queryByRole('toolbar', { name: 'Taskbar' })).not.toBeInTheDocument()
  })
})
