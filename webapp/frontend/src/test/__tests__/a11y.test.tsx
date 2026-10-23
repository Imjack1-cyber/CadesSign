import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { axe } from 'vitest-axe'
import { Wizard } from '../../components/wizard'
import { Dashboard } from '../../components/dashboard/Dashboard'
import App from '../../App'

const seriousViolations = async (container: Element) =>
  (await axe(container)).violations.filter(v => v.impact === 'critical' || v.impact === 'serious')

beforeEach(() => {
  globalThis.fetch = vi.fn(() => Promise.resolve(new Response(JSON.stringify([
    { id: 1, timestamp: '2026-01-01 10:00:00', action: 'SIGN', signature_level: 'LT', packaging: 'DETACHED', digest: 'SHA256', used_tsa: true },
  ]), { status: 200 }))) as any
})

describe('Accessibility (axe-core)', () => {
  it('Wizard renders with no serious axe violations', async () => {
    const { container } = render(<Wizard />)
    expect(await seriousViolations(container)).toHaveLength(0)
  })

  it('Focus layout with the About page renders with no serious axe violations', async () => {
    window.localStorage.setItem('cades-layout', 'focus')
    window.history.replaceState(null, '', '#about')
    try {
      const { container } = render(<App />)
      expect(screen.getByRole('heading', { name: 'About' })).toBeInTheDocument()
      expect(await seriousViolations(container)).toHaveLength(0)
    } finally {
      window.localStorage.removeItem('cades-layout')
      window.history.replaceState(null, '', '#wizard')
    }
  })

  it('A theme with an animated effect adds no serious axe violations', async () => {
    window.localStorage.setItem('cades-theme', 'starry')
    try {
      const { container } = render(<App />)
      expect(screen.getByTestId('theme-effects')).toBeInTheDocument()
      expect(await seriousViolations(container)).toHaveLength(0)
    } finally {
      window.localStorage.removeItem('cades-theme')
    }
  })

  it('The phone Appearance sheet has no serious axe violations', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('max-width: 40rem'), media: query, addEventListener: () => {}, removeEventListener: () => {},
    }))
    try {
      const { container } = render(<App />)
      fireEvent.click(screen.getByRole('button', { name: 'Appearance…' }))
      expect(screen.getByRole('dialog', { name: 'Appearance' })).toBeInTheDocument()
      expect(await seriousViolations(container)).toHaveLength(0)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  describe('iPadOS / iOS theme', () => {
    /** Each test runs axe over the whole app several times, once per surface opened. */
    const AXE_PASSES_MS = 30_000
    const surfaces = async (container: Element) => {
      expect(await seriousViolations(container)).toHaveLength(0)
      fireEvent.click(screen.getByRole('button', { name: /^Control Center/ }))
      expect(screen.getByRole('dialog', { name: 'Control Center' })).toBeInTheDocument()
      expect(await seriousViolations(container)).toHaveLength(0)
      fireEvent.keyDown(window, { key: 'Escape' })
      fireEvent.keyDown(window, { key: ' ', ctrlKey: true })
      fireEvent.change(screen.getByRole('combobox', { name: 'Search' }), { target: { value: 'sign' } })
      expect(await seriousViolations(container)).toHaveLength(0)
      fireEvent.keyDown(window, { key: 'Escape' })
      fireEvent.keyDown(window, { key: 'H', code: 'KeyH', altKey: true, shiftKey: true })
      expect(screen.getByRole('dialog', { name: 'Home Screen' })).toBeInTheDocument()
      expect(await seriousViolations(container)).toHaveLength(0)
    }

    it('on a desktop, with its sheets open, has no serious axe violations', async () => {
      window.localStorage.setItem('cades-theme', 'ios')
      try {
        const { container } = render(<App />)
        await surfaces(container)
        fireEvent.keyDown(window, { key: 'Escape' })
        fireEvent.click(screen.getAllByRole('button', { name: 'Settings' })[0])
        expect(await seriousViolations(container)).toHaveLength(0)
      } finally {
        window.localStorage.clear()
      }
    }, AXE_PASSES_MS)

    it('on a phone has no serious axe violations', async () => {
      window.localStorage.setItem('cades-theme', 'ios')
      vi.stubGlobal('matchMedia', (query: string) => ({
        matches: query.includes('max-width: 40rem'), media: query, addEventListener: () => {}, removeEventListener: () => {},
      }))
      try {
        const { container } = render(<App />)
        await surfaces(container)
      } finally {
        vi.unstubAllGlobals()
        window.localStorage.clear()
      }
    }, AXE_PASSES_MS)
  })

  it('Dashboard renders with no serious axe violations', async () => {
    const { container } = render(<Dashboard />)
    await waitFor(() => expect(screen.getByText('Operations', { exact: true })).toBeInTheDocument())
    expect(await seriousViolations(container)).toHaveLength(0)
  })
})
