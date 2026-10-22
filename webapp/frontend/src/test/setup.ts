import '@testing-library/jest-dom'
import { expect, vi } from 'vitest'
import * as matchers from 'vitest-axe/matchers'

expect.extend(matchers)

// Stencil web components cannot render in jsdom; swap them for DOM stand-ins in every test.
vi.mock('@siemens/ix-react', () => import('./ixMock'))
vi.mock('@siemens/ix', () => ({
  themeSwitcher: {
    toggleMode: () => {},
    getMode: () => 'light',
    getColorSchema: () => 'system',
    setColorSchema: vi.fn(),
    themeChanged: { on: () => ({ dispose: () => {} }) },
  },
}))

// jsdom does not implement scrolling; the wizard scrolls to the top on each step.
window.scrollTo = (() => {}) as typeof window.scrollTo

// jsdom has no canvas; returning null (instead of logging "Not implemented") lets charts and theme
// effects take their no-canvas path quietly.
HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext
