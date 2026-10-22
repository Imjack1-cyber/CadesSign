import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { APP_SIGNAL_EVENT, type AppSignal } from '../../design/signals'
import { clampMove, edgeAt, resized, type Win95Window, WindowManager } from '../../design/win95Windows'

/** Lets the mutation observer fire and then the manager's debounced rescan run. */
const settle = async () => {
  await Promise.resolve()
  await new Promise(r => setTimeout(r, 0))
}

function card(title: string) {
  const el = document.createElement('ix-card')
  el.innerHTML = `<ix-card-content><ix-typography format="h4">${title}</ix-typography><input aria-label="${title} field"></ix-card-content>`
  document.body.append(el)
  return el
}

describe('Windows 95 window manager', () => {
  let windows: Win95Window[] = []
  let manager: WindowManager
  let chrome: string[] = []
  const onSignal = (e: Event) => {
    const d = (e as CustomEvent<AppSignal>).detail
    if (d.type === 'chrome') chrome.push(d.event)
  }

  beforeEach(() => {
    document.body.innerHTML = ''
    windows = []
    chrome = []
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    manager = new WindowManager(list => { windows = list })
  })

  afterEach(() => {
    manager.stop()
    window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
  })

  const button = (el: Element, name: RegExp) =>
    [...el.querySelectorAll<HTMLButtonElement>('button')].find(b => name.test(b.getAttribute('aria-label') ?? ''))!

  it('gives every card a title bar named after its heading, also cards added later', async () => {
    card('Signature')
    manager.start()
    expect(windows).toEqual([{ id: 'w1', title: 'Signature', state: 'normal' }])
    const later = card('Signing keys')
    await settle()
    expect(windows.map(w => w.title)).toEqual(['Signature', 'Signing keys'])
    expect(later.firstElementChild).toHaveClass('w95-titlebar')
    expect(button(later, /^Close Signing keys$/)).toBeTruthy()
  })

  it('minimize, maximize, restore and close change the state and tell the effect', () => {
    const el = card('Signature')
    manager.start()
    fireClick(button(el, /^Maximize/))
    expect(el).toHaveAttribute('data-w95-state', 'maximized')
    expect(button(el, /^Restore Signature$/)).toBeTruthy()
    fireClick(button(el, /^Restore/))
    expect(el).not.toHaveAttribute('data-w95-state')
    fireClick(button(el, /^Minimize/))
    expect(windows[0].state).toBe('minimized')
    manager.restore('w1')
    expect(windows[0].state).toBe('normal')
    fireClick(button(el, /^Close/))
    expect(windows[0].state).toBe('closed')
    manager.restoreClosed()
    expect(windows[0].state).toBe('normal')
    expect(chrome).toEqual(['maximize', 'restore', 'minimize', 'restore', 'close', 'restore'])
  })

  it('a window minimized while maximized comes back maximized', () => {
    const el = card('Signature')
    manager.start()
    manager.maximize('w1')
    manager.minimize('w1')
    manager.restore('w1')
    expect(el).toHaveAttribute('data-w95-state', 'maximized')
  })

  it('stop() takes every title bar and window attribute back out', () => {
    const el = card('Signature')
    manager.start()
    manager.maximize('w1')
    manager.stop()
    expect(el.querySelector('.w95-titlebar')).toBeNull()
    expect(el.getAttributeNames().filter(a => a.startsWith('data-w95'))).toEqual([])
    expect(el.getAttribute('style') ?? '').not.toContain('--w95')
  })

  it('repaints a new page, but not the first one', async () => {
    document.body.innerHTML = '<div class="page">one</div>'
    manager.start()
    expect(document.querySelector('.w95-repaint')).toBeNull()
    document.body.innerHTML = '<div class="page">two</div>'
    await settle()
    expect(document.querySelector('.page')).toHaveClass('w95-repaint')
    expect(chrome).toEqual(['navigate'])
  })
})

describe('window geometry', () => {
  it('resizes from the right and bottom edges only, never below a minimum', () => {
    const rect = { right: 400, bottom: 300 }
    expect(edgeAt(rect, 398, 100)).toBe('e')
    expect(edgeAt(rect, 200, 298)).toBe('s')
    expect(edgeAt(rect, 399, 299)).toBe('se')
    expect(edgeAt(rect, 200, 100)).toBeNull()
    expect(resized({ width: 300, height: 200 }, 'se', -500, 40)).toEqual({ w: 180, h: 240 })
    expect(resized({ width: 300, height: 200 }, 'e', 50, 999)).toEqual({ w: 350, h: 200 })
  })

  it('keeps a moved title bar on screen and above the taskbar', () => {
    const rect = { left: 100, top: 100, width: 300 }
    expect(clampMove(rect, -2000, -500, 1280, 800)).toEqual({ dx: -360, dy: -100 })
    expect(clampMove(rect, 5000, 5000, 1280, 800)).toEqual({ dx: 1140, dy: 652 })
  })
})

function fireClick(el: HTMLElement) {
  el.dispatchEvent(new MouseEvent('click', { bubbles: true }))
}
