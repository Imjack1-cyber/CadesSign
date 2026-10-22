/**
 * The Windows 95 theme's window manager. While the theme is active every ix-card becomes a window: a
 * real title bar (inserted as the card's first child) with minimize, maximize and close buttons; a
 * drag on the title bar moves it and a drag on the right or bottom edge resizes it, both with the
 * dotted outline 95 drew instead of the window contents; double-clicking the title maximizes it;
 * dropping it on the taskbar minimizes it. Closed windows wait in the Recycle Bin.
 *
 * It also notices page and wizard-step changes and repaints the new content the way 95 did.
 * Moving and sizing use relative offsets and plain width/height, never transforms, so IX's
 * fixed-position dropdowns inside the cards keep working. stop() takes everything back out.
 */
import type { Box } from './effects/presets'
import { emitChrome } from './signals'

export type WindowState = 'normal' | 'minimized' | 'maximized' | 'closed'

export interface Win95Window {
  id: string
  title: string
  state: WindowState
}

const WINDOW = 'ix-card'
const MIN_W = 180
const MIN_H = 90
/** How close to the right or bottom edge (px) a press resizes instead of reaching the content. */
const EDGE = 6
/** A drag shorter than this is a click. */
const SLOP = 3
const TASKBAR_H = 28
/** Longest a repaint may take, for a page busy rendering; without motion the class just lapses. */
const REPAINT_MS = 2000
/** Window attributes and properties the manager sets, so stop() can remove exactly those. */
const ATTRS = ['data-w95-state', 'data-w95-moved', 'data-w95-sized', 'data-w95-active', 'data-w95-inactive', 'data-w95-edge']
const PROPS = ['--w95-x', '--w95-y', '--w95-w', '--w95-h', '--w95-z', '--w95-max-top', '--w95-max-left']

type Edge = 'e' | 's' | 'se'

interface Entry {
  id: string
  el: HTMLElement
  bar: HTMLElement
  title: string
  state: WindowState
  /** What a minimized window returns to. */
  before: WindowState
  x: number
  y: number
}

interface Drag {
  entry: Entry
  mode: 'move' | Edge
  startX: number
  startY: number
  rect: DOMRect
  outline: HTMLDivElement | null
}

const toBox = (r: DOMRect): Box => ({ left: r.left, top: r.top, right: r.right, bottom: r.bottom })

/**
 * A window is named after the card's heading. IX React sets an ix-typography's format as a property,
 * not an attribute, so the heading is the first one formatted h1-h6, else the first text at all.
 */
function titleOf(el: HTMLElement) {
  const texts = [...el.querySelectorAll<HTMLElement & { format?: string }>('ix-typography, h1, h2, h3, h4, h5, h6')]
  const isHeading = (t: HTMLElement & { format?: string }) =>
    /^h\d$/i.test(t.tagName) || /^h\d$/.test(t.format ?? t.getAttribute('format') ?? '')
  const heading = texts.find(isHeading) ?? texts[0]
  return heading?.textContent?.trim() || 'Window'
}

/** Which resize edge, if any, the point is on. */
export function edgeAt(rect: Pick<DOMRect, 'right' | 'bottom'>, x: number, y: number): Edge | null {
  const e = x > rect.right - EDGE && x <= rect.right + 1
  const s = y > rect.bottom - EDGE && y <= rect.bottom + 1
  return e && s ? 'se' : e ? 'e' : s ? 's' : null
}

/** A window size after dragging an edge by (dx, dy), never smaller than a usable minimum. */
export function resized(rect: Pick<DOMRect, 'width' | 'height'>, edge: Edge, dx: number, dy: number) {
  return {
    w: edge === 's' ? rect.width : Math.max(MIN_W, rect.width + dx),
    h: edge === 'e' ? rect.height : Math.max(MIN_H, rect.height + dy),
  }
}

/** Limits a move so the title bar stays on screen and above the taskbar. */
export function clampMove(rect: Pick<DOMRect, 'left' | 'top' | 'width'>, dx: number, dy: number, vw: number, vh: number) {
  return {
    dx: Math.min(Math.max(dx, 40 - rect.left - rect.width), vw - 40 - rect.left),
    dy: Math.min(Math.max(dy, -rect.top), vh - TASKBAR_H - 20 - rect.top),
  }
}

export class WindowManager {
  private entries = new Map<HTMLElement, Entry>()
  private nextId = 1
  private zTop = 10
  private observer: MutationObserver | null = null
  private pending = 0
  private drag: Drag | null = null
  private page: Element | null = null
  private step: Element | null = null
  private signature = ''
  private readonly onChange: (windows: Win95Window[]) => void

  constructor(onChange: (windows: Win95Window[]) => void) {
    this.onChange = onChange
  }

  start() {
    this.scan()
    this.observer = new MutationObserver(() => this.schedule())
    this.observer.observe(document.body, { childList: true, subtree: true, characterData: true })
    document.addEventListener('pointerdown', this.onPointerDown, true)
    document.addEventListener('pointermove', this.onPointerMove, { passive: true })
    document.addEventListener('pointerup', this.onPointerUp)
    document.addEventListener('pointercancel', this.onPointerUp)
    document.addEventListener('focusin', this.onFocus)
    window.addEventListener('resize', this.onResize)
  }

  stop() {
    this.observer?.disconnect()
    window.clearTimeout(this.pending)
    document.removeEventListener('pointerdown', this.onPointerDown, true)
    document.removeEventListener('pointermove', this.onPointerMove)
    document.removeEventListener('pointerup', this.onPointerUp)
    document.removeEventListener('pointercancel', this.onPointerUp)
    document.removeEventListener('focusin', this.onFocus)
    window.removeEventListener('resize', this.onResize)
    this.drag?.outline?.remove()
    this.drag = null
    for (const entry of this.entries.values()) {
      entry.bar.remove()
      ATTRS.forEach(a => entry.el.removeAttribute(a))
      PROPS.forEach(p => entry.el.style.removeProperty(p))
    }
    this.entries.clear()
    document.querySelectorAll('.w95-repaint').forEach(el => el.classList.remove('w95-repaint'))
  }

  /** The windows, in page order. */
  list(): Win95Window[] {
    return [...this.entries.values()].map(({ id, title, state }) => ({ id, title, state }))
  }

  minimize(id: string) {
    const entry = this.find(id)
    if (!entry || entry.state === 'minimized' || entry.state === 'closed') return
    const from = toBox(entry.el.getBoundingClientRect())
    const hadFocus = entry.el.contains(document.activeElement)
    entry.before = entry.state
    this.setState(entry, 'minimized')
    emitChrome('minimize', { from, to: this.taskSlot() })
    // Focus follows the window into the taskbar, once its button is there.
    if (hadFocus) window.setTimeout(() => document.querySelector<HTMLElement>(`[data-w95-task="${id}"]`)?.focus(), 0)
  }

  restore(id: string) {
    const entry = this.find(id)
    if (!entry) return
    if (entry.state === 'maximized') {
      this.setState(entry, 'normal')
      emitChrome('restore')
      return
    }
    if (entry.state !== 'minimized' && entry.state !== 'closed') return
    const from = this.taskSlot()
    this.setState(entry, entry.state === 'minimized' ? entry.before : 'normal')
    this.raise(entry)
    emitChrome('restore', { from, to: toBox(entry.el.getBoundingClientRect()) })
    entry.bar.querySelector<HTMLElement>('[data-w95-action=minimize]')?.focus()
  }

  maximize(id: string) {
    const entry = this.find(id)
    if (!entry || entry.state !== 'normal') return
    const from = toBox(entry.el.getBoundingClientRect())
    this.setMaxArea(entry)
    this.setState(entry, 'maximized')
    this.raise(entry)
    emitChrome('maximize', { from, to: toBox(entry.el.getBoundingClientRect()) })
  }

  close(id: string) {
    const entry = this.find(id)
    if (!entry || entry.state === 'closed') return
    const hadFocus = entry.el.contains(document.activeElement)
    this.setState(entry, 'closed')
    emitChrome('close')
    if (hadFocus) window.setTimeout(() => document.querySelector<HTMLElement>('[data-w95-bin]')?.focus(), 0)
  }

  /** Brings every closed window back out of the Recycle Bin. */
  restoreClosed() {
    const closed = [...this.entries.values()].filter(e => e.state === 'closed')
    closed.forEach(e => this.setState(e, 'normal'))
    if (closed.length) emitChrome('restore')
  }

  private find(id: string) {
    for (const entry of this.entries.values()) if (entry.id === id) return entry
    return undefined
  }

  private setState(entry: Entry, state: WindowState) {
    entry.state = state
    if (state === 'normal') entry.el.removeAttribute('data-w95-state')
    else entry.el.setAttribute('data-w95-state', state)
    const max = entry.bar.querySelector<HTMLButtonElement>('[data-w95-action=maximize]')
    if (max) max.dataset.restore = state === 'maximized' ? 'true' : 'false'
    this.label(entry)
    this.notify()
  }

  private label(entry: Entry) {
    const text = entry.bar.querySelector('.w95-titlebar-text')
    if (text && text.textContent !== entry.title) text.textContent = entry.title
    const restore = entry.state === 'maximized'
    const labels: Record<string, string> = {
      minimize: `Minimize ${entry.title}`,
      maximize: `${restore ? 'Restore' : 'Maximize'} ${entry.title}`,
      close: `Close ${entry.title}`,
    }
    entry.bar.querySelectorAll<HTMLButtonElement>('[data-w95-action]').forEach(b => {
      const label = labels[b.dataset.w95Action!]
      if (b.getAttribute('aria-label') !== label) b.setAttribute('aria-label', label)
      b.title = label.split(' ')[0]
    })
  }

  /** Where minimized windows go: the start of the taskbar's task strip. */
  private taskSlot(): Box {
    const r = document.querySelector('.w95-tasks')?.getBoundingClientRect()
    if (!r) return { left: 64, top: window.innerHeight - 26, right: 224, bottom: window.innerHeight - 2 }
    return { left: r.left, top: r.top, right: Math.min(r.right, r.left + 160), bottom: r.bottom }
  }

  /** A maximized window fills the space below the app header and right of the side menu. */
  private setMaxArea(entry: Entry) {
    const top = document.querySelector('ix-application-header')?.getBoundingClientRect().bottom ?? 0
    const left = document.querySelector('ix-content')?.getBoundingClientRect().left ?? 0
    entry.el.style.setProperty('--w95-max-top', `${Math.round(top)}px`)
    entry.el.style.setProperty('--w95-max-left', `${Math.round(left)}px`)
  }

  private raise(entry: Entry) {
    entry.el.style.setProperty('--w95-z', String(++this.zTop))
    for (const other of this.entries.values()) {
      other.el.toggleAttribute('data-w95-active', other === entry)
      other.el.toggleAttribute('data-w95-inactive', other !== entry)
    }
  }

  private notify() {
    const list = this.list()
    const signature = JSON.stringify(list)
    if (signature === this.signature) return
    this.signature = signature
    this.onChange(list)
  }

  private schedule() {
    if (this.pending) return
    this.pending = window.setTimeout(() => {
      this.pending = 0
      this.scan()
    }, 0)
  }

  private scan() {
    for (const el of this.entries.keys()) if (!el.isConnected) this.entries.delete(el)
    document.querySelectorAll<HTMLElement>(WINDOW).forEach(el => {
      const entry = this.entries.get(el) ?? this.adopt(el)
      const title = titleOf(el)
      if (title !== entry.title) {
        entry.title = title
        this.label(entry)
      }
      if (entry.bar.parentElement !== el || el.firstElementChild !== entry.bar) el.prepend(entry.bar)
    })
    this.watchPages()
    this.notify()
  }

  private adopt(el: HTMLElement): Entry {
    const bar = document.createElement('div')
    bar.className = 'w95-titlebar'
    // The title repeats the card's own heading, so only the buttons are announced.
    bar.innerHTML =
      '<span class="w95-titlebar-text" aria-hidden="true"></span>' +
      '<span class="w95-titlebar-buttons">' +
      '<button type="button" data-w95-action="minimize"></button>' +
      '<button type="button" data-w95-action="maximize"></button>' +
      '<button type="button" data-w95-action="close"></button>' +
      '</span>'
    const entry: Entry = { id: `w${this.nextId++}`, el, bar, title: titleOf(el), state: 'normal', before: 'normal', x: 0, y: 0 }
    bar.addEventListener('click', e => {
      const action = (e.target as Element).closest<HTMLElement>('[data-w95-action]')?.dataset.w95Action
      if (action === 'minimize') this.minimize(entry.id)
      else if (action === 'maximize') {
        if (entry.state === 'maximized') this.restore(entry.id)
        else this.maximize(entry.id)
      } else if (action === 'close') this.close(entry.id)
    })
    bar.addEventListener('dblclick', e => {
      if ((e.target as Element).closest('[data-w95-action]')) return
      if (entry.state === 'maximized') this.restore(entry.id)
      else this.maximize(entry.id)
    })
    this.entries.set(el, entry)
    this.label(entry)
    el.prepend(bar)
    return entry
  }

  /** A new page or wizard step repaints in bands, as a busy 486 did; the canvas zooms a window open. */
  private watchPages() {
    const page = document.querySelector('.page')
    const step = document.querySelector('.wizard-body > *')
    const changed = this.page && page && page !== this.page ? page : this.step && step && step !== this.step ? step : null
    this.page = page
    this.step = step
    if (!changed) return
    changed.classList.remove('w95-repaint')
    void (changed as HTMLElement).offsetWidth
    changed.classList.add('w95-repaint')
    // The arrow with a small hourglass while the new page "loads". The repaint ends with its own
    // animation (a heavy page can delay its start), or after a while when motion is off.
    const root = document.documentElement
    root.classList.add('app-starting')
    const done = () => {
      changed.classList.remove('w95-repaint')
      root.classList.remove('app-starting')
    }
    changed.addEventListener('animationend', function end(e) {
      if (e.target !== changed) return
      changed.removeEventListener('animationend', end)
      done()
    })
    window.setTimeout(done, REPAINT_MS)
    const start = document.querySelector('.w95-start')?.getBoundingClientRect()
    const r = changed.getBoundingClientRect()
    const to = { left: r.left, top: r.top, right: r.right, bottom: Math.min(r.bottom, window.innerHeight - TASKBAR_H) }
    emitChrome('navigate', start ? { from: toBox(start), to } : {})
  }

  private entryAt(target: EventTarget | null) {
    const el = target instanceof Element ? target.closest<HTMLElement>(WINDOW) : null
    return el ? this.entries.get(el) : undefined
  }

  private onFocus = (e: FocusEvent) => {
    const entry = this.entryAt(e.target)
    if (entry) this.raise(entry)
  }

  private onResize = () => {
    for (const entry of this.entries.values()) if (entry.state === 'maximized') this.setMaxArea(entry)
  }

  private onPointerDown = (e: PointerEvent) => {
    if (e.button !== 0) return
    const entry = this.entryAt(e.target)
    if (!entry) return
    this.raise(entry)
    if (entry.state !== 'normal') return
    const rect = entry.el.getBoundingClientRect()
    const edge = edgeAt(rect, e.clientX, e.clientY)
    const onBar = (e.target as Element).closest('.w95-titlebar') && !(e.target as Element).closest('[data-w95-action]')
    if (!edge && !onBar) return
    e.preventDefault()
    this.drag = { entry, mode: edge ?? 'move', startX: e.clientX, startY: e.clientY, rect, outline: null }
  }

  private onPointerMove = (e: PointerEvent) => {
    const drag = this.drag
    if (!drag) {
      // Show the resize cursor along the edges a drag would resize.
      const entry = this.entryAt(e.target)
      if (!entry) return
      const edge = entry.state === 'normal' ? edgeAt(entry.el.getBoundingClientRect(), e.clientX, e.clientY) : null
      if (edge) entry.el.setAttribute('data-w95-edge', edge)
      else entry.el.removeAttribute('data-w95-edge')
      return
    }
    const dx = e.clientX - drag.startX
    const dy = e.clientY - drag.startY
    if (!drag.outline) {
      if (Math.abs(dx) < SLOP && Math.abs(dy) < SLOP) return
      drag.outline = document.createElement('div')
      drag.outline.className = 'w95-drag-outline'
      document.body.append(drag.outline)
    }
    const { rect } = drag
    const box = drag.mode === 'move'
      ? { left: rect.left + dx, top: rect.top + dy, w: rect.width, h: rect.height }
      : { left: rect.left, top: rect.top, ...resized(rect, drag.mode, dx, dy) }
    Object.assign(drag.outline.style, { left: `${box.left}px`, top: `${box.top}px`, width: `${box.w}px`, height: `${box.h}px` })
  }

  private onPointerUp = (e: PointerEvent) => {
    const drag = this.drag
    this.drag = null
    if (!drag?.outline) return
    drag.outline.remove()
    const { entry, rect } = drag
    const dx = e.clientX - drag.startX
    const dy = e.clientY - drag.startY
    if (drag.mode === 'move') {
      // Dropped on the taskbar: minimize, as if it went in there.
      if (e.clientY >= window.innerHeight - TASKBAR_H) {
        this.minimize(entry.id)
        return
      }
      const move = clampMove(rect, dx, dy, window.innerWidth, window.innerHeight)
      entry.x += move.dx
      entry.y += move.dy
      entry.el.setAttribute('data-w95-moved', '')
      entry.el.style.setProperty('--w95-x', `${entry.x}px`)
      entry.el.style.setProperty('--w95-y', `${entry.y}px`)
    } else {
      const { w, h } = resized(rect, drag.mode, dx, dy)
      entry.el.setAttribute('data-w95-sized', '')
      entry.el.style.setProperty('--w95-w', `${Math.round(w)}px`)
      entry.el.style.setProperty('--w95-h', `${Math.round(h)}px`)
    }
  }
}
