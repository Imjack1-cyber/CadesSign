import type { EffectKind } from '../designs'
import { APP_SIGNAL_EVENT, type AppSignal, GENERATED_EVENT } from '../signals'
import { type AppKey, type Box, type Control, type KeyKind, PRESETS, type SignalName, type World } from './presets'
import { createSound } from './sound'

/** How long a signal's class stays on <html> unless the preset says otherwise; themes.css keys off it. */
const SIGNAL_MS = 600

const TEXT_TYPES = new Set(['text', 'search', 'url', 'tel', 'password', 'email', 'number'])

/** The text field an event really happened in; IX inputs keep theirs inside shadow DOM. */
function textField(target: EventTarget | null | undefined): HTMLInputElement | HTMLTextAreaElement | null {
  if (target instanceof HTMLTextAreaElement) return target
  if (target instanceof HTMLInputElement && TEXT_TYPES.has(target.type)) return target
  return null
}

/**
 * What a key press means to a theme. Shortcuts are ignored; 'unknown' is a virtual keyboard or IME
 * that does not say which key it was, so the input event that follows decides (describeInput).
 */
export function describeKey(e: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'altKey'>): KeyKind | 'unknown' | null {
  switch (e.key) {
    case 'Enter': return 'enter'
    case 'Tab': return 'tab'
    case 'Backspace':
    case 'Delete': return 'delete'
    case 'Unidentified':
    case 'Process': return 'unknown'
  }
  // AltGr reports Ctrl+Alt, and still types a character.
  if (e.key.length !== 1 || ((e.ctrlKey || e.metaKey) && !e.altKey)) return null
  return e.key === ' ' ? 'space' : 'char'
}

export function describeInput(inputType: string, data: string | null): KeyKind | null {
  if (inputType.startsWith('delete')) return 'delete'
  if (inputType === 'insertLineBreak' || inputType === 'insertParagraph') return 'enter'
  if (inputType.startsWith('insert')) return data === ' ' ? 'space' : 'char'
  return null
}

const toBox = (r: DOMRect): Box => ({ left: r.left, top: r.top, right: r.right, bottom: r.bottom })

/**
 * Places a key at the caret of the field it was typed into, estimated from the caret index and the
 * font size, or at the middle of the focused element otherwise. Password fields never pass the glyph.
 */
export function locateKey(kind: KeyKind, target: EventTarget | null, glyph?: string): AppKey {
  const field = textField(target)
  if (!field) {
    const el = target instanceof Element && target !== document.body && target !== document.documentElement ? target : null
    const r = el?.getBoundingClientRect()
    return {
      kind, field: false, size: 16,
      x: r ? r.left + r.width / 2 : window.innerWidth / 2,
      y: r ? r.top + r.height / 2 : window.innerHeight / 2,
      edge: r ? r.right : window.innerWidth * 0.75,
    }
  }
  const r = field.getBoundingClientRect()
  const style = window.getComputedStyle(field)
  const size = parseFloat(style.fontSize) || 14
  let caret = field.value.length
  try {
    caret = field.selectionStart ?? caret
  } catch {
    // Some input types (email, number) do not expose a selection.
  }
  const x = r.left + (parseFloat(style.paddingLeft) || 0) + caret * size * 0.6 - field.scrollLeft
  return {
    kind, field: true, size, edge: r.right,
    x: Math.max(r.left, Math.min(r.right - 4, x)),
    y: r.top + r.height / 2,
    glyph: field.type === 'password' ? undefined : glyph,
    empty: field.value.length === 0,
  }
}

/** Page layout containers: a press on one of these, not on a control or text inside, is on bare page. */
const BARE = new Set(['HTML', 'BODY', 'IX-APPLICATION', 'IX-CONTENT', 'MAIN'])

export function isBare(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false
  return BARE.has(target.tagName) || target.matches('.page, .stack, .app-backdrop, [class^=decor]')
}

/** IX hosts and plain elements by the kind of control they are; the first match along the press's path wins. */
const CONTROLS: ReadonlyArray<[string, Control]> = [
  ['ix-action-card, ix-select-item, ix-dropdown-item, ix-pill, ix-pagination, [role=option]', 'choice'],
  ['ix-tab-item, ix-menu-item, ix-menu-about-item', 'nav'],
  ['ix-checkbox, ix-toggle-button, ix-blind, summary, input[type=checkbox], input[type=radio]', 'toggle'],
  ['ix-upload, input[type=file]', 'upload'],
  ['ix-input, ix-date-input, ix-select, input, textarea, select', 'field'],
  ['ix-workflow-step', 'back'],
  ['ix-button, ix-icon-button, button, a[href], [role=button]', 'button'],
]

/** Buttons whose icon says what they do. */
const ICONS: Record<string, Control> = {
  download: 'download', trashcan: 'discard', 'clear-filter': 'discard', cancel: 'discard', 'chevron-left': 'back',
}

/** A property React set on an IX element, or the attribute of the same name on a plain one. */
function prop(el: Element, name: string, attr = name): unknown {
  const value = (el as unknown as Record<string, unknown>)[name]
  return value !== undefined ? value : el.getAttribute(attr)
}

/**
 * The control a press landed on and what kind it is, from the event's composed path (innermost
 * first), or undefined for plain page and text. Elements inside a shadow root are an IX control's
 * own insides, so only the host counts. A disabled control is 'disabled' whatever it is.
 */
export function controlAt(path: readonly EventTarget[]): { el: Element; kind: Control } | undefined {
  for (const node of path) {
    if (!(node instanceof Element) || node.getRootNode() instanceof ShadowRoot) continue
    const kind = CONTROLS.find(([selector]) => node.matches(selector))?.[1]
    if (!kind) continue
    const disabled = prop(node, 'disabled')
    if ((disabled !== null && disabled !== false && disabled !== 'false') || node.getAttribute('aria-disabled') === 'true') return { el: node, kind: 'disabled' }
    if (kind !== 'button') return { el: node, kind }
    if (prop(node, 'iconRight', 'icon-right') === 'chevron-right') return { el: node, kind: 'forward' }
    return { el: node, kind: ICONS[String(prop(node, 'icon') ?? '')] ?? 'button' }
  }
  return undefined
}

/** What kind of control a press landed on (see controlAt). */
export const controlKind = (path: readonly EventTarget[]): Control | undefined => controlAt(path)?.kind

/**
 * What the mouse is over: a control, or else the innermost element (outside IX's insides) that holds
 * text of its own, or nothing on bare page.
 */
export function hoverAt(path: readonly EventTarget[]): { el: Element; kind: Control | 'text' } | undefined {
  const control = controlAt(path)
  if (control) return control
  const el = path.find((n): n is Element => n instanceof Element && !(n.getRootNode() instanceof ShadowRoot))
  if (!el || isBare(el)) return undefined
  const text = [...el.childNodes].some(n => n.nodeType === Node.TEXT_NODE && n.textContent?.trim())
  return text ? { el, kind: 'text' } : undefined
}

/**
 * A disabled control under (x, y), if any. IX turns pointer events off on disabled controls, so a
 * press on one lands on whatever is behind it and its path never names it.
 */
export function disabledAt(x: number, y: number): Control | undefined {
  for (const el of document.querySelectorAll('ix-button, ix-icon-button, ix-action-card, ix-toggle-button')) {
    if (prop(el, 'disabled') !== true) continue
    const r = el.getBoundingClientRect()
    if (x >= r.left && x <= r.right && y >= r.top && y <= r.bottom) return 'disabled'
  }
  return undefined
}

/** Options in an open list. IX marks the one the arrow keys reached with .ix-focused. */
const OPTION = 'ix-select-item, ix-dropdown-item, [role=option]'
const BROWSE_KEYS = new Set(['ArrowUp', 'ArrowDown', 'Home', 'End', 'PageUp', 'PageDown'])
const BROWSE_DELAY_MS = 60

/** The option along a composed path, skipping IX's insides as controlKind does. */
export function optionIn(path: readonly EventTarget[]): Element | undefined {
  return path.find((n): n is Element => n instanceof Element && !(n.getRootNode() instanceof ShadowRoot) && n.matches(OPTION))
}

/** An option's place among the options beside it. */
export const optionIndex = (el: Element) =>
  el.parentElement ? [...el.parentElement.children].filter(c => c.matches(OPTION)).indexOf(el) : 0

/** Where the wizard shows its result, if it is on screen. */
function resultBox(): Box | null {
  const el = document.querySelector('[data-result]') ?? document.querySelector('.wizard-body ix-message-bar')
  if (!el) return null
  const r = el.getBoundingClientRect()
  return r.bottom < 0 || r.top > window.innerHeight ? null : toBox(r)
}

/**
 * Runs one effect preset on a full-screen canvas until the returned stop function is called.
 * The canvas never takes pointer events, so the pointer, keys and focus are read from window
 * listeners; the wizard's busy and result signals arrive as APP_SIGNAL_EVENT. The loop pauses while
 * the tab is hidden and restarts the preset on resize. Without a 2D context (jsdom) it does nothing.
 */
export function runEffect(canvas: HTMLCanvasElement, kind: EffectKind, wild: boolean, sound = false): () => void {
  const ctx = canvas.getContext('2d')
  if (!ctx) return () => {}
  const preset = PRESETS[kind]
  const root = document.documentElement
  const timers = new Map<SignalName, number>()
  const signalled = new Set<SignalName>()

  const world: World = {
    w: 0, h: 0, t: 0, dt: 0, wind: 0, wild, rnd: Math.random, typing: 0,
    pointer: { x: 0, y: 0, vx: 0, vy: 0, active: false },
    sound: sound ? createSound() : undefined,
    signal: (name, ms = SIGNAL_MS) => {
      window.clearTimeout(timers.get(name))
      timers.delete(name)
      const cls = `app-${name}`
      if (ms <= 0) {
        root.classList.remove(cls)
        return
      }
      // Restart the class so a CSS animation keyed to it plays again.
      root.classList.remove(cls)
      void root.offsetWidth
      root.classList.add(cls)
      signalled.add(name)
      timers.set(name, window.setTimeout(() => root.classList.remove(cls), ms))
    },
  }
  let state = preset.init(world)

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    world.w = window.innerWidth
    world.h = window.innerHeight
    canvas.width = Math.round(world.w * dpr)
    canvas.height = Math.round(world.h * dpr)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    state = preset.init(world, state)
  }
  resize()
  preset.start?.(state, world)

  let rawX = 0
  let rawY = 0
  const onMove = (e: PointerEvent) => {
    rawX = e.clientX
    rawY = e.clientY
    world.pointer.touch = e.pointerType === 'touch' || e.pointerType === 'pen'
    if (!world.pointer.active) {
      world.pointer.x = rawX
      world.pointer.y = rawY
      world.pointer.active = true
    }
  }
  const onDown = (e: PointerEvent) => {
    const p = world.pointer
    p.down = true
    p.touch = e.pointerType === 'touch' || e.pointerType === 'pen'
    p.downX = e.clientX
    p.downY = e.clientY
    // e.target, not the composed path: a press inside an IX control is retargeted to the control itself.
    p.bare = isBare(e.target)
    p.control = controlKind(e.composedPath()) ?? disabledAt(e.clientX, e.clientY)
    if (wild) preset.burst?.(state, world, e.clientX, e.clientY)
  }
  const onUp = () => {
    world.pointer.down = false
  }
  const onLeave = () => {
    world.pointer.active = false
    hover(undefined)
  }

  const press = (k: AppKey) => {
    if (k.kind !== 'tab') world.typing += 1
    preset.key?.(state, world, k)
  }
  // Set when a keydown could not say which key it was, so the input event that follows reports it.
  let pendingInput = false
  const onKey = (e: KeyboardEvent) => {
    const kind = describeKey(e)
    pendingInput = kind === 'unknown'
    if (kind && kind !== 'unknown') press(locateKey(kind, e.composedPath()[0] ?? null, e.key))
  }
  const onInput = (e: Event) => {
    if (!pendingInput || !(e instanceof InputEvent)) return
    pendingInput = false
    const kind = describeInput(e.inputType, e.data)
    if (kind) press(locateKey(kind, e.composedPath()[0] ?? null, e.data?.slice(-1)))
  }
  // The option last browsed, so moving within it, or a key that does not move the highlight, stays quiet.
  let browsed: Element | undefined
  const browse = (el: Element | undefined) => {
    if (el === browsed) return
    browsed = el
    if (el) preset.browse?.(state, world, optionIndex(el))
  }
  const onOver = (e: PointerEvent) => {
    const path = e.composedPath()
    browse(optionIn(path))
    // Only a mouse rests on things; a finger or pen just lands.
    hover(e.pointerType === 'mouse' ? hoverAt(path) : undefined)
  }
  // IX re-renders the highlight a moment after the key, later than the next frame, so look a little later.
  const onBrowseKey = (e: KeyboardEvent) => {
    if (!BROWSE_KEYS.has(e.key)) return
    window.setTimeout(() => browse(document.querySelector(`:is(${OPTION}).ix-focused`) ?? browsed), BROWSE_DELAY_MS)
  }
  const onFocus = (e: FocusEvent) => {
    const field = textField(e.composedPath()[0])
    if (field) preset.focus?.(state, world, toBox(field.getBoundingClientRect()))
  }
  // The wizard's step before the latest one, to tell moving forward from going back.
  let lastStep = 0
  const onSignal = (e: Event) => {
    const detail = (e as CustomEvent<AppSignal>).detail
    if (detail.type === 'busy') preset.busy?.(state, world, detail.on)
    else if (detail.type === 'chrome') preset.chrome?.(state, world, detail.event, { from: detail.from, to: detail.to })
    else if (detail.type === 'outcome') preset.outcome?.(state, world, detail.kind, resultBox(), detail.action)
    else if (detail.type === 'file') preset.activity?.(state, world, detail.added ? 'file-in' : 'file-out')
    else if (detail.type === 'command') preset.command?.(state, world, detail.ok)
    else if (detail.type === 'step') {
      if (lastStep && detail.step !== lastStep) preset.activity?.(state, world, detail.step > lastStep ? 'forward' : 'back')
      lastStep = detail.step
    }
  }
  const onGenerated = () => preset.activity?.(state, world, 'saved')
  // What the mouse rests on; its box is read again every frame, since the page moves under it.
  let hovered: { el: Element; kind: Control | 'text'; radius: number; line: number } | null = null
  const hover = (target: { el: Element; kind: Control | 'text' } | undefined) => {
    if (target?.el === hovered?.el && target?.kind === hovered?.kind) return
    if (!target) {
      hovered = null
      return
    }
    const style = window.getComputedStyle(target.el)
    const size = parseFloat(style.fontSize) || 16
    hovered = {
      ...target,
      radius: parseFloat(style.borderTopLeftRadius) || 0,
      line: parseFloat(style.lineHeight) || size * 1.2,
    }
  }
  // IX's About panel: its tabs say when they change; whether it is open shows only in its class.
  const onTab = () => preset.activity?.(state, world, 'tab')
  const aboutOpen = new WeakMap<Element, boolean>()
  const panels = new MutationObserver(records => {
    for (const r of records) {
      const el = r.target as Element
      if (el.tagName !== 'IX-MENU-ABOUT') continue
      const open = el.classList.contains('show')
      if (open === (aboutOpen.get(el) ?? false)) continue
      aboutOpen.set(el, open)
      preset.activity?.(state, world, open ? 'panel-open' : 'panel-close')
    }
  })
  // Scrolling inside IX's shadow DOM never reaches the page as a scroll event, so the wheel it is.
  const onWheel = (e: WheelEvent) => {
    const dy = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? window.innerHeight : 1)
    if (dy) preset.scroll?.(state, world, dy)
  }

  let frame = 0
  let last = performance.now()
  const tick = (now: number) => {
    const dt = Math.min(0.05, (now - last) / 1000)
    last = now
    world.dt = dt
    world.t += dt
    // Two slow waves make an irregular gust; wild weather blows harder.
    world.wind = (0.6 * Math.sin(world.t * 0.21) + 0.4 * Math.sin(world.t * 0.57 + 2)) * (wild ? 1.6 : 0.8)
    // Each key adds one; decaying over a second leaves roughly keys per second.
    world.typing *= Math.exp(-dt)

    const p = world.pointer
    if (p.active && dt > 0) {
      p.vx = p.vx * 0.7 + ((rawX - p.x) / dt) * 0.3
      p.vy = p.vy * 0.7 + ((rawY - p.y) / dt) * 0.3
      p.x = rawX
      p.y = rawY
      if (wild) {
        root.style.setProperty('--app-pointer-x', `${p.x}px`)
        root.style.setProperty('--app-pointer-y', `${p.y}px`)
      }
    }
    if (hovered && (!hovered.el.isConnected || p.touch)) hovered = null
    world.hover = hovered ? { box: toBox(hovered.el.getBoundingClientRect()), radius: hovered.radius, kind: hovered.kind, line: hovered.line } : undefined

    preset.step(state, world)
    ctx.clearRect(0, 0, world.w, world.h)
    preset.draw(ctx, state, world)
    frame = requestAnimationFrame(tick)
  }

  const onVisibility = () => {
    cancelAnimationFrame(frame)
    if (!document.hidden) {
      last = performance.now()
      frame = requestAnimationFrame(tick)
    }
  }

  window.addEventListener('resize', resize)
  window.addEventListener('pointermove', onMove, { passive: true })
  window.addEventListener('pointerdown', onDown, { passive: true })
  window.addEventListener('pointerup', onUp, { passive: true })
  window.addEventListener('pointercancel', onUp, { passive: true })
  document.documentElement.addEventListener('pointerleave', onLeave)
  document.addEventListener('visibilitychange', onVisibility)
  if (wild) {
    window.addEventListener('keydown', onKey, true)
    window.addEventListener('keydown', onBrowseKey, true)
    window.addEventListener('pointerover', onOver, { passive: true })
    window.addEventListener('input', onInput, true)
    window.addEventListener('focusin', onFocus, true)
    window.addEventListener(APP_SIGNAL_EVENT, onSignal)
    window.addEventListener(GENERATED_EVENT, onGenerated)
    window.addEventListener('tabChange', onTab)
    window.addEventListener('wheel', onWheel, { passive: true })
    panels.observe(document.body, { subtree: true, attributes: true, attributeFilter: ['class'] })
  }
  frame = requestAnimationFrame(tick)

  return () => {
    cancelAnimationFrame(frame)
    timers.forEach(clearTimeout)
    window.removeEventListener('resize', resize)
    window.removeEventListener('pointermove', onMove)
    window.removeEventListener('pointerdown', onDown)
    window.removeEventListener('pointerup', onUp)
    window.removeEventListener('pointercancel', onUp)
    document.documentElement.removeEventListener('pointerleave', onLeave)
    document.removeEventListener('visibilitychange', onVisibility)
    window.removeEventListener('keydown', onKey, true)
    window.removeEventListener('keydown', onBrowseKey, true)
    window.removeEventListener('pointerover', onOver)
    window.removeEventListener('input', onInput, true)
    window.removeEventListener('focusin', onFocus, true)
    window.removeEventListener(APP_SIGNAL_EVENT, onSignal)
    window.removeEventListener(GENERATED_EVENT, onGenerated)
    window.removeEventListener('tabChange', onTab)
    window.removeEventListener('wheel', onWheel)
    panels.disconnect()
    world.sound?.dispose()
    signalled.forEach(name => root.classList.remove(`app-${name}`))
    root.style.removeProperty('--app-pointer-x')
    root.style.removeProperty('--app-pointer-y')
  }
}
