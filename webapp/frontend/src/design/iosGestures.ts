/**
 * Touch gestures for the iPadOS theme, as plain functions so they can be tested: how far something
 * moves when pulled past its limit, which edge swipe a drag was, and whether a dragged sheet should
 * close. useLongPress turns a held press (or a right-click, or the context-menu key) into one call.
 */
import { useCallback, useEffect, useRef, type MouseEvent as ReactMouseEvent, type PointerEvent as ReactPointerEvent } from 'react'

export interface Point {
  x: number
  y: number
}

export type Swipe = 'notifications' | 'control' | 'home' | 'switcher' | 'back' | null

/** How close to an edge (px) a drag must start to be an edge swipe, and how far it must go. */
export const EDGE = 24
const MIN_SWIPE = 40
/** A swipe up from the bottom that takes longer than this, and stays short, pauses for the App Switcher. */
const HOLD_MS = 350
export const LONG_PRESS_MS = 500
/** A press that moves further than this (px) is a drag, not a long press. */
const SLOP = 8

/**
 * iOS rubber banding: past its limit something follows the finger less and less, never further
 * than `dim`. `x` is how far past the limit it was pulled.
 */
export function rubberBand(x: number, dim: number, c = 0.55) {
  if (x === 0 || dim <= 0) return 0
  return Math.sign(x) * (1 - 1 / ((Math.abs(x) * c) / dim + 1)) * dim
}

/**
 * Which system gesture a drag from `start` to `end` taking `ms` was, on a screen `w` by `h` whose
 * status bar is `top` px tall: down from the status bar's left or right half, up from the bottom
 * edge (a flick goes home, a slow short drag opens the App Switcher), or right from the left edge.
 */
export function edgeSwipe(start: Point, end: Point, w: number, h: number, ms: number, top = 54): Swipe {
  const dx = end.x - start.x
  const dy = end.y - start.y
  const vertical = Math.abs(dy) > Math.abs(dx)
  if (start.y <= top && dy > MIN_SWIPE && vertical) return start.x < w / 2 ? 'notifications' : 'control'
  if (start.y >= h - EDGE && -dy > MIN_SWIPE && vertical) return ms > HOLD_MS && -dy < h * 0.4 ? 'switcher' : 'home'
  if (start.x <= EDGE && dx > MIN_SWIPE * 2 && Math.abs(dx) > Math.abs(dy) * 1.5) return 'back'
  return null
}

/** A sheet dragged `distance` px at `velocity` px/ms closes when pulled a third of its `size`, or flicked. */
export const shouldDismiss = (distance: number, velocity: number, size: number) => distance > size / 3 || velocity > 0.5

/**
 * Calls `onLongPress` when a press is held still for LONG_PRESS_MS, on a right-click, or on the
 * context-menu key. Spread `handlers` on the element; `fired()` tells (once) whether the click that
 * ends the press should be ignored because the long press already acted.
 */
export function useLongPress(onLongPress: (at: Point) => void) {
  const timer = useRef(0)
  const start = useRef<Point | null>(null)
  const done = useRef(false)
  const cb = useRef(onLongPress)
  useEffect(() => {
    cb.current = onLongPress
  })
  useEffect(() => () => window.clearTimeout(timer.current), [])

  const cancel = useCallback(() => {
    window.clearTimeout(timer.current)
    start.current = null
  }, [])

  const handlers = {
    onPointerDown: (e: ReactPointerEvent) => {
      if (e.button !== 0) return
      done.current = false
      const at = { x: e.clientX, y: e.clientY }
      start.current = at
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => {
        done.current = true
        start.current = null
        cb.current(at)
      }, LONG_PRESS_MS)
    },
    onPointerMove: (e: ReactPointerEvent) => {
      const s = start.current
      if (s && Math.hypot(e.clientX - s.x, e.clientY - s.y) > SLOP) cancel()
    },
    onPointerUp: cancel,
    onPointerCancel: cancel,
    onPointerLeave: cancel,
    onContextMenu: (e: ReactMouseEvent) => {
      e.preventDefault()
      cancel()
      const r = (e.currentTarget as Element).getBoundingClientRect()
      // The context-menu key reports no position; open the menu from the element itself.
      cb.current(e.clientX || e.clientY ? { x: e.clientX, y: e.clientY } : { x: r.left + r.width / 2, y: r.bottom })
    },
  }

  const fired = useCallback(() => {
    const was = done.current
    done.current = false
    return was
  }, [])

  return { handlers, fired }
}
