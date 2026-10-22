import { useCallback, useEffect, useRef } from 'react'
import { flushSync } from 'react-dom'
import type { DesignPreview } from './useDesign'

/** How long the pointer (or keyboard focus) rests on an option before the page tries it on. */
export const PREVIEW_DELAY_MS = 250
/** How long after leaving an option the page goes back, so crossing the gap between cards does not flash. */
export const REVERT_DELAY_MS = 200
/** Pointer events closer than this to where the last preview started count as "the pointer did not move". */
const STILL_PX = 3

type Point = { x: number; y: number }

/**
 * Applies a look with a short crossfade (the View Transitions API, where available and motion is
 * welcome), so switching previews eases instead of snapping.
 */
function applyWithFade(apply: () => void) {
  const doc = document as Document & { startViewTransition?: (update: () => void) => unknown }
  const reduced = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (typeof doc.startViewTransition !== 'function' || reduced) {
    apply()
    return
  }
  doc.startViewTransition(() => flushSync(apply))
}

/**
 * Hover and focus intent for previews in the Appearance panel.
 *
 * - A preview starts only after the pointer or focus has rested on an option for PREVIEW_DELAY_MS,
 *   and ends REVERT_DELAY_MS after leaving, so sweeping across the panel does not flicker.
 * - Previewing a theme can change the page's layout, which can slide a different option under a
 *   pointer that has not moved. The browser then reports mouseenter / mouseleave as if the user had
 *   moved. Those events arrive at the same spot where the current preview began, so they are ignored:
 *   only real pointer movement can switch to another preview.
 */
export function usePreviewIntent(setPreview: (preview: DesignPreview | null) => void, enabled: boolean) {
  const timer = useRef<number | undefined>(undefined)
  const pointer = useRef<Point | null>(null)
  // Where the pointer was when the shown preview (or the revert) last took effect.
  const settledAt = useRef<Point | null>(null)

  const cancel = useCallback(() => window.clearTimeout(timer.current), [])

  useEffect(() => {
    if (!enabled) return
    const onMove = (e: MouseEvent) => {
      pointer.current = { x: e.clientX, y: e.clientY }
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.clearTimeout(timer.current)
      settledAt.current = null
    }
  }, [enabled])

  const pointerStill = (e: { clientX: number; clientY: number }) =>
    settledAt.current !== null
    && Math.hypot(e.clientX - settledAt.current.x, e.clientY - settledAt.current.y) < STILL_PX

  const schedule = (next: DesignPreview | null, delay: number, at: Point | null) => {
    cancel()
    timer.current = window.setTimeout(() => {
      settledAt.current = pointer.current ?? at
      applyWithFade(() => setPreview(next))
    }, delay)
  }

  return {
    /** The pointer entered an option. */
    enter: (e: { clientX: number; clientY: number }, next: DesignPreview) => {
      if (pointerStill(e)) return
      schedule(next, PREVIEW_DELAY_MS, { x: e.clientX, y: e.clientY })
    },
    /** The pointer left an option. */
    leave: (e: { clientX: number; clientY: number }) => {
      if (pointerStill(e)) return
      schedule(null, REVERT_DELAY_MS, { x: e.clientX, y: e.clientY })
    },
    /** Keyboard focus reached an option. */
    focus: (next: DesignPreview) => schedule(next, PREVIEW_DELAY_MS, pointer.current),
    /** Keyboard focus left an option. */
    blur: () => schedule(null, REVERT_DELAY_MS, pointer.current),
    /** An option was chosen; whatever was pending no longer applies. */
    cancel,
  }
}

export type PreviewIntent = ReturnType<typeof usePreviewIntent>
