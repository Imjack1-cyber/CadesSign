import { type RefObject, useEffect, useRef } from 'react'

/** Open surfaces, innermost last; only the last one answers Escape and keeps Tab inside itself. */
const stack: Array<RefObject<HTMLElement | null>> = []

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]):not([type=hidden]), select, textarea, [tabindex]:not([tabindex="-1"])'

/**
 * Makes an element behave as an iPadOS surface: focus moves into it when it opens (to the element
 * marked data-autofocus, else the first control, else the surface itself) and goes back where it was
 * when it closes; Escape closes it. A modal surface also keeps Tab inside itself.
 */
export function useIosModal(ref: RefObject<HTMLElement | null>, onClose: () => void, modal = true) {
  const close = useRef(onClose)
  useEffect(() => {
    close.current = onClose
  })

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const previous = document.activeElement as HTMLElement | null
    stack.push(ref)
    const first = el.querySelector<HTMLElement>('[data-autofocus]') ?? el.querySelector<HTMLElement>(FOCUSABLE) ?? el
    first.focus({ preventScroll: true })
    const onKey = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== ref) return
      // A field marked data-escape (a name being edited) handles Escape itself.
      if (e.key === 'Escape' && (e.target as Element | null)?.closest?.('[data-escape]')) return
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopPropagation()
        close.current()
        return
      }
      if (e.key !== 'Tab' || !modal) return
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(i => !i.closest('[inert]'))
      if (!items.length) return
      const at = items.indexOf(document.activeElement as HTMLElement)
      const next = e.shiftKey ? (at <= 0 ? items.length - 1 : at - 1) : at === items.length - 1 ? 0 : at + 1
      if (at === -1 || (e.shiftKey && at === 0) || (!e.shiftKey && at === items.length - 1)) {
        e.preventDefault()
        items[next].focus()
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => {
      window.removeEventListener('keydown', onKey, true)
      stack.splice(stack.indexOf(ref), 1)
      if (previous?.isConnected) previous.focus({ preventScroll: true })
    }
  }, [ref, modal])
}

/** Whether any iPadOS surface is open (so global shortcuts and gestures can stay out of its way). */
export const anyModalOpen = () => stack.length > 0
