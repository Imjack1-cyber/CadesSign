/** Keeps Tab and Shift+Tab inside the dialog. */
export function trapFocus(e: KeyboardEvent, root: HTMLElement | null) {
  if (!root) return
  const items = [...root.querySelectorAll<HTMLElement>('button:not([disabled])')].filter(el => el.offsetParent !== null || el === document.activeElement)
  if (!items.length) {
    e.preventDefault()
    root.focus()
    return
  }
  const first = items[0]
  const last = items[items.length - 1]
  const active = document.activeElement
  if (e.shiftKey && (active === first || active === root)) {
    e.preventDefault()
    last.focus()
  } else if (!e.shiftKey && (active === last || !root.contains(active))) {
    e.preventDefault()
    first.focus()
  }
}
